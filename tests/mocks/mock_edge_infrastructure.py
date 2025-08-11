"""Mock edge computing infrastructure for testing.

This module provides mock classes and utilities for testing edge computing functionality
without requiring actual edge devices, CDN services, or distributed systems.
"""

import asyncio
import json
import random
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from unittest.mock import Mock, MagicMock, AsyncMock

from fastapi import Request
from fastapi.testclient import TestClient

from fastapi_shield.edge_computing import (
    EdgeLocation, EdgeCapability, SyncMode, EdgeResourceLevel,
    ConsensusAlgorithm, EdgeNode, EdgePolicy, EdgeCacheEntry,
    EdgeSyncState
)


@dataclass
class MockEdgeTestConfig:
    """Configuration for mock edge testing environment."""
    simulate_network_latency: bool = True
    network_latency_ms: float = 50.0
    simulate_failures: bool = False
    failure_rate: float = 0.05
    offline_mode: bool = False
    resource_constraints: bool = True
    enable_compression: bool = True
    consensus_enabled: bool = True


@dataclass
class MockEdgeMetrics:
    """Mock edge computing metrics."""
    requests_processed: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    policy_syncs: int = 0
    auth_successes: int = 0
    auth_failures: int = 0
    consensus_decisions: int = 0
    cdn_operations: int = 0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    network_bytes_sent: int = 0
    network_bytes_received: int = 0


class MockNetworkSimulator:
    """Simulates network conditions for edge testing."""
    
    def __init__(self, config: MockEdgeTestConfig):
        self.config = config
        self.connection_status = {}
        self.bandwidth_limits = {}
        self.packet_loss_rates = {}
    
    async def simulate_network_delay(self, source: str, target: str) -> float:
        """Simulate network latency between nodes."""
        if not self.config.simulate_network_latency:
            return 0.0
        
        # Base latency with some randomness
        base_latency = self.config.network_latency_ms
        jitter = random.uniform(-10.0, 10.0)
        
        # Geographic distance simulation
        distance_factor = self._calculate_distance_factor(source, target)
        
        total_latency = base_latency * distance_factor + jitter
        
        # Simulate network delay
        if total_latency > 0:
            await asyncio.sleep(total_latency / 1000.0)
        
        return max(0.0, total_latency)
    
    def simulate_failure(self, operation: str) -> bool:
        """Simulate random operation failures."""
        if not self.config.simulate_failures:
            return False
        
        return random.random() < self.config.failure_rate
    
    def is_node_online(self, node_id: str) -> bool:
        """Check if node is online."""
        if self.config.offline_mode:
            return False
        
        # Random connection status with some persistence
        if node_id not in self.connection_status:
            self.connection_status[node_id] = random.random() > 0.1  # 90% online
        
        # Occasionally change status
        if random.random() < 0.01:  # 1% chance per check
            self.connection_status[node_id] = not self.connection_status[node_id]
        
        return self.connection_status[node_id]
    
    def _calculate_distance_factor(self, source: str, target: str) -> float:
        """Calculate network distance factor between nodes."""
        # Simple hash-based distance simulation
        source_hash = hash(source) % 1000
        target_hash = hash(target) % 1000
        distance = abs(source_hash - target_hash)
        
        # Scale distance to reasonable latency multiplier
        return 1.0 + (distance / 1000.0)


class MockCloudEndpoint:
    """Mock cloud endpoint for edge-to-cloud synchronization."""
    
    def __init__(self, config: MockEdgeTestConfig):
        self.config = config
        self.policies = {}
        self.node_registrations = {}
        self.sync_requests = []
        self.manifest_version = 1
        
        # Initialize with some default policies
        self._create_default_policies()
    
    def _create_default_policies(self):
        """Create default test policies."""
        policies = [
            {
                'policy_id': 'global_rate_limit',
                'name': 'Global Rate Limiting',
                'version': '1.0.0',
                'priority': 100,
                'conditions': {'path_pattern': '/api/*'},
                'actions': {'rate_limit': {'requests': 100, 'window': 60}},
                'resource_constraints': {'memory_mb': 5, 'cpu_percent': 2}
            },
            {
                'policy_id': 'security_headers',
                'name': 'Security Headers',
                'version': '2.1.0',
                'priority': 90,
                'conditions': {'methods': ['GET', 'POST']},
                'actions': {'headers': {'X-Frame-Options': 'DENY'}},
                'resource_constraints': {'memory_mb': 2, 'cpu_percent': 1}
            },
            {
                'policy_id': 'bot_protection',
                'name': 'Bot Protection',
                'version': '1.5.0',
                'priority': 80,
                'conditions': {'path_pattern': '/api/public/*'},
                'actions': {'challenge': {'type': 'captcha'}},
                'resource_constraints': {'memory_mb': 10, 'cpu_percent': 5}
            }
        ]
        
        for policy_data in policies:
            policy = EdgePolicy(**policy_data)
            self.policies[policy.policy_id] = policy
    
    async def get_manifest(self, node_id: str) -> Dict[str, Any]:
        """Get policy manifest for node."""
        await asyncio.sleep(0.01)  # Simulate network delay
        
        if self.config.simulate_failures and random.random() < self.config.failure_rate:
            raise Exception("Cloud endpoint temporarily unavailable")
        
        self.sync_requests.append({
            'node_id': node_id,
            'timestamp': time.time(),
            'operation': 'get_manifest'
        })
        
        return {
            'node_id': node_id,
            'manifest_version': self.manifest_version,
            'timestamp': time.time(),
            'policies': {
                policy_id: {
                    'version': policy.version,
                    'checksum': policy.checksum,
                    'size': policy.size_bytes,
                    'priority': policy.priority
                }
                for policy_id, policy in self.policies.items()
            }
        }
    
    async def get_policy(self, policy_id: str, node_id: str) -> Optional[EdgePolicy]:
        """Get specific policy for node."""
        await asyncio.sleep(0.02)  # Simulate download time
        
        if self.config.simulate_failures and random.random() < self.config.failure_rate:
            raise Exception(f"Failed to download policy {policy_id}")
        
        self.sync_requests.append({
            'node_id': node_id,
            'timestamp': time.time(),
            'operation': 'get_policy',
            'policy_id': policy_id
        })
        
        return self.policies.get(policy_id)
    
    def register_node(self, node: EdgeNode):
        """Register edge node with cloud."""
        self.node_registrations[node.node_id] = {
            'node': node,
            'registered_at': time.time(),
            'last_heartbeat': time.time()
        }
    
    def update_node_heartbeat(self, node_id: str):
        """Update node heartbeat timestamp."""
        if node_id in self.node_registrations:
            self.node_registrations[node_id]['last_heartbeat'] = time.time()
    
    def add_policy(self, policy: EdgePolicy):
        """Add new policy to cloud."""
        self.policies[policy.policy_id] = policy
        self.manifest_version += 1
    
    def update_policy(self, policy: EdgePolicy):
        """Update existing policy."""
        self.policies[policy.policy_id] = policy
        self.manifest_version += 1
    
    def get_sync_stats(self) -> Dict[str, Any]:
        """Get synchronization statistics."""
        return {
            'total_policies': len(self.policies),
            'registered_nodes': len(self.node_registrations),
            'sync_requests': len(self.sync_requests),
            'manifest_version': self.manifest_version,
            'recent_requests': self.sync_requests[-10:] if self.sync_requests else []
        }


class MockCDNProvider:
    """Mock CDN provider for testing CDN integration."""
    
    def __init__(self, provider_name: str = "MockCDN"):
        self.provider_name = provider_name
        self.cache_rules = {}
        self.purge_requests = []
        self.cached_responses = {}
        self.edge_locations = [
            "us-east-1", "us-west-1", "eu-west-1", "ap-southeast-1"
        ]
        
    def add_cache_rule(self, path_pattern: str, rule_config: Dict[str, Any]):
        """Add caching rule for path pattern."""
        self.cache_rules[path_pattern] = rule_config
    
    def should_cache(self, path: str, status_code: int) -> bool:
        """Check if response should be cached."""
        if status_code != 200:
            return False
        
        for pattern, config in self.cache_rules.items():
            if self._matches_pattern(path, pattern):
                return config.get('enabled', True)
        
        return False
    
    def get_cache_headers(self, path: str) -> Dict[str, str]:
        """Get cache headers for path."""
        headers = {}
        
        for pattern, config in self.cache_rules.items():
            if self._matches_pattern(path, pattern):
                if 'max_age' in config:
                    headers['Cache-Control'] = f"public, max-age={config['max_age']}"
                if 'etag' in config:
                    headers['ETag'] = f'"{hash(path) % 100000}"'
                break
        
        return headers
    
    async def purge_cache(self, path_pattern: str, tags: List[str] = None):
        """Simulate cache purge operation."""
        purge_request = {
            'path_pattern': path_pattern,
            'tags': tags or [],
            'timestamp': time.time(),
            'request_id': str(uuid.uuid4())
        }
        
        self.purge_requests.append(purge_request)
        
        # Simulate purge delay
        await asyncio.sleep(0.1)
        
        # Remove matching cached responses
        to_remove = []
        for cached_path in self.cached_responses.keys():
            if self._matches_pattern(cached_path, path_pattern):
                to_remove.append(cached_path)
        
        for path in to_remove:
            del self.cached_responses[path]
        
        return {'status': 'success', 'purged_paths': len(to_remove)}
    
    def cache_response(self, path: str, response_data: Any, ttl_seconds: int = 3600):
        """Cache response data."""
        self.cached_responses[path] = {
            'data': response_data,
            'cached_at': time.time(),
            'ttl': ttl_seconds,
            'expires_at': time.time() + ttl_seconds
        }
    
    def get_cached_response(self, path: str) -> Optional[Any]:
        """Get cached response if available and not expired."""
        if path in self.cached_responses:
            cached = self.cached_responses[path]
            if time.time() < cached['expires_at']:
                return cached['data']
            else:
                # Remove expired entry
                del self.cached_responses[path]
        
        return None
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches pattern."""
        import re
        pattern = pattern.replace('*', '.*').replace('?', '.')
        return bool(re.match(f"^{pattern}$", path))
    
    def get_cdn_stats(self) -> Dict[str, Any]:
        """Get CDN statistics."""
        total_cached = len(self.cached_responses)
        expired_entries = sum(1 for entry in self.cached_responses.values() 
                            if time.time() >= entry['expires_at'])
        
        return {
            'provider_name': self.provider_name,
            'edge_locations': len(self.edge_locations),
            'cache_rules': len(self.cache_rules),
            'cached_responses': total_cached,
            'expired_entries': expired_entries,
            'purge_requests': len(self.purge_requests),
            'recent_purges': self.purge_requests[-5:] if self.purge_requests else []
        }


class MockResourceMonitor:
    """Mock resource monitoring for edge devices."""
    
    def __init__(self, resource_level: EdgeResourceLevel):
        self.resource_level = resource_level
        self.memory_usage_history = deque(maxlen=100)
        self.cpu_usage_history = deque(maxlen=100)
        self.network_stats = {'bytes_sent': 0, 'bytes_received': 0}
        
        # Set realistic resource constraints
        self.constraints = {
            EdgeResourceLevel.ULTRA_LOW: {
                'max_memory_mb': 64,
                'max_cpu_percent': 80,
                'max_bandwidth_kbps': 100
            },
            EdgeResourceLevel.LOW: {
                'max_memory_mb': 256,
                'max_cpu_percent': 70,
                'max_bandwidth_kbps': 1000
            },
            EdgeResourceLevel.MEDIUM: {
                'max_memory_mb': 1024,
                'max_cpu_percent': 60,
                'max_bandwidth_kbps': 10000
            },
            EdgeResourceLevel.HIGH: {
                'max_memory_mb': 4096,
                'max_cpu_percent': 50,
                'max_bandwidth_kbps': 100000
            },
            EdgeResourceLevel.UNLIMITED: {
                'max_memory_mb': 16384,
                'max_cpu_percent': 40,
                'max_bandwidth_kbps': 1000000
            }
        }
    
    def get_memory_usage(self) -> float:
        """Get current memory usage as fraction."""
        # Simulate memory usage with some variation
        base_usage = 0.3 + (len(self.memory_usage_history) * 0.001)
        variation = random.uniform(-0.1, 0.1)
        usage = max(0.1, min(0.9, base_usage + variation))
        
        self.memory_usage_history.append({
            'timestamp': time.time(),
            'usage': usage
        })
        
        return usage
    
    def get_cpu_usage(self) -> float:
        """Get current CPU usage as fraction."""
        # Simulate CPU usage with spikes
        base_usage = 0.2 + random.uniform(0.0, 0.3)
        
        # Occasional CPU spikes
        if random.random() < 0.1:
            base_usage += random.uniform(0.2, 0.4)
        
        usage = max(0.05, min(0.95, base_usage))
        
        self.cpu_usage_history.append({
            'timestamp': time.time(),
            'usage': usage
        })
        
        return usage
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory usage statistics."""
        if not self.memory_usage_history:
            return {'current': 0.0, 'average': 0.0, 'peak': 0.0}
        
        usage_values = [entry['usage'] for entry in self.memory_usage_history]
        
        return {
            'current': usage_values[-1],
            'average': sum(usage_values) / len(usage_values),
            'peak': max(usage_values),
            'min': min(usage_values),
            'trend': (usage_values[-1] - usage_values[0]) if len(usage_values) > 1 else 0
        }
    
    def get_cpu_stats(self) -> Dict[str, Any]:
        """Get CPU usage statistics."""
        if not self.cpu_usage_history:
            return {'current': 0.0, 'average': 0.0, 'peak': 0.0}
        
        usage_values = [entry['usage'] for entry in self.cpu_usage_history]
        
        return {
            'current': usage_values[-1],
            'average': sum(usage_values) / len(usage_values),
            'peak': max(usage_values),
            'min': min(usage_values)
        }
    
    def is_resource_constrained(self) -> bool:
        """Check if device is currently resource constrained."""
        constraints = self.constraints[self.resource_level]
        
        memory_usage = self.get_memory_usage()
        cpu_usage = self.get_cpu_usage()
        
        memory_mb = memory_usage * constraints['max_memory_mb']
        cpu_percent = cpu_usage * 100
        
        return (memory_mb > constraints['max_memory_mb'] * 0.8 or
                cpu_percent > constraints['max_cpu_percent'] * 0.8)
    
    def simulate_network_usage(self, bytes_sent: int, bytes_received: int):
        """Simulate network usage."""
        self.network_stats['bytes_sent'] += bytes_sent
        self.network_stats['bytes_received'] += bytes_received
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get network usage statistics."""
        return {
            'bytes_sent': self.network_stats['bytes_sent'],
            'bytes_received': self.network_stats['bytes_received'],
            'total_bytes': self.network_stats['bytes_sent'] + self.network_stats['bytes_received']
        }


class MockDistributedCluster:
    """Mock distributed cluster for consensus testing."""
    
    def __init__(self):
        self.nodes = {}
        self.leader_node_id = None
        self.cluster_term = 1
        self.log_entries = []
        self.node_states = {}
    
    def add_node(self, node: EdgeNode):
        """Add node to cluster."""
        self.nodes[node.node_id] = node
        self.node_states[node.node_id] = {
            'is_leader': False,
            'current_term': self.cluster_term,
            'voted_for': None,
            'log_index': len(self.log_entries),
            'last_heartbeat': time.time()
        }
        
        # First node becomes leader
        if not self.leader_node_id:
            self.elect_leader(node.node_id)
    
    def remove_node(self, node_id: str):
        """Remove node from cluster."""
        if node_id in self.nodes:
            del self.nodes[node_id]
            del self.node_states[node_id]
            
            # Elect new leader if current leader was removed
            if self.leader_node_id == node_id:
                self.elect_new_leader()
    
    def elect_leader(self, node_id: str):
        """Elect specific node as leader."""
        # Reset all nodes to followers
        for state in self.node_states.values():
            state['is_leader'] = False
        
        # Make specified node the leader
        if node_id in self.node_states:
            self.leader_node_id = node_id
            self.node_states[node_id]['is_leader'] = True
            self.cluster_term += 1
            
            # Update term for all nodes
            for state in self.node_states.values():
                state['current_term'] = self.cluster_term
    
    def elect_new_leader(self):
        """Elect new leader randomly from available nodes."""
        online_nodes = [node_id for node_id, node in self.nodes.items() if node.is_online]
        if online_nodes:
            new_leader = random.choice(online_nodes)
            self.elect_leader(new_leader)
    
    def propose_log_entry(self, proposer_node_id: str, entry_type: str, data: Dict[str, Any]) -> bool:
        """Propose new log entry to cluster."""
        if proposer_node_id != self.leader_node_id:
            return False  # Only leader can propose
        
        log_entry = {
            'term': self.cluster_term,
            'index': len(self.log_entries),
            'type': entry_type,
            'data': data,
            'timestamp': time.time(),
            'proposer': proposer_node_id
        }
        
        self.log_entries.append(log_entry)
        
        # Update log index for all nodes
        for state in self.node_states.values():
            state['log_index'] = len(self.log_entries)
        
        return True
    
    def get_cluster_state(self) -> Dict[str, Any]:
        """Get current cluster state."""
        online_nodes = sum(1 for node in self.nodes.values() if node.is_online)
        
        return {
            'total_nodes': len(self.nodes),
            'online_nodes': online_nodes,
            'leader_node_id': self.leader_node_id,
            'current_term': self.cluster_term,
            'log_entries': len(self.log_entries),
            'consensus_health': online_nodes / len(self.nodes) if self.nodes else 0
        }
    
    def simulate_node_failure(self, node_id: str):
        """Simulate node failure."""
        if node_id in self.nodes:
            self.nodes[node_id].is_online = False
            
            # Trigger leader election if leader failed
            if node_id == self.leader_node_id:
                self.elect_new_leader()
    
    def simulate_node_recovery(self, node_id: str):
        """Simulate node recovery."""
        if node_id in self.nodes:
            self.nodes[node_id].is_online = True
            self.nodes[node_id].last_heartbeat = datetime.now(timezone.utc)


class MockEdgeTestEnvironment:
    """Complete mock environment for edge computing testing."""
    
    def __init__(self, config: MockEdgeTestConfig = None):
        self.config = config or MockEdgeTestConfig()
        
        # Initialize mock components
        self.network_simulator = MockNetworkSimulator(self.config)
        self.cloud_endpoint = MockCloudEndpoint(self.config)
        self.cdn_provider = MockCDNProvider()
        self.distributed_cluster = MockDistributedCluster()
        
        # Edge nodes and their monitors
        self.edge_nodes = {}
        self.resource_monitors = {}
        
        # Test data and metrics
        self.test_requests = []
        self.performance_metrics = MockEdgeMetrics()
        
        # Initialize with some default nodes
        self._create_default_nodes()
    
    def _create_default_nodes(self):
        """Create default edge nodes for testing."""
        default_nodes = [
            {
                'node_id': 'cdn-edge-01',
                'location_type': EdgeLocation.CDN_EDGE,
                'resource_level': EdgeResourceLevel.HIGH,
                'capabilities': [
                    EdgeCapability.LOCAL_CACHE,
                    EdgeCapability.CDN_INTEGRATION,
                    EdgeCapability.POLICY_SYNC
                ],
                'region': 'us-east-1'
            },
            {
                'node_id': 'iot-gateway-01',
                'location_type': EdgeLocation.IOT_GATEWAY,
                'resource_level': EdgeResourceLevel.LOW,
                'capabilities': [
                    EdgeCapability.LOCAL_CACHE,
                    EdgeCapability.OFFLINE_AUTH,
                    EdgeCapability.COMPRESSION
                ],
                'region': 'us-west-1'
            },
            {
                'node_id': 'mobile-edge-01',
                'location_type': EdgeLocation.MOBILE_EDGE,
                'resource_level': EdgeResourceLevel.MEDIUM,
                'capabilities': [
                    EdgeCapability.LOCAL_CACHE,
                    EdgeCapability.POLICY_SYNC,
                    EdgeCapability.DISTRIBUTED_STATE
                ],
                'region': 'eu-west-1'
            }
        ]
        
        for node_config in default_nodes:
            self.create_edge_node(**node_config)
    
    def create_edge_node(self, node_id: str, location_type: EdgeLocation,
                        resource_level: EdgeResourceLevel, capabilities: List[EdgeCapability],
                        region: str = "default") -> EdgeNode:
        """Create and register edge node."""
        node = EdgeNode(
            node_id=node_id,
            location_type=location_type,
            resource_level=resource_level,
            capabilities=capabilities,
            endpoint=f"https://{node_id}.edge.example.com",
            region=region,
            is_online=True,
            last_heartbeat=datetime.now(timezone.utc)
        )
        
        self.edge_nodes[node_id] = node
        self.resource_monitors[node_id] = MockResourceMonitor(resource_level)
        
        # Register with cloud and cluster
        self.cloud_endpoint.register_node(node)
        self.distributed_cluster.add_node(node)
        
        return node
    
    def create_test_request(self, method: str = "GET", path: str = "/api/test",
                          headers: Dict[str, str] = None, client_ip: str = None) -> Mock:
        """Create mock request for testing."""
        mock_request = Mock(spec=Request)
        mock_request.method = method
        mock_request.url.path = path
        mock_request.url.scheme = "https"
        mock_request.headers = headers or {}
        mock_request.client.host = client_ip or f"192.168.1.{random.randint(1, 254)}"
        mock_request.query_params = {}
        mock_request.cookies = {}
        
        # Mock URL string representation
        mock_request.url.__str__ = lambda: f"https://api.example.com{path}"
        
        return mock_request
    
    def create_authenticated_request(self, method: str = "GET", path: str = "/api/secure",
                                   user_id: str = "test_user") -> Mock:
        """Create authenticated mock request."""
        token = f"mock_token_{user_id}_{int(time.time())}"
        headers = {
            'authorization': f'Bearer {token}',
            'user-agent': 'EdgeTestClient/1.0'
        }
        
        request = self.create_test_request(method, path, headers)
        
        # Cache authentication info for offline auth testing
        for node_id, monitor in self.resource_monitors.items():
            node = self.edge_nodes[node_id]
            if EdgeCapability.OFFLINE_AUTH in node.capabilities:
                # Would cache auth in real offline auth cache
                pass
        
        return request
    
    def simulate_edge_request_scenario(self, node_id: str, request: Mock) -> Dict[str, Any]:
        """Simulate processing request through specific edge node."""
        if node_id not in self.edge_nodes:
            raise ValueError(f"Node {node_id} not found")
        
        node = self.edge_nodes[node_id]
        monitor = self.resource_monitors[node_id]
        
        # Record request start
        start_time = time.time()
        
        # Simulate resource usage
        memory_before = monitor.get_memory_usage()
        cpu_before = monitor.get_cpu_usage()
        
        # Simulate request processing
        processing_time = random.uniform(0.001, 0.050)  # 1-50ms
        time.sleep(processing_time * 0.1)  # Scaled down for testing
        
        # Simulate various processing outcomes
        outcomes = {
            'cache_hit': 0.3,
            'cache_miss': 0.4,
            'policy_applied': 0.2,
            'auth_check': 0.6,
            'normal_processing': 0.8
        }
        
        result = {}
        for outcome, probability in outcomes.items():
            if random.random() < probability:
                result[outcome] = True
                # Update metrics
                if outcome == 'cache_hit':
                    self.performance_metrics.cache_hits += 1
                elif outcome == 'cache_miss':
                    self.performance_metrics.cache_misses += 1
                elif outcome == 'auth_check':
                    if random.random() < 0.9:  # 90% auth success
                        self.performance_metrics.auth_successes += 1
                    else:
                        self.performance_metrics.auth_failures += 1
        
        # Update resource usage
        memory_after = monitor.get_memory_usage()
        cpu_after = monitor.get_cpu_usage()
        
        # Calculate performance metrics
        end_time = time.time()
        total_latency = (end_time - start_time) * 1000  # milliseconds
        
        self.performance_metrics.requests_processed += 1
        
        return {
            'node_id': node_id,
            'request_method': request.method,
            'request_path': request.url.path,
            'processing_time_ms': total_latency,
            'memory_delta': memory_after - memory_before,
            'cpu_delta': cpu_after - cpu_before,
            'outcomes': result,
            'timestamp': end_time
        }
    
    def simulate_policy_sync(self, node_id: str) -> Dict[str, Any]:
        """Simulate policy synchronization for node."""
        if node_id not in self.edge_nodes:
            raise ValueError(f"Node {node_id} not found")
        
        start_time = time.time()
        
        try:
            # Simulate fetching manifest
            manifest = asyncio.run(self.cloud_endpoint.get_manifest(node_id))
            
            # Simulate policy downloads
            policies_updated = 0
            for policy_id in manifest['policies'].keys():
                if random.random() < 0.7:  # 70% chance of update needed
                    policy = asyncio.run(self.cloud_endpoint.get_policy(policy_id, node_id))
                    if policy:
                        policies_updated += 1
            
            sync_duration = (time.time() - start_time) * 1000
            
            self.performance_metrics.policy_syncs += 1
            
            return {
                'node_id': node_id,
                'sync_duration_ms': sync_duration,
                'policies_updated': policies_updated,
                'manifest_version': manifest['manifest_version'],
                'success': True
            }
        
        except Exception as e:
            return {
                'node_id': node_id,
                'sync_duration_ms': (time.time() - start_time) * 1000,
                'error': str(e),
                'success': False
            }
    
    def simulate_consensus_decision(self, decision_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate distributed consensus decision."""
        leader_node = self.distributed_cluster.leader_node_id
        
        if not leader_node:
            return {
                'success': False,
                'error': 'No leader available'
            }
        
        start_time = time.time()
        
        # Propose to cluster
        success = self.distributed_cluster.propose_log_entry(leader_node, decision_type, data)
        
        decision_time = (time.time() - start_time) * 1000
        
        if success:
            self.performance_metrics.consensus_decisions += 1
        
        return {
            'leader_node': leader_node,
            'decision_type': decision_type,
            'decision_time_ms': decision_time,
            'success': success,
            'cluster_state': self.distributed_cluster.get_cluster_state()
        }
    
    def simulate_cdn_operation(self, operation: str, path: str, **kwargs) -> Dict[str, Any]:
        """Simulate CDN operations."""
        start_time = time.time()
        
        if operation == 'cache':
            response_data = kwargs.get('response_data', {'status': 'ok'})
            ttl = kwargs.get('ttl', 3600)
            self.cdn_provider.cache_response(path, response_data, ttl)
            
        elif operation == 'purge':
            tags = kwargs.get('tags', [])
            result = asyncio.run(self.cdn_provider.purge_cache(path, tags))
            
        elif operation == 'get':
            result = self.cdn_provider.get_cached_response(path)
        
        operation_time = (time.time() - start_time) * 1000
        
        self.performance_metrics.cdn_operations += 1
        
        return {
            'operation': operation,
            'path': path,
            'operation_time_ms': operation_time,
            'success': True,
            'timestamp': time.time()
        }
    
    def simulate_network_partition(self, affected_nodes: List[str], duration_seconds: float = 10):
        """Simulate network partition affecting specific nodes."""
        # Mark nodes as offline
        for node_id in affected_nodes:
            if node_id in self.edge_nodes:
                self.network_simulator.connection_status[node_id] = False
                self.distributed_cluster.simulate_node_failure(node_id)
        
        # Schedule recovery
        def recover():
            time.sleep(duration_seconds)
            for node_id in affected_nodes:
                if node_id in self.edge_nodes:
                    self.network_simulator.connection_status[node_id] = True
                    self.distributed_cluster.simulate_node_recovery(node_id)
        
        # Run recovery in background
        recovery_thread = Thread(target=recover, daemon=True)
        recovery_thread.start()
        
        return {
            'affected_nodes': affected_nodes,
            'duration_seconds': duration_seconds,
            'recovery_scheduled': True
        }
    
    def run_performance_test(self, test_duration_seconds: int = 60, 
                           requests_per_second: int = 10) -> Dict[str, Any]:
        """Run comprehensive performance test."""
        start_time = time.time()
        test_results = []
        
        # Reset metrics
        self.performance_metrics = MockEdgeMetrics()
        
        while (time.time() - start_time) < test_duration_seconds:
            # Generate test requests across nodes
            for _ in range(requests_per_second):
                node_id = random.choice(list(self.edge_nodes.keys()))
                request = self.create_test_request(
                    method=random.choice(['GET', 'POST']),
                    path=random.choice(['/api/test', '/api/data', '/api/public'])
                )
                
                result = self.simulate_edge_request_scenario(node_id, request)
                test_results.append(result)
            
            # Occasional policy sync
            if random.random() < 0.1:  # 10% chance
                node_id = random.choice(list(self.edge_nodes.keys()))
                sync_result = self.simulate_policy_sync(node_id)
                test_results.append(sync_result)
            
            # Wait for next batch
            time.sleep(1.0)
        
        total_time = time.time() - start_time
        
        # Calculate performance statistics
        request_latencies = [r.get('processing_time_ms', 0) for r in test_results 
                           if 'processing_time_ms' in r]
        
        return {
            'test_duration_seconds': total_time,
            'total_requests': len([r for r in test_results if 'processing_time_ms' in r]),
            'requests_per_second': len(request_latencies) / total_time,
            'avg_latency_ms': sum(request_latencies) / len(request_latencies) if request_latencies else 0,
            'min_latency_ms': min(request_latencies) if request_latencies else 0,
            'max_latency_ms': max(request_latencies) if request_latencies else 0,
            'metrics': asdict(self.performance_metrics),
            'node_resource_usage': {
                node_id: monitor.get_memory_stats()
                for node_id, monitor in self.resource_monitors.items()
            }
        }
    
    def get_environment_stats(self) -> Dict[str, Any]:
        """Get comprehensive environment statistics."""
        return {
            'edge_nodes': len(self.edge_nodes),
            'online_nodes': sum(1 for node in self.edge_nodes.values() if node.is_online),
            'cloud_endpoint': self.cloud_endpoint.get_sync_stats(),
            'cdn_provider': self.cdn_provider.get_cdn_stats(),
            'distributed_cluster': self.distributed_cluster.get_cluster_state(),
            'performance_metrics': asdict(self.performance_metrics),
            'config': asdict(self.config)
        }


# Utility functions for creating test scenarios

def create_iot_gateway_scenario() -> Dict[str, Any]:
    """Create IoT gateway test scenario."""
    env = MockEdgeTestEnvironment(MockEdgeTestConfig(
        simulate_network_latency=True,
        network_latency_ms=100.0,  # Higher latency for IoT
        resource_constraints=True
    ))
    
    # Add IoT-specific nodes
    env.create_edge_node(
        node_id="iot-factory-01",
        location_type=EdgeLocation.FACTORY_EDGE,
        resource_level=EdgeResourceLevel.LOW,
        capabilities=[EdgeCapability.LOCAL_CACHE, EdgeCapability.OFFLINE_AUTH],
        region="factory-floor"
    )
    
    return {
        'environment': env,
        'test_requests': [
            env.create_test_request('POST', '/api/sensors/data'),
            env.create_test_request('GET', '/api/config'),
            env.create_authenticated_request('POST', '/api/control')
        ]
    }


def create_cdn_edge_scenario() -> Dict[str, Any]:
    """Create CDN edge test scenario."""
    env = MockEdgeTestEnvironment(MockEdgeTestConfig(
        simulate_network_latency=True,
        network_latency_ms=20.0,  # Low latency for CDN
        resource_constraints=False
    ))
    
    # Configure CDN caching
    env.cdn_provider.add_cache_rule('/static/*', {
        'enabled': True,
        'max_age': 86400,  # 24 hours
        'etag': True
    })
    
    return {
        'environment': env,
        'test_requests': [
            env.create_test_request('GET', '/static/js/app.js'),
            env.create_test_request('GET', '/static/css/style.css'),
            env.create_test_request('GET', '/api/dynamic')
        ]
    }


def create_mobile_edge_scenario() -> Dict[str, Any]:
    """Create mobile edge test scenario."""
    config = MockEdgeTestConfig(
        simulate_network_latency=True,
        network_latency_ms=50.0,
        simulate_failures=True,
        failure_rate=0.1  # Higher failure rate for mobile
    )
    
    env = MockEdgeTestEnvironment(config)
    
    # Add mobile-specific nodes
    env.create_edge_node(
        node_id="mobile-tower-01",
        location_type=EdgeLocation.MOBILE_EDGE,
        resource_level=EdgeResourceLevel.MEDIUM,
        capabilities=[
            EdgeCapability.LOCAL_CACHE,
            EdgeCapability.POLICY_SYNC,
            EdgeCapability.DISTRIBUTED_STATE
        ],
        region="cellular-network"
    )
    
    return {
        'environment': env,
        'test_requests': [
            env.create_test_request('GET', '/api/location'),
            env.create_authenticated_request('POST', '/api/user/update'),
            env.create_test_request('GET', '/api/nearby')
        ]
    }


# Context manager for edge testing
class mock_edge_environment:
    """Context manager for mock edge testing environment."""
    
    def __init__(self, config: MockEdgeTestConfig = None):
        self.config = config or MockEdgeTestConfig()
        self.environment = None
    
    def __enter__(self) -> MockEdgeTestEnvironment:
        self.environment = MockEdgeTestEnvironment(self.config)
        return self.environment
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Cleanup if needed
        pass


if __name__ == "__main__":
    # Example usage
    with mock_edge_environment() as env:
        # Create test scenario
        request = env.create_test_request('GET', '/api/test')
        result = env.simulate_edge_request_scenario('cdn-edge-01', request)
        
        print(f"Request processed: {result}")
        print(f"Environment stats: {env.get_environment_stats()}")