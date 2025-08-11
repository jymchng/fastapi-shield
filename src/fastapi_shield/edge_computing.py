"""FastAPI-Shield Edge Computing Support

This module provides comprehensive edge computing support for FastAPI-Shield,
enabling lightweight, distributed security operations at the edge with:
- Minimal memory and CPU footprint optimization
- Offline authentication and caching capabilities  
- Edge-to-cloud policy synchronization
- CDN integration and distributed coordination
- Local decision making with global policy consistency
- High-performance edge deployment optimization
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import pickle
import sqlite3
import time
import uuid
import zlib
from abc import ABC, abstractmethod
from collections import defaultdict, deque, OrderedDict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps, lru_cache
from pathlib import Path
from threading import RLock, Lock, Event, Thread
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    NamedTuple, Protocol, TypeVar, AsyncIterator
)
import weakref

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# Edge computing specific enums and constants
class EdgeLocation(Enum):
    """Edge computing location types."""
    CDN_EDGE = "cdn_edge"           # CDN edge servers
    IOT_GATEWAY = "iot_gateway"     # IoT gateway devices  
    MOBILE_EDGE = "mobile_edge"     # Mobile edge computing
    RETAIL_EDGE = "retail_edge"     # Retail edge locations
    FACTORY_EDGE = "factory_edge"   # Factory/industrial edge
    VEHICLE_EDGE = "vehicle_edge"   # Vehicle edge computing
    HOME_EDGE = "home_edge"         # Home edge devices
    CUSTOM_EDGE = "custom_edge"     # Custom edge deployments


class EdgeCapability(Enum):
    """Edge computing capabilities."""
    OFFLINE_AUTH = "offline_auth"           # Offline authentication
    LOCAL_CACHE = "local_cache"            # Local caching
    POLICY_SYNC = "policy_sync"            # Policy synchronization
    CDN_INTEGRATION = "cdn_integration"    # CDN integration
    DISTRIBUTED_STATE = "distributed_state" # Distributed state management
    CONSENSUS = "consensus"                # Distributed consensus
    COMPRESSION = "compression"            # Data compression
    ENCRYPTION = "encryption"              # Edge encryption
    ANALYTICS = "analytics"                # Local analytics
    MONITORING = "monitoring"              # Edge monitoring


class SyncMode(Enum):
    """Policy synchronization modes."""
    REAL_TIME = "real_time"        # Real-time synchronization
    PERIODIC = "periodic"          # Periodic synchronization
    ON_DEMAND = "on_demand"        # On-demand synchronization
    EVENT_DRIVEN = "event_driven"  # Event-driven synchronization
    OFFLINE = "offline"            # Offline-first mode


class EdgeResourceLevel(Enum):
    """Edge resource constraint levels."""
    ULTRA_LOW = "ultra_low"    # < 64MB RAM, < 100MHz CPU
    LOW = "low"                # < 256MB RAM, < 500MHz CPU  
    MEDIUM = "medium"          # < 1GB RAM, < 1GHz CPU
    HIGH = "high"              # < 4GB RAM, < 2GHz CPU
    UNLIMITED = "unlimited"    # No resource constraints


class ConsensusAlgorithm(Enum):
    """Distributed consensus algorithms."""
    RAFT = "raft"              # Raft consensus
    PBFT = "pbft"              # Practical Byzantine Fault Tolerance
    GOSSIP = "gossip"          # Gossip protocol
    EVENTUAL = "eventual"      # Eventual consistency
    QUORUM = "quorum"          # Quorum-based consensus


@dataclass
class EdgeNode:
    """Edge computing node definition."""
    node_id: str
    location_type: EdgeLocation
    resource_level: EdgeResourceLevel
    capabilities: List[EdgeCapability]
    endpoint: str
    region: str
    cluster_id: Optional[str] = None
    is_online: bool = True
    last_heartbeat: Optional[datetime] = None
    load_factor: float = 0.0  # Current load 0.0-1.0
    latency_ms: Optional[float] = None
    bandwidth_mbps: Optional[float] = None
    storage_mb: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.last_heartbeat:
            self.last_heartbeat = datetime.now(timezone.utc)


@dataclass  
class EdgePolicy:
    """Edge-optimized security policy."""
    policy_id: str
    name: str
    version: str
    priority: int
    conditions: Dict[str, Any]
    actions: Dict[str, Any]
    resource_constraints: Dict[str, Any]
    expiry: Optional[datetime] = None
    checksum: Optional[str] = None
    compressed: bool = False
    size_bytes: int = 0
    
    def __post_init__(self):
        if not self.checksum:
            self.checksum = self._calculate_checksum()
        if not self.size_bytes:
            self.size_bytes = len(json.dumps(asdict(self), default=str))
    
    def _calculate_checksum(self) -> str:
        """Calculate policy checksum for integrity verification."""
        policy_data = {
            'policy_id': self.policy_id,
            'name': self.name,
            'version': self.version,
            'conditions': self.conditions,
            'actions': self.actions
        }
        content = json.dumps(policy_data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify policy integrity using checksum."""
        expected = self._calculate_checksum()
        return hmac.compare_digest(self.checksum or "", expected)
    
    def compress(self) -> bytes:
        """Compress policy data for efficient transmission."""
        policy_data = asdict(self)
        json_data = json.dumps(policy_data, default=str).encode()
        return zlib.compress(json_data, level=9)
    
    @classmethod
    def decompress(cls, compressed_data: bytes) -> 'EdgePolicy':
        """Decompress policy data."""
        json_data = zlib.decompress(compressed_data)
        policy_data = json.loads(json_data.decode())
        return cls(**policy_data)


@dataclass
class EdgeCacheEntry:
    """Edge cache entry with TTL and compression."""
    key: str
    value: Any
    expires_at: datetime
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    compressed: bool = False
    size_bytes: int = 0
    
    def __post_init__(self):
        if not self.last_accessed:
            self.last_accessed = datetime.now(timezone.utc)
        if not self.size_bytes:
            self.size_bytes = len(pickle.dumps(self.value))
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def touch(self):
        """Update access tracking."""
        self.access_count += 1
        self.last_accessed = datetime.now(timezone.utc)
    
    def get_value(self) -> Any:
        """Get cache value and update access tracking."""
        self.touch()
        return self.value


@dataclass
class EdgeSyncState:
    """Edge synchronization state tracking."""
    node_id: str
    last_sync: datetime
    sync_version: int
    policies_count: int
    pending_updates: int
    sync_errors: int = 0
    bandwidth_used_mb: float = 0.0
    sync_duration_ms: float = 0.0
    is_syncing: bool = False


class EdgeOptimizer:
    """Edge resource optimization and monitoring."""
    
    def __init__(self, resource_level: EdgeResourceLevel):
        self.resource_level = resource_level
        self.memory_monitor = MemoryMonitor()
        self.cpu_monitor = CPUMonitor()
        self._optimization_strategies = self._initialize_strategies()
    
    def _initialize_strategies(self) -> Dict[EdgeResourceLevel, Dict[str, Any]]:
        """Initialize optimization strategies based on resource level."""
        return {
            EdgeResourceLevel.ULTRA_LOW: {
                'max_cache_size': 1024 * 1024,      # 1MB cache
                'max_policies': 50,
                'compression_level': 9,
                'gc_threshold': 0.8,
                'sync_batch_size': 5,
                'heartbeat_interval': 300,           # 5 minutes
                'enable_compression': True,
                'enable_analytics': False
            },
            EdgeResourceLevel.LOW: {
                'max_cache_size': 8 * 1024 * 1024,  # 8MB cache
                'max_policies': 200,
                'compression_level': 6,
                'gc_threshold': 0.7,
                'sync_batch_size': 20,
                'heartbeat_interval': 120,           # 2 minutes
                'enable_compression': True,
                'enable_analytics': True
            },
            EdgeResourceLevel.MEDIUM: {
                'max_cache_size': 32 * 1024 * 1024, # 32MB cache
                'max_policies': 1000,
                'compression_level': 3,
                'gc_threshold': 0.6,
                'sync_batch_size': 50,
                'heartbeat_interval': 60,            # 1 minute
                'enable_compression': False,
                'enable_analytics': True
            },
            EdgeResourceLevel.HIGH: {
                'max_cache_size': 128 * 1024 * 1024, # 128MB cache
                'max_policies': 5000,
                'compression_level': 1,
                'gc_threshold': 0.5,
                'sync_batch_size': 100,
                'heartbeat_interval': 30,            # 30 seconds
                'enable_compression': False,
                'enable_analytics': True
            },
            EdgeResourceLevel.UNLIMITED: {
                'max_cache_size': 1024 * 1024 * 1024, # 1GB cache
                'max_policies': 50000,
                'compression_level': 1,
                'gc_threshold': 0.3,
                'sync_batch_size': 500,
                'heartbeat_interval': 15,            # 15 seconds
                'enable_compression': False,
                'enable_analytics': True
            }
        }
    
    def get_strategy(self, key: str) -> Any:
        """Get optimization strategy value."""
        return self._optimization_strategies[self.resource_level].get(key)
    
    def should_compress(self) -> bool:
        """Check if compression should be enabled."""
        return self.get_strategy('enable_compression')
    
    def should_garbage_collect(self, current_usage: float) -> bool:
        """Check if garbage collection should be triggered."""
        threshold = self.get_strategy('gc_threshold')
        return current_usage > threshold
    
    def get_cache_limit(self) -> int:
        """Get cache size limit in bytes."""
        return self.get_strategy('max_cache_size')
    
    def get_policy_limit(self) -> int:
        """Get maximum number of cached policies."""
        return self.get_strategy('max_policies')


class MemoryMonitor:
    """Memory usage monitoring for edge optimization."""
    
    def __init__(self):
        self._usage_history = deque(maxlen=60)  # Last 60 measurements
        self._lock = Lock()
    
    def get_current_usage(self) -> float:
        """Get current memory usage as fraction of available."""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()
            usage_fraction = memory_info.rss / system_memory.total
            
            with self._lock:
                self._usage_history.append({
                    'timestamp': time.time(),
                    'usage': usage_fraction,
                    'rss_mb': memory_info.rss / (1024 * 1024)
                })
            
            return usage_fraction
        except ImportError:
            # Fallback for environments without psutil
            return 0.5  # Assume 50% usage
    
    def get_usage_trend(self) -> Dict[str, float]:
        """Get memory usage trend analysis."""
        with self._lock:
            if len(self._usage_history) < 2:
                return {'trend': 0.0, 'average': 0.5, 'peak': 0.5}
            
            recent = list(self._usage_history)[-10:]  # Last 10 measurements
            usage_values = [entry['usage'] for entry in recent]
            
            trend = (usage_values[-1] - usage_values[0]) / len(usage_values)
            average = sum(usage_values) / len(usage_values)
            peak = max(usage_values)
            
            return {
                'trend': trend,
                'average': average,
                'peak': peak,
                'current': usage_values[-1]
            }


class CPUMonitor:
    """CPU usage monitoring for edge optimization."""
    
    def __init__(self):
        self._usage_history = deque(maxlen=60)
        self._lock = Lock()
    
    def get_current_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil
            cpu_percent = psutil.cpu_percent(interval=0.1)
            usage_fraction = cpu_percent / 100.0
            
            with self._lock:
                self._usage_history.append({
                    'timestamp': time.time(),
                    'usage': usage_fraction
                })
            
            return usage_fraction
        except ImportError:
            return 0.3  # Assume 30% usage
    
    def get_load_average(self) -> float:
        """Get system load average."""
        try:
            import psutil
            load_avg = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 1.0
            return load_avg
        except (ImportError, AttributeError):
            return 1.0


class EdgeCache:
    """High-performance edge cache with LRU eviction and compression."""
    
    def __init__(self, max_size_bytes: int, enable_compression: bool = False):
        self.max_size_bytes = max_size_bytes
        self.enable_compression = enable_compression
        self._cache: OrderedDict[str, EdgeCacheEntry] = OrderedDict()
        self._current_size = 0
        self._lock = RLock()
        self._stats = defaultdict(int)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if entry.is_expired():
                    self._remove_entry(key)
                    self._stats['expired'] += 1
                    return None
                
                # Move to end (most recently used)
                self._cache.move_to_end(key)
                self._stats['hits'] += 1
                return entry.get_value()
            
            self._stats['misses'] += 1
            return None
    
    def put(self, key: str, value: Any, ttl_seconds: int = 3600) -> bool:
        """Put value into cache."""
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        
        # Compress value if enabled
        if self.enable_compression and self._should_compress(value):
            value = self._compress_value(value)
            compressed = True
        else:
            compressed = False
        
        entry = EdgeCacheEntry(
            key=key,
            value=value,
            expires_at=expires_at,
            compressed=compressed
        )
        
        with self._lock:
            # Remove existing entry if present
            if key in self._cache:
                self._remove_entry(key)
            
            # Ensure cache doesn't exceed size limit
            while (self._current_size + entry.size_bytes > self.max_size_bytes and 
                   len(self._cache) > 0):
                self._evict_lru()
            
            if self._current_size + entry.size_bytes <= self.max_size_bytes:
                self._cache[key] = entry
                self._current_size += entry.size_bytes
                self._stats['puts'] += 1
                return True
            
            self._stats['rejected'] += 1
            return False
    
    def remove(self, key: str) -> bool:
        """Remove key from cache."""
        with self._lock:
            if key in self._cache:
                self._remove_entry(key)
                return True
            return False
    
    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._current_size = 0
            self._stats['clears'] += 1
    
    def cleanup_expired(self):
        """Remove expired entries."""
        with self._lock:
            expired_keys = []
            for key, entry in self._cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            for key in expired_keys:
                self._remove_entry(key)
            
            self._stats['cleanup_runs'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = self._stats['hits'] / total_requests if total_requests > 0 else 0
            
            return {
                'size_bytes': self._current_size,
                'max_size_bytes': self.max_size_bytes,
                'entry_count': len(self._cache),
                'hit_rate': hit_rate,
                'stats': dict(self._stats)
            }
    
    def _remove_entry(self, key: str):
        """Remove entry and update size tracking."""
        if key in self._cache:
            entry = self._cache.pop(key)
            self._current_size -= entry.size_bytes
    
    def _evict_lru(self):
        """Evict least recently used entry."""
        if self._cache:
            lru_key = next(iter(self._cache))
            self._remove_entry(lru_key)
            self._stats['evictions'] += 1
    
    def _should_compress(self, value: Any) -> bool:
        """Check if value should be compressed."""
        try:
            size = len(pickle.dumps(value))
            return size > 1024  # Compress values larger than 1KB
        except:
            return False
    
    def _compress_value(self, value: Any) -> bytes:
        """Compress value using zlib."""
        pickled = pickle.dumps(value)
        return zlib.compress(pickled, level=6)


class OfflineAuthCache:
    """Offline authentication cache for edge deployments."""
    
    def __init__(self, db_path: str = ":memory:", max_entries: int = 10000):
        self.db_path = db_path
        self.max_entries = max_entries
        self._lock = RLock()
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for offline auth cache."""
        with self._lock:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS auth_cache (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    permissions TEXT NOT NULL,  -- JSON encoded
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    access_count INTEGER DEFAULT 0,
                    last_access TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_expires_at ON auth_cache(expires_at)
            ''')
            self.conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_user_id ON auth_cache(user_id)
            ''')
            self.conn.commit()
    
    def cache_auth(self, token: str, user_id: str, permissions: List[str], 
                   ttl_seconds: int = 3600) -> bool:
        """Cache authentication information."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        permissions_json = json.dumps(permissions)
        
        with self._lock:
            try:
                # Clean up expired entries first
                self.cleanup_expired()
                
                # Check if we need to make room
                count_result = self.conn.execute('SELECT COUNT(*) FROM auth_cache').fetchone()
                if count_result[0] >= self.max_entries:
                    # Remove oldest entries
                    self.conn.execute('''
                        DELETE FROM auth_cache WHERE token_hash IN (
                            SELECT token_hash FROM auth_cache 
                            ORDER BY last_access ASC LIMIT ?
                        )
                    ''', (self.max_entries // 10,))  # Remove 10%
                
                # Insert or replace auth entry
                self.conn.execute('''
                    INSERT OR REPLACE INTO auth_cache 
                    (token_hash, user_id, permissions, expires_at) 
                    VALUES (?, ?, ?, ?)
                ''', (token_hash, user_id, permissions_json, expires_at))
                
                self.conn.commit()
                return True
            except Exception as e:
                logger.error(f"Failed to cache auth: {e}")
                return False
    
    def verify_auth(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify cached authentication."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        with self._lock:
            try:
                cursor = self.conn.execute('''
                    SELECT user_id, permissions, expires_at, access_count
                    FROM auth_cache 
                    WHERE token_hash = ? AND expires_at > datetime('now')
                ''', (token_hash,))
                
                result = cursor.fetchone()
                if result:
                    user_id, permissions_json, expires_at, access_count = result
                    
                    # Update access tracking
                    self.conn.execute('''
                        UPDATE auth_cache 
                        SET access_count = access_count + 1, last_access = CURRENT_TIMESTAMP
                        WHERE token_hash = ?
                    ''', (token_hash,))
                    self.conn.commit()
                    
                    return {
                        'user_id': user_id,
                        'permissions': json.loads(permissions_json),
                        'expires_at': expires_at,
                        'access_count': access_count + 1
                    }
                
                return None
            except Exception as e:
                logger.error(f"Failed to verify auth: {e}")
                return None
    
    def invalidate_user(self, user_id: str) -> int:
        """Invalidate all cached auth for a user."""
        with self._lock:
            try:
                cursor = self.conn.execute('DELETE FROM auth_cache WHERE user_id = ?', (user_id,))
                self.conn.commit()
                return cursor.rowcount
            except Exception as e:
                logger.error(f"Failed to invalidate user auth: {e}")
                return 0
    
    def cleanup_expired(self) -> int:
        """Clean up expired auth entries."""
        with self._lock:
            try:
                cursor = self.conn.execute("DELETE FROM auth_cache WHERE expires_at <= datetime('now')")
                self.conn.commit()
                return cursor.rowcount
            except Exception as e:
                logger.error(f"Failed to cleanup expired auth: {e}")
                return 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get auth cache statistics."""
        with self._lock:
            try:
                cursor = self.conn.execute('''
                    SELECT 
                        COUNT(*) as total_entries,
                        COUNT(CASE WHEN expires_at > datetime('now') THEN 1 END) as valid_entries,
                        AVG(access_count) as avg_access_count,
                        MAX(access_count) as max_access_count
                    FROM auth_cache
                ''')
                
                result = cursor.fetchone()
                if result:
                    return {
                        'total_entries': result[0],
                        'valid_entries': result[1],
                        'expired_entries': result[0] - result[1],
                        'avg_access_count': round(result[2] or 0, 2),
                        'max_access_count': result[3] or 0
                    }
                
                return {'total_entries': 0, 'valid_entries': 0, 'expired_entries': 0}
            except Exception as e:
                logger.error(f"Failed to get auth stats: {e}")
                return {'error': str(e)}


class PolicySynchronizer:
    """Edge-to-cloud policy synchronization manager."""
    
    def __init__(self, node_id: str, cloud_endpoint: str, sync_mode: SyncMode = SyncMode.PERIODIC):
        self.node_id = node_id
        self.cloud_endpoint = cloud_endpoint
        self.sync_mode = sync_mode
        self.local_policies: Dict[str, EdgePolicy] = {}
        self.sync_state = EdgeSyncState(
            node_id=node_id,
            last_sync=datetime.now(timezone.utc),
            sync_version=0,
            policies_count=0,
            pending_updates=0
        )
        self._lock = RLock()
        self._sync_thread: Optional[Thread] = None
        self._stop_event = Event()
        self._sync_callbacks: List[Callable] = []
        
        if sync_mode == SyncMode.PERIODIC:
            self.start_periodic_sync()
    
    def add_sync_callback(self, callback: Callable[[EdgeSyncState], None]):
        """Add callback for sync state changes."""
        self._sync_callbacks.append(callback)
    
    def start_periodic_sync(self, interval_seconds: int = 300):
        """Start periodic synchronization thread."""
        if self._sync_thread and self._sync_thread.is_alive():
            return
        
        def sync_worker():
            while not self._stop_event.wait(interval_seconds):
                try:
                    asyncio.run(self.sync_policies())
                except Exception as e:
                    logger.error(f"Periodic sync error: {e}")
                    self.sync_state.sync_errors += 1
        
        self._sync_thread = Thread(target=sync_worker, daemon=True)
        self._sync_thread.start()
        logger.info(f"Started periodic policy sync with {interval_seconds}s interval")
    
    def stop_periodic_sync(self):
        """Stop periodic synchronization."""
        if self._sync_thread:
            self._stop_event.set()
            self._sync_thread.join(timeout=5.0)
            logger.info("Stopped periodic policy sync")
    
    async def sync_policies(self) -> bool:
        """Synchronize policies with cloud."""
        with self._lock:
            if self.sync_state.is_syncing:
                return False
            
            self.sync_state.is_syncing = True
            sync_start = time.time()
        
        try:
            # Get cloud policy manifest
            cloud_manifest = await self._fetch_cloud_manifest()
            if not cloud_manifest:
                return False
            
            # Determine what needs to be updated
            updates_needed = self._compare_policies(cloud_manifest)
            
            # Download and update policies
            updated_count = 0
            for policy_id, cloud_version in updates_needed.items():
                policy = await self._fetch_cloud_policy(policy_id, cloud_version)
                if policy and policy.verify_integrity():
                    self.local_policies[policy_id] = policy
                    updated_count += 1
                    logger.info(f"Updated policy {policy_id} to version {cloud_version}")
            
            # Update sync state
            with self._lock:
                self.sync_state.last_sync = datetime.now(timezone.utc)
                self.sync_state.sync_version += 1
                self.sync_state.policies_count = len(self.local_policies)
                self.sync_state.pending_updates = max(0, self.sync_state.pending_updates - updated_count)
                self.sync_state.sync_duration_ms = (time.time() - sync_start) * 1000
                self.sync_state.is_syncing = False
            
            # Notify callbacks
            for callback in self._sync_callbacks:
                try:
                    callback(self.sync_state)
                except Exception as e:
                    logger.error(f"Sync callback error: {e}")
            
            logger.info(f"Policy sync completed: {updated_count} policies updated")
            return True
        
        except Exception as e:
            logger.error(f"Policy sync failed: {e}")
            with self._lock:
                self.sync_state.sync_errors += 1
                self.sync_state.is_syncing = False
            return False
    
    async def _fetch_cloud_manifest(self) -> Optional[Dict[str, Any]]:
        """Fetch policy manifest from cloud."""
        try:
            # In production, this would make HTTP request to cloud endpoint
            # For now, simulate cloud response
            return {
                'node_id': self.node_id,
                'manifest_version': int(time.time()),
                'policies': {
                    'global_rate_limit': {
                        'version': '1.2.0',
                        'checksum': 'abc123',
                        'size': 1024,
                        'priority': 100
                    },
                    'security_headers': {
                        'version': '2.1.0', 
                        'checksum': 'def456',
                        'size': 2048,
                        'priority': 90
                    }
                }
            }
        except Exception as e:
            logger.error(f"Failed to fetch cloud manifest: {e}")
            return None
    
    async def _fetch_cloud_policy(self, policy_id: str, version: str) -> Optional[EdgePolicy]:
        """Fetch specific policy from cloud."""
        try:
            # In production, this would download policy from cloud
            # For now, create mock policy
            return EdgePolicy(
                policy_id=policy_id,
                name=f"Policy {policy_id}",
                version=version,
                priority=100,
                conditions={"path_pattern": "/api/*"},
                actions={"rate_limit": {"requests": 100, "window": 60}},
                resource_constraints={"memory_mb": 10, "cpu_percent": 5}
            )
        except Exception as e:
            logger.error(f"Failed to fetch policy {policy_id}: {e}")
            return None
    
    def _compare_policies(self, cloud_manifest: Dict[str, Any]) -> Dict[str, str]:
        """Compare local policies with cloud manifest."""
        updates_needed = {}
        cloud_policies = cloud_manifest.get('policies', {})
        
        for policy_id, cloud_info in cloud_policies.items():
            cloud_version = cloud_info['version']
            
            if policy_id not in self.local_policies:
                # New policy
                updates_needed[policy_id] = cloud_version
            else:
                local_policy = self.local_policies[policy_id]
                if local_policy.version != cloud_version:
                    # Version mismatch
                    updates_needed[policy_id] = cloud_version
        
        return updates_needed
    
    def get_policy(self, policy_id: str) -> Optional[EdgePolicy]:
        """Get local policy by ID."""
        with self._lock:
            return self.local_policies.get(policy_id)
    
    def get_all_policies(self) -> List[EdgePolicy]:
        """Get all local policies."""
        with self._lock:
            return list(self.local_policies.values())
    
    def get_sync_state(self) -> EdgeSyncState:
        """Get current synchronization state."""
        with self._lock:
            return self.sync_state
    
    def force_sync(self):
        """Force immediate policy synchronization."""
        if self.sync_mode != SyncMode.OFFLINE:
            asyncio.create_task(self.sync_policies())


class DistributedConsensus:
    """Distributed consensus for edge node coordination."""
    
    def __init__(self, node_id: str, algorithm: ConsensusAlgorithm = ConsensusAlgorithm.RAFT):
        self.node_id = node_id
        self.algorithm = algorithm
        self.cluster_nodes: Dict[str, EdgeNode] = {}
        self.is_leader = False
        self.current_term = 0
        self.voted_for: Optional[str] = None
        self.log_entries: List[Dict[str, Any]] = []
        self.commit_index = -1
        self.last_applied = -1
        self._lock = RLock()
        self._heartbeat_thread: Optional[Thread] = None
        self._election_timeout = 5.0  # seconds
        self._heartbeat_interval = 1.0  # seconds
        
        if algorithm == ConsensusAlgorithm.RAFT:
            self._start_raft_protocol()
    
    def _start_raft_protocol(self):
        """Start Raft consensus protocol."""
        def heartbeat_worker():
            while True:
                if self.is_leader:
                    self._send_heartbeats()
                else:
                    self._check_election_timeout()
                time.sleep(self._heartbeat_interval)
        
        self._heartbeat_thread = Thread(target=heartbeat_worker, daemon=True)
        self._heartbeat_thread.start()
    
    def add_node(self, node: EdgeNode):
        """Add node to cluster."""
        with self._lock:
            self.cluster_nodes[node.node_id] = node
            logger.info(f"Added node {node.node_id} to consensus cluster")
    
    def remove_node(self, node_id: str):
        """Remove node from cluster."""
        with self._lock:
            if node_id in self.cluster_nodes:
                del self.cluster_nodes[node_id]
                logger.info(f"Removed node {node_id} from consensus cluster")
    
    def propose_change(self, change_type: str, data: Dict[str, Any]) -> bool:
        """Propose change to cluster state."""
        if not self.is_leader:
            return False
        
        with self._lock:
            log_entry = {
                'term': self.current_term,
                'index': len(self.log_entries),
                'type': change_type,
                'data': data,
                'timestamp': time.time()
            }
            
            self.log_entries.append(log_entry)
            
            # In real Raft, would replicate to followers
            # For now, auto-commit
            self.commit_index = len(self.log_entries) - 1
            self._apply_log_entry(log_entry)
            
            return True
    
    def _send_heartbeats(self):
        """Send heartbeats to follower nodes."""
        with self._lock:
            for node_id, node in self.cluster_nodes.items():
                if node_id != self.node_id and node.is_online:
                    try:
                        # In production, send actual heartbeat to node
                        node.last_heartbeat = datetime.now(timezone.utc)
                    except Exception as e:
                        logger.error(f"Failed to send heartbeat to {node_id}: {e}")
                        node.is_online = False
    
    def _check_election_timeout(self):
        """Check if election timeout occurred."""
        # Simplified election logic
        if not self.is_leader and len(self.cluster_nodes) > 1:
            # Randomly become leader if no heartbeats received
            if time.time() % 10 < 1:  # 10% chance per check
                self._start_election()
    
    def _start_election(self):
        """Start leader election."""
        with self._lock:
            self.current_term += 1
            self.voted_for = self.node_id
            self.is_leader = True
            logger.info(f"Node {self.node_id} became leader for term {self.current_term}")
    
    def _apply_log_entry(self, log_entry: Dict[str, Any]):
        """Apply committed log entry to state machine."""
        try:
            change_type = log_entry['type']
            data = log_entry['data']
            
            if change_type == 'policy_update':
                # Apply policy update
                logger.info(f"Applied policy update: {data.get('policy_id')}")
            elif change_type == 'node_config':
                # Apply node configuration change
                logger.info(f"Applied node config change: {data}")
            
            self.last_applied = log_entry['index']
        except Exception as e:
            logger.error(f"Failed to apply log entry: {e}")
    
    def get_cluster_state(self) -> Dict[str, Any]:
        """Get current cluster state."""
        with self._lock:
            return {
                'node_id': self.node_id,
                'is_leader': self.is_leader,
                'current_term': self.current_term,
                'cluster_size': len(self.cluster_nodes),
                'online_nodes': len([n for n in self.cluster_nodes.values() if n.is_online]),
                'log_entries': len(self.log_entries),
                'commit_index': self.commit_index,
                'last_applied': self.last_applied
            }


class CDNIntegration:
    """CDN integration for edge computing deployments."""
    
    def __init__(self, cdn_provider: str, edge_locations: List[str]):
        self.cdn_provider = cdn_provider
        self.edge_locations = edge_locations
        self.cache_config = {}
        self.purge_queue = deque()
        self._stats = defaultdict(int)
    
    def configure_caching(self, path_pattern: str, cache_config: Dict[str, Any]):
        """Configure CDN caching for path pattern."""
        self.cache_config[path_pattern] = cache_config
        logger.info(f"Configured CDN caching for {path_pattern}: {cache_config}")
    
    def get_cache_headers(self, request_path: str) -> Dict[str, str]:
        """Get appropriate cache headers for request path."""
        headers = {}
        
        for pattern, config in self.cache_config.items():
            if self._matches_pattern(request_path, pattern):
                if 'max_age' in config:
                    headers['Cache-Control'] = f"public, max-age={config['max_age']}"
                if 'etag' in config and config['etag']:
                    headers['ETag'] = f'"{hashlib.md5(request_path.encode()).hexdigest()}"'
                if 'vary' in config:
                    headers['Vary'] = config['vary']
                break
        
        return headers
    
    def should_cache_response(self, request_path: str, response_status: int) -> bool:
        """Determine if response should be cached."""
        if response_status != 200:
            return False
        
        for pattern, config in self.cache_config.items():
            if self._matches_pattern(request_path, pattern):
                return config.get('enabled', True)
        
        return False
    
    def queue_purge(self, path_pattern: str, tags: List[str] = None):
        """Queue CDN cache purge for path pattern."""
        purge_request = {
            'path_pattern': path_pattern,
            'tags': tags or [],
            'timestamp': time.time(),
            'node_id': getattr(self, 'node_id', 'unknown')
        }
        
        self.purge_queue.append(purge_request)
        self._stats['purge_requests'] += 1
        logger.info(f"Queued CDN purge for {path_pattern}")
    
    def process_purge_queue(self) -> int:
        """Process queued CDN purge requests."""
        processed = 0
        
        while self.purge_queue:
            try:
                purge_request = self.purge_queue.popleft()
                success = self._execute_purge(purge_request)
                
                if success:
                    processed += 1
                    self._stats['purge_success'] += 1
                else:
                    self._stats['purge_failures'] += 1
                
            except Exception as e:
                logger.error(f"Failed to process purge request: {e}")
                self._stats['purge_failures'] += 1
        
        return processed
    
    def _execute_purge(self, purge_request: Dict[str, Any]) -> bool:
        """Execute CDN cache purge request."""
        # In production, this would make API calls to CDN provider
        logger.info(f"Executing CDN purge: {purge_request['path_pattern']}")
        return True
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches pattern."""
        import re
        # Convert simple glob pattern to regex
        pattern = pattern.replace('*', '.*').replace('?', '.')
        return bool(re.match(f"^{pattern}$", path))
    
    def get_cdn_stats(self) -> Dict[str, Any]:
        """Get CDN integration statistics."""
        return {
            'cdn_provider': self.cdn_provider,
            'edge_locations': len(self.edge_locations),
            'cache_configs': len(self.cache_config),
            'pending_purges': len(self.purge_queue),
            'stats': dict(self._stats)
        }


class EdgeShield:
    """Main edge-optimized security shield."""
    
    def __init__(self, 
                 node_id: str,
                 location_type: EdgeLocation,
                 resource_level: EdgeResourceLevel,
                 capabilities: List[EdgeCapability],
                 cloud_endpoint: Optional[str] = None):
        
        self.node_id = node_id
        self.location_type = location_type
        self.resource_level = resource_level
        self.capabilities = capabilities
        self.cloud_endpoint = cloud_endpoint
        
        # Initialize components based on capabilities
        self.optimizer = EdgeOptimizer(resource_level)
        self.cache = EdgeCache(
            max_size_bytes=self.optimizer.get_cache_limit(),
            enable_compression=self.optimizer.should_compress()
        ) if EdgeCapability.LOCAL_CACHE in capabilities else None
        
        self.auth_cache = OfflineAuthCache() if EdgeCapability.OFFLINE_AUTH in capabilities else None
        
        self.policy_sync = PolicySynchronizer(
            node_id=node_id,
            cloud_endpoint=cloud_endpoint or "",
            sync_mode=SyncMode.PERIODIC
        ) if EdgeCapability.POLICY_SYNC in capabilities else None
        
        self.consensus = DistributedConsensus(
            node_id=node_id
        ) if EdgeCapability.CONSENSUS in capabilities else None
        
        self.cdn_integration = CDNIntegration(
            cdn_provider="generic",
            edge_locations=[f"{location_type.value}_{node_id}"]
        ) if EdgeCapability.CDN_INTEGRATION in capabilities else None
        
        # Performance tracking
        self.request_count = 0
        self.total_latency = 0.0
        self._stats = defaultdict(int)
        self._lock = RLock()
        
        # Start background tasks
        self._start_background_tasks()
        
        logger.info(f"Initialized EdgeShield {node_id} with capabilities: {[c.value for c in capabilities]}")
    
    def _start_background_tasks(self):
        """Start background maintenance tasks."""
        def maintenance_worker():
            while True:
                try:
                    self._run_maintenance()
                    time.sleep(30)  # Run every 30 seconds
                except Exception as e:
                    logger.error(f"Maintenance task error: {e}")
        
        maintenance_thread = Thread(target=maintenance_worker, daemon=True)
        maintenance_thread.start()
    
    def _run_maintenance(self):
        """Run periodic maintenance tasks."""
        # Clean up expired cache entries
        if self.cache:
            self.cache.cleanup_expired()
        
        # Clean up expired auth entries
        if self.auth_cache:
            expired_count = self.auth_cache.cleanup_expired()
            if expired_count > 0:
                logger.debug(f"Cleaned up {expired_count} expired auth entries")
        
        # Process CDN purge queue
        if self.cdn_integration:
            purged_count = self.cdn_integration.process_purge_queue()
            if purged_count > 0:
                logger.debug(f"Processed {purged_count} CDN purge requests")
        
        # Memory management
        memory_usage = self.optimizer.memory_monitor.get_current_usage()
        if self.optimizer.should_garbage_collect(memory_usage):
            self._perform_garbage_collection()
    
    def _perform_garbage_collection(self):
        """Perform memory optimization and garbage collection."""
        initial_usage = self.optimizer.memory_monitor.get_current_usage()
        
        # Clear least recently used cache entries
        if self.cache:
            current_size = self.cache.get_stats()['size_bytes']
            target_size = self.optimizer.get_cache_limit() * 0.7  # Reduce to 70% of limit
            
            while current_size > target_size and self.cache._cache:
                self.cache._evict_lru()
                current_size = self.cache.get_stats()['size_bytes']
        
        # Run Python garbage collection
        import gc
        collected = gc.collect()
        
        final_usage = self.optimizer.memory_monitor.get_current_usage()
        logger.info(f"GC: {initial_usage:.1%} -> {final_usage:.1%} memory usage, {collected} objects collected")
    
    async def process_request(self, request: Request) -> Optional[Response]:
        """Process incoming request through edge shield."""
        start_time = time.time()
        
        try:
            with self._lock:
                self.request_count += 1
                request_id = f"req_{self.request_count}"
            
            # Check cache first if enabled
            if self.cache and request.method == "GET":
                cache_key = f"{request.method}:{request.url.path}"
                cached_response = self.cache.get(cache_key)
                if cached_response:
                    self._update_stats('cache_hit')
                    return cached_response
                self._update_stats('cache_miss')
            
            # Offline authentication if enabled
            if self.auth_cache:
                auth_header = request.headers.get('authorization')
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                    auth_info = self.auth_cache.verify_auth(token)
                    if not auth_info:
                        self._update_stats('auth_failed')
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Authentication required"}
                        )
                    self._update_stats('auth_success')
            
            # Apply policies from sync manager
            if self.policy_sync:
                policies = self.policy_sync.get_all_policies()
                for policy in policies:
                    if self._policy_matches_request(policy, request):
                        response = self._apply_policy(policy, request)
                        if response:
                            self._update_stats('policy_applied')
                            return response
            
            # CDN caching headers
            if self.cdn_integration and request.method == "GET":
                cache_headers = self.cdn_integration.get_cache_headers(request.url.path)
                if cache_headers:
                    # Would modify response headers in production
                    self._update_stats('cdn_headers_added')
            
            # Allow request to continue
            return None
        
        finally:
            # Update performance metrics
            latency = (time.time() - start_time) * 1000  # milliseconds
            with self._lock:
                self.total_latency += latency
            self._update_stats('requests_processed')
    
    def _policy_matches_request(self, policy: EdgePolicy, request: Request) -> bool:
        """Check if policy matches current request."""
        conditions = policy.conditions
        
        # Path pattern matching
        if 'path_pattern' in conditions:
            pattern = conditions['path_pattern']
            if not self._matches_pattern(request.url.path, pattern):
                return False
        
        # Method matching
        if 'methods' in conditions:
            if request.method.lower() not in [m.lower() for m in conditions['methods']]:
                return False
        
        # Header matching
        if 'required_headers' in conditions:
            for header_name in conditions['required_headers']:
                if header_name.lower() not in [h.lower() for h in request.headers.keys()]:
                    return False
        
        return True
    
    def _apply_policy(self, policy: EdgePolicy, request: Request) -> Optional[Response]:
        """Apply policy actions to request."""
        actions = policy.actions
        
        # Rate limiting
        if 'rate_limit' in actions:
            rate_config = actions['rate_limit']
            if self._check_rate_limit(request, rate_config):
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded"}
                )
        
        # Block request
        if 'block' in actions and actions['block']:
            return JSONResponse(
                status_code=403,
                content={"error": "Request blocked by policy"}
            )
        
        # Redirect
        if 'redirect' in actions:
            redirect_url = actions['redirect']
            return JSONResponse(
                status_code=302,
                headers={"Location": redirect_url},
                content={"redirect": redirect_url}
            )
        
        return None
    
    def _check_rate_limit(self, request: Request, rate_config: Dict[str, Any]) -> bool:
        """Check if request exceeds rate limit."""
        # Simple rate limiting implementation
        client_ip = getattr(request.client, 'host', 'unknown')
        requests_limit = rate_config.get('requests', 100)
        window_seconds = rate_config.get('window', 60)
        
        # Use cache for rate limiting if available
        if self.cache:
            rate_key = f"rate_limit:{client_ip}"
            current_requests = self.cache.get(rate_key) or 0
            
            if current_requests >= requests_limit:
                return True  # Rate limit exceeded
            
            self.cache.put(rate_key, current_requests + 1, ttl_seconds=window_seconds)
        
        return False
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches pattern."""
        import re
        pattern = pattern.replace('*', '.*').replace('?', '.')
        return bool(re.match(f"^{pattern}$", path))
    
    def _update_stats(self, stat_name: str, increment: int = 1):
        """Update internal statistics."""
        with self._lock:
            self._stats[stat_name] += increment
    
    def get_shield_stats(self) -> Dict[str, Any]:
        """Get comprehensive shield statistics."""
        with self._lock:
            avg_latency = self.total_latency / self.request_count if self.request_count > 0 else 0
            
            stats = {
                'node_id': self.node_id,
                'location_type': self.location_type.value,
                'resource_level': self.resource_level.value,
                'capabilities': [cap.value for cap in self.capabilities],
                'performance': {
                    'requests_processed': self.request_count,
                    'avg_latency_ms': round(avg_latency, 2),
                    'total_latency_ms': round(self.total_latency, 2)
                },
                'stats': dict(self._stats)
            }
            
            # Add component stats
            if self.cache:
                stats['cache'] = self.cache.get_stats()
            
            if self.auth_cache:
                stats['auth_cache'] = self.auth_cache.get_stats()
            
            if self.policy_sync:
                stats['policy_sync'] = asdict(self.policy_sync.get_sync_state())
            
            if self.consensus:
                stats['consensus'] = self.consensus.get_cluster_state()
            
            if self.cdn_integration:
                stats['cdn'] = self.cdn_integration.get_cdn_stats()
            
            # Memory and CPU stats
            stats['resources'] = {
                'memory_usage': self.optimizer.memory_monitor.get_current_usage(),
                'memory_trend': self.optimizer.memory_monitor.get_usage_trend(),
                'cpu_usage': self.optimizer.cpu_monitor.get_current_usage()
            }
            
            return stats


# Convenience functions and factories

def create_edge_shield(node_id: str,
                      location_type: EdgeLocation = EdgeLocation.CDN_EDGE,
                      resource_level: EdgeResourceLevel = EdgeResourceLevel.MEDIUM,
                      capabilities: List[EdgeCapability] = None,
                      cloud_endpoint: str = None) -> EdgeShield:
    """Create optimally configured edge shield."""
    if capabilities is None:
        # Default capabilities based on resource level
        if resource_level in [EdgeResourceLevel.ULTRA_LOW, EdgeResourceLevel.LOW]:
            capabilities = [
                EdgeCapability.LOCAL_CACHE,
                EdgeCapability.OFFLINE_AUTH,
                EdgeCapability.COMPRESSION
            ]
        elif resource_level == EdgeResourceLevel.MEDIUM:
            capabilities = [
                EdgeCapability.LOCAL_CACHE,
                EdgeCapability.OFFLINE_AUTH,
                EdgeCapability.POLICY_SYNC,
                EdgeCapability.CDN_INTEGRATION,
                EdgeCapability.COMPRESSION
            ]
        else:  # HIGH or UNLIMITED
            capabilities = [
                EdgeCapability.LOCAL_CACHE,
                EdgeCapability.OFFLINE_AUTH,
                EdgeCapability.POLICY_SYNC,
                EdgeCapability.CDN_INTEGRATION,
                EdgeCapability.DISTRIBUTED_STATE,
                EdgeCapability.CONSENSUS,
                EdgeCapability.COMPRESSION,
                EdgeCapability.ENCRYPTION,
                EdgeCapability.ANALYTICS,
                EdgeCapability.MONITORING
            ]
    
    return EdgeShield(
        node_id=node_id,
        location_type=location_type,
        resource_level=resource_level,
        capabilities=capabilities,
        cloud_endpoint=cloud_endpoint
    )


def edge_optimized(resource_level: EdgeResourceLevel = EdgeResourceLevel.MEDIUM):
    """Decorator for edge-optimized endpoint protection."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                request = kwargs.get('request')
            
            if not request:
                raise ValueError("Request object not found for edge optimization")
            
            # Create lightweight edge shield for this request
            node_id = f"edge_{hash(request.url.path) % 10000}"
            edge_shield = create_edge_shield(
                node_id=node_id,
                resource_level=resource_level
            )
            
            # Process request through edge shield
            shield_response = await edge_shield.process_request(request)
            if shield_response:
                return shield_response
            
            # Continue with original function
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def ultra_lightweight(func):
    """Ultra-lightweight edge protection decorator."""
    return edge_optimized(EdgeResourceLevel.ULTRA_LOW)(func)


def iot_gateway_protection(func):
    """IoT gateway optimized protection decorator."""
    def decorator_wrapper(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if request:
                # Create IoT-optimized shield
                shield = create_edge_shield(
                    node_id=f"iot_{hash(str(request.client.host)) % 1000}",
                    location_type=EdgeLocation.IOT_GATEWAY,
                    resource_level=EdgeResourceLevel.LOW,
                    capabilities=[
                        EdgeCapability.LOCAL_CACHE,
                        EdgeCapability.OFFLINE_AUTH,
                        EdgeCapability.COMPRESSION
                    ]
                )
                
                response = await shield.process_request(request)
                if response:
                    return response
            
            return await func(*args, **kwargs)
        
        return wrapper
    
    return decorator_wrapper(func)


class EdgeMiddleware:
    """FastAPI middleware for edge computing optimization."""
    
    def __init__(self, 
                 app,
                 node_id: str,
                 location_type: EdgeLocation = EdgeLocation.CDN_EDGE,
                 resource_level: EdgeResourceLevel = EdgeResourceLevel.MEDIUM,
                 capabilities: List[EdgeCapability] = None,
                 cloud_endpoint: str = None,
                 excluded_paths: List[str] = None):
        
        self.app = app
        self.edge_shield = create_edge_shield(
            node_id=node_id,
            location_type=location_type,
            resource_level=resource_level,
            capabilities=capabilities,
            cloud_endpoint=cloud_endpoint
        )
        self.excluded_paths = excluded_paths or ['/health', '/metrics', '/docs']
    
    async def __call__(self, scope, receive, send):
        """ASGI middleware entry point."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # Skip edge processing for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            await self.app(scope, receive, send)
            return
        
        # Process through edge shield
        try:
            response = await self.edge_shield.process_request(request)
            if response:
                await response(scope, receive, send)
                return
        except Exception as e:
            logger.error(f"Edge middleware error: {e}")
            # Continue with request on error
        
        # Continue with original app
        await self.app(scope, receive, send)


# Export all public classes and functions
__all__ = [
    # Enums
    'EdgeLocation',
    'EdgeCapability',
    'SyncMode',
    'EdgeResourceLevel',
    'ConsensusAlgorithm',
    
    # Data classes
    'EdgeNode',
    'EdgePolicy',
    'EdgeCacheEntry',
    'EdgeSyncState',
    
    # Core classes
    'EdgeOptimizer',
    'MemoryMonitor',
    'CPUMonitor',
    'EdgeCache',
    'OfflineAuthCache',
    'PolicySynchronizer',
    'DistributedConsensus',
    'CDNIntegration',
    'EdgeShield',
    'EdgeMiddleware',
    
    # Convenience functions
    'create_edge_shield',
    'edge_optimized',
    'ultra_lightweight',
    'iot_gateway_protection',
]