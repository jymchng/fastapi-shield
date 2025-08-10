"""Request Replay shield for FastAPI Shield.

This module provides comprehensive request replay attack protection functionality,
including nonce-based and timestamp-based validation, configurable replay windows,
distributed storage support, and performance optimization.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple
from urllib.parse import urlparse, parse_qs

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from fastapi_shield.shield import Shield


class ReplayProtectionStrategy(str, Enum):
    """Replay protection strategy enumeration."""
    NONCE_ONLY = "nonce_only"
    TIMESTAMP_ONLY = "timestamp_only"
    NONCE_AND_TIMESTAMP = "nonce_and_timestamp"
    SIGNATURE_BASED = "signature_based"
    COMBINED = "combined"


class NonceFormat(str, Enum):
    """Nonce format enumeration."""
    UUID = "uuid"
    RANDOM_HEX = "random_hex"
    RANDOM_BASE64 = "random_base64"
    CUSTOM = "custom"


class TimestampFormat(str, Enum):
    """Timestamp format enumeration."""
    UNIX_TIMESTAMP = "unix_timestamp"
    ISO_8601 = "iso_8601"
    CUSTOM = "custom"


class ReplayDetectionResult(str, Enum):
    """Replay detection result enumeration."""
    ALLOWED = "allowed"
    REPLAY_DETECTED = "replay_detected"
    INVALID_NONCE = "invalid_nonce"
    INVALID_TIMESTAMP = "invalid_timestamp"
    EXPIRED_TIMESTAMP = "expired_timestamp"
    MISSING_NONCE = "missing_nonce"
    MISSING_TIMESTAMP = "missing_timestamp"
    INVALID_SIGNATURE = "invalid_signature"
    STORAGE_ERROR = "storage_error"


@dataclass
class ReplayProtectionResult:
    """Result of replay protection check."""
    allowed: bool
    result: ReplayDetectionResult
    nonce: Optional[str] = None
    timestamp: Optional[float] = None
    signature: Optional[str] = None
    message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'allowed': self.allowed,
            'result': self.result.value,
            'nonce': self.nonce,
            'timestamp': self.timestamp,
            'signature': self.signature,
            'message': self.message,
            'details': self.details,
            'metadata': self.metadata
        }


class NonceStorage(ABC):
    """Abstract base class for nonce storage implementations."""
    
    @abstractmethod
    async def store_nonce(self, nonce: str, ttl_seconds: float = None) -> bool:
        """Store a nonce with optional TTL."""
        pass
    
    @abstractmethod
    async def has_nonce(self, nonce: str) -> bool:
        """Check if nonce exists."""
        pass
    
    @abstractmethod
    async def remove_nonce(self, nonce: str) -> bool:
        """Remove a nonce."""
        pass
    
    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Clean up expired nonces."""
        pass
    
    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        pass


class MemoryNonceStorage(NonceStorage):
    """In-memory nonce storage implementation."""
    
    def __init__(self, max_nonces: int = 100000):
        self.max_nonces = max_nonces
        self._nonces: Dict[str, float] = {}  # nonce -> expiry_time
        self._access_times: deque = deque()  # (access_time, nonce) for LRU
        self._lock = asyncio.Lock()
        self._logger = logging.getLogger(__name__)
    
    async def store_nonce(self, nonce: str, ttl_seconds: float = None) -> bool:
        """Store a nonce with optional TTL."""
        async with self._lock:
            try:
                current_time = time.time()
                expiry_time = current_time + (ttl_seconds or 3600)  # 1 hour default
                
                # Clean up expired nonces if needed
                await self._cleanup_expired_internal()
                
                # Enforce size limit using LRU
                if len(self._nonces) >= self.max_nonces:
                    await self._evict_oldest()
                
                self._nonces[nonce] = expiry_time
                self._access_times.append((current_time, nonce))
                
                return True
            except Exception as e:
                self._logger.error(f"Failed to store nonce: {e}")
                return False
    
    async def has_nonce(self, nonce: str) -> bool:
        """Check if nonce exists and is not expired."""
        async with self._lock:
            if nonce not in self._nonces:
                return False
            
            current_time = time.time()
            expiry_time = self._nonces[nonce]
            
            if current_time > expiry_time:
                # Expired, remove it
                del self._nonces[nonce]
                return False
            
            return True
    
    async def remove_nonce(self, nonce: str) -> bool:
        """Remove a nonce."""
        async with self._lock:
            if nonce in self._nonces:
                del self._nonces[nonce]
                return True
            return False
    
    async def cleanup_expired(self) -> int:
        """Clean up expired nonces."""
        async with self._lock:
            return await self._cleanup_expired_internal()
    
    async def _cleanup_expired_internal(self) -> int:
        """Internal cleanup method (assumes lock is held)."""
        current_time = time.time()
        expired_nonces = []
        
        for nonce, expiry_time in self._nonces.items():
            if current_time > expiry_time:
                expired_nonces.append(nonce)
        
        for nonce in expired_nonces:
            del self._nonces[nonce]
        
        # Clean access times
        while self._access_times and self._access_times[0][1] in expired_nonces:
            self._access_times.popleft()
        
        return len(expired_nonces)
    
    async def _evict_oldest(self):
        """Evict oldest nonces when at capacity."""
        evict_count = max(1, self.max_nonces // 10)  # Evict 10% when full
        
        for _ in range(evict_count):
            if not self._access_times:
                break
            
            _, oldest_nonce = self._access_times.popleft()
            self._nonces.pop(oldest_nonce, None)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        async with self._lock:
            current_time = time.time()
            expired_count = sum(1 for exp_time in self._nonces.values() if current_time > exp_time)
            
            return {
                'total_nonces': len(self._nonces),
                'expired_nonces': expired_count,
                'active_nonces': len(self._nonces) - expired_count,
                'max_nonces': self.max_nonces,
                'storage_type': 'memory'
            }


class RedisNonceStorage(NonceStorage):
    """Redis-based nonce storage implementation."""
    
    def __init__(
        self,
        redis_client=None,
        redis_url: str = "redis://localhost:6379",
        key_prefix: str = "fastapi_shield:nonce:",
        pool_size: int = 10
    ):
        self.key_prefix = key_prefix
        self._redis_client = redis_client
        self._redis_url = redis_url
        self._pool_size = pool_size
        self._logger = logging.getLogger(__name__)
        
        # Lazy initialization
        self._initialized = False
        self._init_lock = asyncio.Lock()
    
    async def _ensure_initialized(self):
        """Ensure Redis client is initialized."""
        if self._initialized:
            return
        
        async with self._init_lock:
            if self._initialized:
                return
            
            if self._redis_client is None:
                try:
                    import redis.asyncio as aioredis
                    
                    # Parse Redis URL
                    parsed = urlparse(self._redis_url)
                    
                    self._redis_client = aioredis.from_url(
                        self._redis_url,
                        max_connections=self._pool_size,
                        decode_responses=True
                    )
                    
                    # Test connection
                    await self._redis_client.ping()
                    self._initialized = True
                    
                except ImportError:
                    raise ImportError("redis package is required for RedisNonceStorage")
                except Exception as e:
                    self._logger.error(f"Failed to initialize Redis client: {e}")
                    raise
            else:
                self._initialized = True
    
    def _get_key(self, nonce: str) -> str:
        """Get Redis key for nonce."""
        return f"{self.key_prefix}{nonce}"
    
    async def store_nonce(self, nonce: str, ttl_seconds: float = None) -> bool:
        """Store a nonce with optional TTL."""
        try:
            await self._ensure_initialized()
            
            key = self._get_key(nonce)
            current_time = time.time()
            
            # Store with expiration
            ttl = int(ttl_seconds or 3600)  # 1 hour default
            
            result = await self._redis_client.setex(
                key, ttl, json.dumps({
                    'stored_at': current_time,
                    'ttl': ttl
                })
            )
            
            return bool(result)
            
        except Exception as e:
            self._logger.error(f"Failed to store nonce in Redis: {e}")
            return False
    
    async def has_nonce(self, nonce: str) -> bool:
        """Check if nonce exists."""
        try:
            await self._ensure_initialized()
            
            key = self._get_key(nonce)
            result = await self._redis_client.exists(key)
            
            return bool(result)
            
        except Exception as e:
            self._logger.error(f"Failed to check nonce in Redis: {e}")
            return False
    
    async def remove_nonce(self, nonce: str) -> bool:
        """Remove a nonce."""
        try:
            await self._ensure_initialized()
            
            key = self._get_key(nonce)
            result = await self._redis_client.delete(key)
            
            return bool(result)
            
        except Exception as e:
            self._logger.error(f"Failed to remove nonce from Redis: {e}")
            return False
    
    async def cleanup_expired(self) -> int:
        """Clean up expired nonces (Redis handles this automatically)."""
        # Redis automatically expires keys, so we don't need to do anything
        return 0
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        try:
            await self._ensure_initialized()
            
            # Count keys with our prefix
            pattern = f"{self.key_prefix}*"
            keys = await self._redis_client.keys(pattern)
            
            # Get Redis info
            info = await self._redis_client.info('memory')
            
            return {
                'total_nonces': len(keys),
                'storage_type': 'redis',
                'redis_memory_usage': info.get('used_memory_human', 'unknown'),
                'redis_connected_clients': info.get('connected_clients', 0)
            }
            
        except Exception as e:
            self._logger.error(f"Failed to get Redis stats: {e}")
            return {'storage_type': 'redis', 'error': str(e)}


class NonceGenerator:
    """Nonce generation utility."""
    
    def __init__(self, format_type: NonceFormat = NonceFormat.UUID):
        self.format_type = format_type
        self._logger = logging.getLogger(__name__)
    
    def generate(self, custom_generator: Callable[[], str] = None) -> str:
        """Generate a nonce based on the configured format."""
        try:
            if self.format_type == NonceFormat.UUID:
                return str(uuid.uuid4())
            elif self.format_type == NonceFormat.RANDOM_HEX:
                return secrets.token_hex(16)  # 32 character hex string
            elif self.format_type == NonceFormat.RANDOM_BASE64:
                return secrets.token_urlsafe(16)  # URL-safe base64
            elif self.format_type == NonceFormat.CUSTOM and custom_generator:
                return custom_generator()
            else:
                # Default to UUID
                return str(uuid.uuid4())
        
        except Exception as e:
            self._logger.error(f"Failed to generate nonce: {e}")
            # Fallback to UUID
            return str(uuid.uuid4())


class TimestampValidator:
    """Timestamp validation utility."""
    
    def __init__(
        self,
        format_type: TimestampFormat = TimestampFormat.UNIX_TIMESTAMP,
        clock_skew_tolerance: float = 300.0  # 5 minutes
    ):
        self.format_type = format_type
        self.clock_skew_tolerance = clock_skew_tolerance
        self._logger = logging.getLogger(__name__)
    
    def parse_timestamp(self, timestamp_str: str, custom_parser: Callable[[str], float] = None) -> Optional[float]:
        """Parse timestamp string to Unix timestamp."""
        try:
            if self.format_type == TimestampFormat.UNIX_TIMESTAMP:
                return float(timestamp_str)
            elif self.format_type == TimestampFormat.ISO_8601:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                return dt.timestamp()
            elif self.format_type == TimestampFormat.CUSTOM and custom_parser:
                return custom_parser(timestamp_str)
            else:
                # Try to parse as Unix timestamp
                return float(timestamp_str)
        
        except (ValueError, TypeError) as e:
            self._logger.error(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return None
    
    def is_timestamp_valid(self, timestamp: float, replay_window: float) -> Tuple[bool, str]:
        """Validate timestamp against current time and replay window."""
        current_time = time.time()
        
        # Check if timestamp is too old
        if current_time - timestamp > replay_window:
            return False, f"Timestamp too old: {timestamp} (current: {current_time}, window: {replay_window}s)"
        
        # Check if timestamp is too far in the future (clock skew)
        if timestamp - current_time > self.clock_skew_tolerance:
            return False, f"Timestamp too far in future: {timestamp} (current: {current_time}, tolerance: {self.clock_skew_tolerance}s)"
        
        return True, "Timestamp valid"


class SignatureValidator:
    """Request signature validation utility."""
    
    def __init__(self, secret_key: str, algorithm: str = "sha256"):
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self.algorithm = algorithm
        self._logger = logging.getLogger(__name__)
    
    def generate_signature(
        self,
        method: str,
        path: str,
        nonce: str,
        timestamp: str,
        body: str = "",
        query_params: Dict[str, str] = None
    ) -> str:
        """Generate request signature."""
        try:
            # Create canonical string
            canonical_parts = [
                method.upper(),
                path,
                nonce,
                timestamp
            ]
            
            # Add sorted query parameters
            if query_params:
                sorted_params = sorted(query_params.items())
                query_string = "&".join(f"{k}={v}" for k, v in sorted_params)
                canonical_parts.append(query_string)
            
            # Add body hash
            if body:
                body_hash = hashlib.sha256(body.encode()).hexdigest()
                canonical_parts.append(body_hash)
            
            canonical_string = "\n".join(canonical_parts)
            
            # Generate HMAC signature
            signature = hmac.new(
                self.secret_key,
                canonical_string.encode(),
                getattr(hashlib, self.algorithm)
            ).hexdigest()
            
            return signature
        
        except Exception as e:
            self._logger.error(f"Failed to generate signature: {e}")
            raise
    
    def verify_signature(
        self,
        provided_signature: str,
        method: str,
        path: str,
        nonce: str,
        timestamp: str,
        body: str = "",
        query_params: Dict[str, str] = None
    ) -> bool:
        """Verify request signature."""
        try:
            expected_signature = self.generate_signature(
                method, path, nonce, timestamp, body, query_params
            )
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(provided_signature, expected_signature)
        
        except Exception as e:
            self._logger.error(f"Failed to verify signature: {e}")
            return False


@dataclass
class ReplayProtectionConfig:
    """Configuration for request replay protection."""
    
    strategy: ReplayProtectionStrategy = ReplayProtectionStrategy.NONCE_AND_TIMESTAMP
    replay_window_seconds: float = 300.0  # 5 minutes
    nonce_storage: NonceStorage = None
    nonce_format: NonceFormat = NonceFormat.UUID
    timestamp_format: TimestampFormat = TimestampFormat.UNIX_TIMESTAMP
    clock_skew_tolerance: float = 300.0  # 5 minutes
    
    # Header/query parameter names
    nonce_header: str = "X-Request-Nonce"
    timestamp_header: str = "X-Request-Timestamp"
    signature_header: str = "X-Request-Signature"
    nonce_query_param: str = "nonce"
    timestamp_query_param: str = "timestamp"
    signature_query_param: str = "signature"
    
    # Signature configuration
    signature_secret: Optional[str] = None
    signature_algorithm: str = "sha256"
    
    # Extraction preferences
    prefer_headers: bool = True  # Prefer headers over query params
    require_signature: bool = False
    
    # Performance settings
    enable_async_storage: bool = True
    storage_timeout_seconds: float = 5.0
    auto_cleanup_interval: float = 3600.0  # 1 hour
    
    # Custom extractors and validators
    custom_nonce_extractor: Optional[Callable[[Request], str]] = None
    custom_timestamp_extractor: Optional[Callable[[Request], str]] = None
    custom_signature_extractor: Optional[Callable[[Request], str]] = None
    custom_nonce_generator: Optional[Callable[[], str]] = None
    custom_timestamp_parser: Optional[Callable[[str], float]] = None
    
    # Logging and monitoring
    log_replay_attempts: bool = True
    log_invalid_requests: bool = True
    include_client_info: bool = True
    
    # Error handling
    block_on_storage_error: bool = False
    default_allow_on_error: bool = False
    
    metadata: Dict[str, Any] = field(default_factory=dict)


class RequestReplayShield(Shield):
    """Request replay protection shield."""
    
    def __init__(self, config: ReplayProtectionConfig):
        self.config = config
        self._setup_components()
        self._cleanup_task = None
        self._logger = logging.getLogger(__name__)
        
        super().__init__(self._shield_function)
    
    def _setup_components(self):
        """Setup internal components."""
        # Setup storage
        if self.config.nonce_storage is None:
            self.config.nonce_storage = MemoryNonceStorage()
        
        # Setup generators and validators
        self._nonce_generator = NonceGenerator(self.config.nonce_format)
        self._timestamp_validator = TimestampValidator(
            self.config.timestamp_format,
            self.config.clock_skew_tolerance
        )
        
        # Setup signature validator if needed
        self._signature_validator = None
        if (self.config.strategy in [ReplayProtectionStrategy.SIGNATURE_BASED, ReplayProtectionStrategy.COMBINED] or
            self.config.require_signature):
            if not self.config.signature_secret:
                raise ValueError("Signature secret is required for signature-based protection")
            self._signature_validator = SignatureValidator(
                self.config.signature_secret,
                self.config.signature_algorithm
            )
        
        # Start cleanup task
        if self.config.auto_cleanup_interval > 0:
            self._start_cleanup_task()
    
    def _start_cleanup_task(self):
        """Start automatic cleanup task."""
        async def cleanup_loop():
            while True:
                try:
                    await asyncio.sleep(self.config.auto_cleanup_interval)
                    await self.config.nonce_storage.cleanup_expired()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self._logger.error(f"Cleanup task error: {e}")
        
        try:
            loop = asyncio.get_event_loop()
            self._cleanup_task = loop.create_task(cleanup_loop())
        except RuntimeError:
            # No event loop running, cleanup will be manual
            pass
    
    def stop_cleanup_task(self):
        """Stop automatic cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            self._cleanup_task = None
    
    def __del__(self):
        """Cleanup when shield is destroyed."""
        if hasattr(self, '_cleanup_task'):
            self.stop_cleanup_task()
    
    def generate_nonce(self) -> str:
        """Generate a new nonce."""
        return self._nonce_generator.generate(self.config.custom_nonce_generator)
    
    async def _extract_nonce(self, request: Request) -> Optional[str]:
        """Extract nonce from request."""
        if self.config.custom_nonce_extractor:
            try:
                return self.config.custom_nonce_extractor(request)
            except Exception as e:
                self._logger.error(f"Custom nonce extractor failed: {e}")
        
        # Try headers first if preferred
        if self.config.prefer_headers:
            nonce = request.headers.get(self.config.nonce_header)
            if nonce:
                return nonce
            
            # Fallback to query params
            nonce = request.query_params.get(self.config.nonce_query_param)
            if nonce:
                return nonce
        else:
            # Try query params first
            nonce = request.query_params.get(self.config.nonce_query_param)
            if nonce:
                return nonce
            
            # Fallback to headers
            nonce = request.headers.get(self.config.nonce_header)
            if nonce:
                return nonce
        
        return None
    
    async def _extract_timestamp(self, request: Request) -> Optional[str]:
        """Extract timestamp from request."""
        if self.config.custom_timestamp_extractor:
            try:
                return self.config.custom_timestamp_extractor(request)
            except Exception as e:
                self._logger.error(f"Custom timestamp extractor failed: {e}")
        
        # Try headers first if preferred
        if self.config.prefer_headers:
            timestamp = request.headers.get(self.config.timestamp_header)
            if timestamp:
                return timestamp
            
            # Fallback to query params
            timestamp = request.query_params.get(self.config.timestamp_query_param)
            if timestamp:
                return timestamp
        else:
            # Try query params first
            timestamp = request.query_params.get(self.config.timestamp_query_param)
            if timestamp:
                return timestamp
            
            # Fallback to headers
            timestamp = request.headers.get(self.config.timestamp_header)
            if timestamp:
                return timestamp
        
        return None
    
    async def _extract_signature(self, request: Request) -> Optional[str]:
        """Extract signature from request."""
        if self.config.custom_signature_extractor:
            try:
                return self.config.custom_signature_extractor(request)
            except Exception as e:
                self._logger.error(f"Custom signature extractor failed: {e}")
        
        # Try headers first if preferred
        if self.config.prefer_headers:
            signature = request.headers.get(self.config.signature_header)
            if signature:
                return signature
            
            # Fallback to query params
            signature = request.query_params.get(self.config.signature_query_param)
            if signature:
                return signature
        else:
            # Try query params first
            signature = request.query_params.get(self.config.signature_query_param)
            if signature:
                return signature
            
            # Fallback to headers
            signature = request.headers.get(self.config.signature_header)
            if signature:
                return signature
        
        return None
    
    async def _get_request_body(self, request: Request) -> str:
        """Get request body for signature verification."""
        try:
            # Try to get cached body first
            if hasattr(request.state, 'fastapi_shield_body'):
                cached_body = request.state.fastapi_shield_body
                if isinstance(cached_body, str):
                    return cached_body
            
            # Read body (this can only be done once)
            body = await request.body()
            if isinstance(body, bytes):
                body_str = body.decode() if body else ""
            elif isinstance(body, str):
                body_str = body
            else:
                body_str = str(body) if body else ""
            
            # Cache for future use with unique attribute name
            request.state.fastapi_shield_body = body_str
            
            return body_str
        except Exception as e:
            self._logger.error(f"Failed to read request body: {e}")
            return ""
    
    async def _validate_and_store_nonce(self, nonce: str) -> Tuple[bool, str]:
        """Validate nonce format and storage atomically."""
        if not nonce or len(nonce.strip()) == 0:
            return False, "Empty nonce"
        
        # Basic format validation
        if self.config.nonce_format == NonceFormat.UUID:
            try:
                uuid.UUID(nonce)
            except ValueError:
                return False, "Invalid UUID format"
        
        # Atomic check and store to prevent race conditions
        try:
            if self.config.enable_async_storage:
                # Check if nonce was already used
                already_used = await asyncio.wait_for(
                    self.config.nonce_storage.has_nonce(nonce),
                    timeout=self.config.storage_timeout_seconds
                )
                
                if already_used:
                    return False, "Nonce already used (replay detected)"
                
                # Store nonce immediately
                stored = await asyncio.wait_for(
                    self.config.nonce_storage.store_nonce(nonce, self.config.replay_window_seconds),
                    timeout=self.config.storage_timeout_seconds
                )
            else:
                already_used = await self.config.nonce_storage.has_nonce(nonce)
                
                if already_used:
                    return False, "Nonce already used (replay detected)"
                
                stored = await self.config.nonce_storage.store_nonce(nonce, self.config.replay_window_seconds)
            
            if not stored:
                return False, "Failed to store nonce"
            
            return True, "Nonce validated and stored"
        
        except asyncio.TimeoutError:
            return False, "Storage timeout"
        except Exception as e:
            self._logger.error(f"Nonce validation error: {e}")
            return False, f"Storage error: {e}"
    
    async def _store_nonce(self, nonce: str) -> bool:
        """Store nonce to prevent replay."""
        try:
            if self.config.enable_async_storage:
                stored = await asyncio.wait_for(
                    self.config.nonce_storage.store_nonce(nonce, self.config.replay_window_seconds),
                    timeout=self.config.storage_timeout_seconds
                )
            else:
                stored = await self.config.nonce_storage.store_nonce(nonce, self.config.replay_window_seconds)
            
            return stored
        
        except asyncio.TimeoutError:
            self._logger.error("Nonce storage timeout")
            return False
        except Exception as e:
            self._logger.error(f"Nonce storage error: {e}")
            return False
    
    async def check_replay_protection(self, request: Request) -> ReplayProtectionResult:
        """Check request against replay protection."""
        result_details = {}
        metadata = {}
        
        # Add client info if enabled
        if self.config.include_client_info:
            client_info = {
                'client_ip': getattr(request.client, 'host', None) if request.client else None,
                'user_agent': request.headers.get('user-agent'),
                'method': request.method,
                'path': str(request.url.path)
            }
            metadata['client_info'] = client_info
        
        # Extract required components
        nonce = await self._extract_nonce(request)
        timestamp_str = await self._extract_timestamp(request)
        signature = await self._extract_signature(request)
        
        # Strategy-based validation
        if self.config.strategy == ReplayProtectionStrategy.NONCE_ONLY:
            return await self._validate_nonce_only(nonce, result_details, metadata)
        
        elif self.config.strategy == ReplayProtectionStrategy.TIMESTAMP_ONLY:
            return await self._validate_timestamp_only(timestamp_str, result_details, metadata)
        
        elif self.config.strategy == ReplayProtectionStrategy.NONCE_AND_TIMESTAMP:
            return await self._validate_nonce_and_timestamp(nonce, timestamp_str, result_details, metadata)
        
        elif self.config.strategy == ReplayProtectionStrategy.SIGNATURE_BASED:
            return await self._validate_signature_based(request, nonce, timestamp_str, signature, result_details, metadata)
        
        elif self.config.strategy == ReplayProtectionStrategy.COMBINED:
            return await self._validate_combined(request, nonce, timestamp_str, signature, result_details, metadata)
        
        else:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.INVALID_NONCE,
                message="Unknown protection strategy",
                details=result_details,
                metadata=metadata
            )
    
    async def _validate_nonce_only(self, nonce: str, details: Dict, metadata: Dict) -> ReplayProtectionResult:
        """Validate using nonce only."""
        if not nonce:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.MISSING_NONCE,
                message="Missing nonce",
                details=details,
                metadata=metadata
            )
        
        nonce_valid, nonce_message = await self._validate_and_store_nonce(nonce)
        if not nonce_valid:
            # Check if this is a storage error and should be handled specially
            if "Storage error" in nonce_message or "timeout" in nonce_message.lower():
                if self.config.default_allow_on_error:
                    # Allow the request despite storage error
                    return ReplayProtectionResult(
                        allowed=True,
                        result=ReplayDetectionResult.ALLOWED,
                        nonce=nonce,
                        message=f"Allowed due to storage error: {nonce_message}",
                        details=details,
                        metadata=metadata
                    )
                else:
                    result_type = ReplayDetectionResult.STORAGE_ERROR
            else:
                result_type = ReplayDetectionResult.REPLAY_DETECTED if "already used" in nonce_message else ReplayDetectionResult.INVALID_NONCE
            
            return ReplayProtectionResult(
                allowed=False,
                result=result_type,
                nonce=nonce,
                message=nonce_message,
                details=details,
                metadata=metadata
            )
        
        return ReplayProtectionResult(
            allowed=True,
            result=ReplayDetectionResult.ALLOWED,
            nonce=nonce,
            message="Nonce validation passed",
            details=details,
            metadata=metadata
        )
    
    async def _validate_timestamp_only(self, timestamp_str: str, details: Dict, metadata: Dict) -> ReplayProtectionResult:
        """Validate using timestamp only."""
        if not timestamp_str:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.MISSING_TIMESTAMP,
                message="Missing timestamp",
                details=details,
                metadata=metadata
            )
        
        timestamp = self._timestamp_validator.parse_timestamp(
            timestamp_str, self.config.custom_timestamp_parser
        )
        
        if timestamp is None:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.INVALID_TIMESTAMP,
                message="Invalid timestamp format",
                details=details,
                metadata=metadata
            )
        
        timestamp_valid, timestamp_message = self._timestamp_validator.is_timestamp_valid(
            timestamp, self.config.replay_window_seconds
        )
        
        if not timestamp_valid:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.EXPIRED_TIMESTAMP,
                timestamp=timestamp,
                message=timestamp_message,
                details=details,
                metadata=metadata
            )
        
        return ReplayProtectionResult(
            allowed=True,
            result=ReplayDetectionResult.ALLOWED,
            timestamp=timestamp,
            message="Timestamp validation passed",
            details=details,
            metadata=metadata
        )
    
    async def _validate_nonce_and_timestamp(self, nonce: str, timestamp_str: str, details: Dict, metadata: Dict) -> ReplayProtectionResult:
        """Validate using both nonce and timestamp."""
        # Check nonce
        nonce_result = await self._validate_nonce_only(nonce, details, metadata)
        if not nonce_result.allowed:
            return nonce_result
        
        # Check timestamp
        timestamp_result = await self._validate_timestamp_only(timestamp_str, details, metadata)
        if not timestamp_result.allowed:
            return timestamp_result
        
        return ReplayProtectionResult(
            allowed=True,
            result=ReplayDetectionResult.ALLOWED,
            nonce=nonce,
            timestamp=timestamp_result.timestamp,
            message="Nonce and timestamp validation passed",
            details=details,
            metadata=metadata
        )
    
    async def _validate_signature_based(self, request: Request, nonce: str, timestamp_str: str, signature: str, details: Dict, metadata: Dict) -> ReplayProtectionResult:
        """Validate using signature."""
        if not signature:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.INVALID_SIGNATURE,
                message="Missing signature",
                details=details,
                metadata=metadata
            )
        
        if not nonce or not timestamp_str:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.MISSING_NONCE if not nonce else ReplayDetectionResult.MISSING_TIMESTAMP,
                message="Missing nonce or timestamp for signature validation",
                details=details,
                metadata=metadata
            )
        
        # Validate timestamp first
        timestamp_result = await self._validate_timestamp_only(timestamp_str, details, metadata)
        if not timestamp_result.allowed:
            return timestamp_result
        
        # Get request body and query params for signature verification
        body = await self._get_request_body(request)
        query_params = dict(request.query_params)
        
        # Verify signature
        signature_valid = self._signature_validator.verify_signature(
            signature, request.method, str(request.url.path), nonce, timestamp_str, body, query_params
        )
        
        if not signature_valid:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.INVALID_SIGNATURE,
                nonce=nonce,
                timestamp=timestamp_result.timestamp,
                signature=signature,
                message="Invalid signature",
                details=details,
                metadata=metadata
            )
        
        # Validate and store nonce to prevent signature replay (but only basic validation, no replay check)
        if not nonce or len(nonce.strip()) == 0:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.INVALID_NONCE,
                message="Empty nonce",
                details=details,
                metadata=metadata
            )
        
        # Basic format validation
        if self.config.nonce_format == NonceFormat.UUID:
            try:
                uuid.UUID(nonce)
            except ValueError:
                return ReplayProtectionResult(
                    allowed=False,
                    result=ReplayDetectionResult.INVALID_NONCE,
                    message="Invalid UUID format",
                    details=details,
                    metadata=metadata
                )
        
        # Store nonce to prevent signature replay
        stored = await self._store_nonce(nonce)
        if not stored and self.config.block_on_storage_error:
            return ReplayProtectionResult(
                allowed=False,
                result=ReplayDetectionResult.STORAGE_ERROR,
                nonce=nonce,
                timestamp=timestamp_result.timestamp,
                signature=signature,
                message="Failed to store nonce",
                details=details,
                metadata=metadata
            )
        
        return ReplayProtectionResult(
            allowed=True,
            result=ReplayDetectionResult.ALLOWED,
            nonce=nonce,
            timestamp=timestamp_result.timestamp,
            signature=signature,
            message="Signature validation passed",
            details=details,
            metadata=metadata
        )
    
    async def _validate_combined(self, request: Request, nonce: str, timestamp_str: str, signature: str, details: Dict, metadata: Dict) -> ReplayProtectionResult:
        """Validate using all methods combined."""
        # Validate nonce and timestamp first
        nonce_timestamp_result = await self._validate_nonce_and_timestamp(nonce, timestamp_str, details, metadata)
        if not nonce_timestamp_result.allowed:
            return nonce_timestamp_result
        
        # If signature is required or provided, validate it
        if self.config.require_signature or signature:
            signature_result = await self._validate_signature_based(request, nonce, timestamp_str, signature, details, metadata)
            return signature_result
        
        return nonce_timestamp_result
    
    async def _shield_function(self, request: Request) -> Optional[Response]:
        """Main shield function for replay protection."""
        try:
            protection_result = await self.check_replay_protection(request)
            
            if protection_result.allowed:
                # Log successful validation if enabled
                if self.config.log_replay_attempts:
                    self._logger.info(f"Request allowed: {protection_result.message}")
                
                return None  # Allow request to proceed
            else:
                # Log replay attempt
                if self.config.log_replay_attempts:
                    self._logger.warning(f"Replay attack detected: {protection_result.message}")
                
                if self.config.log_invalid_requests:
                    self._logger.warning(f"Invalid request details: {protection_result.to_dict()}")
                
                # Return error response
                error_response = {
                    'error': 'Replay attack detected',
                    'message': protection_result.message,
                    'result': protection_result.result.value
                }
                
                # Add debug info in development
                if self.config.metadata.get('include_debug_info', False):
                    error_response['debug'] = protection_result.to_dict()
                
                return JSONResponse(
                    content=error_response,
                    status_code=status.HTTP_400_BAD_REQUEST
                )
        
        except Exception as e:
            self._logger.error(f"Replay protection error: {e}")
            
            # Handle errors based on configuration
            if self.config.default_allow_on_error:
                self._logger.info("Allowing request due to error and default_allow_on_error=True")
                return None
            else:
                return JSONResponse(
                    content={'error': 'Replay protection service error'},
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
    
    async def get_storage_stats(self) -> Dict[str, Any]:
        """Get nonce storage statistics."""
        return await self.config.nonce_storage.get_stats()
    
    async def cleanup_expired_nonces(self) -> int:
        """Manually trigger cleanup of expired nonces."""
        return await self.config.nonce_storage.cleanup_expired()


# Convenience functions for creating replay protection shields

def nonce_only_replay_shield(
    nonce_storage: NonceStorage = None,
    replay_window_seconds: float = 300.0,
    nonce_format: NonceFormat = NonceFormat.UUID
) -> RequestReplayShield:
    """Create a nonce-only replay protection shield.
    
    Args:
        nonce_storage: Storage backend for nonces
        replay_window_seconds: How long nonces are stored
        nonce_format: Format for nonces
    
    Returns:
        RequestReplayShield instance
    """
    config = ReplayProtectionConfig(
        strategy=ReplayProtectionStrategy.NONCE_ONLY,
        replay_window_seconds=replay_window_seconds,
        nonce_storage=nonce_storage or MemoryNonceStorage(),
        nonce_format=nonce_format
    )
    
    return RequestReplayShield(config)


def timestamp_only_replay_shield(
    replay_window_seconds: float = 300.0,
    clock_skew_tolerance: float = 300.0,
    timestamp_format: TimestampFormat = TimestampFormat.UNIX_TIMESTAMP
) -> RequestReplayShield:
    """Create a timestamp-only replay protection shield.
    
    Args:
        replay_window_seconds: Time window for valid timestamps
        clock_skew_tolerance: Tolerance for clock skew
        timestamp_format: Format for timestamps
    
    Returns:
        RequestReplayShield instance
    """
    config = ReplayProtectionConfig(
        strategy=ReplayProtectionStrategy.TIMESTAMP_ONLY,
        replay_window_seconds=replay_window_seconds,
        clock_skew_tolerance=clock_skew_tolerance,
        timestamp_format=timestamp_format
    )
    
    return RequestReplayShield(config)


def nonce_and_timestamp_replay_shield(
    nonce_storage: NonceStorage = None,
    replay_window_seconds: float = 300.0,
    clock_skew_tolerance: float = 300.0
) -> RequestReplayShield:
    """Create a nonce and timestamp replay protection shield.
    
    Args:
        nonce_storage: Storage backend for nonces
        replay_window_seconds: Time window for valid requests
        clock_skew_tolerance: Tolerance for clock skew
    
    Returns:
        RequestReplayShield instance
    """
    config = ReplayProtectionConfig(
        strategy=ReplayProtectionStrategy.NONCE_AND_TIMESTAMP,
        replay_window_seconds=replay_window_seconds,
        nonce_storage=nonce_storage or MemoryNonceStorage(),
        clock_skew_tolerance=clock_skew_tolerance
    )
    
    return RequestReplayShield(config)


def signature_based_replay_shield(
    signature_secret: str,
    nonce_storage: NonceStorage = None,
    replay_window_seconds: float = 300.0,
    signature_algorithm: str = "sha256"
) -> RequestReplayShield:
    """Create a signature-based replay protection shield.
    
    Args:
        signature_secret: Secret key for signature verification
        nonce_storage: Storage backend for nonces
        replay_window_seconds: Time window for valid requests
        signature_algorithm: Algorithm for signature generation
    
    Returns:
        RequestReplayShield instance
    """
    config = ReplayProtectionConfig(
        strategy=ReplayProtectionStrategy.SIGNATURE_BASED,
        replay_window_seconds=replay_window_seconds,
        nonce_storage=nonce_storage or MemoryNonceStorage(),
        signature_secret=signature_secret,
        signature_algorithm=signature_algorithm
    )
    
    return RequestReplayShield(config)


def redis_replay_shield(
    redis_url: str = "redis://localhost:6379",
    strategy: ReplayProtectionStrategy = ReplayProtectionStrategy.NONCE_AND_TIMESTAMP,
    replay_window_seconds: float = 300.0
) -> RequestReplayShield:
    """Create a replay protection shield with Redis storage.
    
    Args:
        redis_url: Redis connection URL
        strategy: Protection strategy to use
        replay_window_seconds: Time window for valid requests
    
    Returns:
        RequestReplayShield instance
    """
    redis_storage = RedisNonceStorage(redis_url=redis_url)
    
    config = ReplayProtectionConfig(
        strategy=strategy,
        replay_window_seconds=replay_window_seconds,
        nonce_storage=redis_storage
    )
    
    return RequestReplayShield(config)


def comprehensive_replay_shield(
    signature_secret: str,
    redis_url: Optional[str] = None,
    nonce_storage: NonceStorage = None,
    replay_window_seconds: float = 300.0,
    require_signature: bool = True
) -> RequestReplayShield:
    """Create a comprehensive replay protection shield with all features.
    
    Args:
        signature_secret: Secret key for signature verification
        redis_url: Redis connection URL (optional)
        nonce_storage: Custom storage backend (optional)
        replay_window_seconds: Time window for valid requests
        require_signature: Whether to require signature validation
    
    Returns:
        RequestReplayShield instance
    """
    # Choose storage backend
    if nonce_storage:
        storage = nonce_storage
    elif redis_url:
        storage = RedisNonceStorage(redis_url=redis_url)
    else:
        storage = MemoryNonceStorage(max_nonces=1000000)  # Larger for comprehensive use
    
    config = ReplayProtectionConfig(
        strategy=ReplayProtectionStrategy.COMBINED,
        replay_window_seconds=replay_window_seconds,
        nonce_storage=storage,
        signature_secret=signature_secret,
        require_signature=require_signature,
        log_replay_attempts=True,
        log_invalid_requests=True,
        include_client_info=True,
        enable_async_storage=True
    )
    
    return RequestReplayShield(config)