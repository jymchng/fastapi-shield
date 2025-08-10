"""API key rotation shield for FastAPI Shield.

This module provides comprehensive API key lifecycle management including
rotation, deprecation, validation, and integration with external key stores.
It supports multiple active keys per client, automatic rotation scheduling,
and graceful key transitions without service interruption.
"""

import asyncio
import hashlib
import secrets
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from uuid import uuid4

from fastapi import HTTPException, Request, status
from pydantic import BaseModel

from fastapi_shield.shield import Shield, shield


class KeyStatus(str, Enum):
    """API key status values."""
    ACTIVE = "active"           # Key is active and valid
    DEPRECATED = "deprecated"   # Key is deprecated but still valid
    EXPIRED = "expired"        # Key has expired and is invalid
    REVOKED = "revoked"        # Key has been revoked
    PENDING = "pending"        # Key is pending activation


class KeyRotationStrategy(str, Enum):
    """Key rotation strategies."""
    MANUAL = "manual"           # Manual rotation only
    SCHEDULED = "scheduled"     # Automatic scheduled rotation
    USAGE_BASED = "usage_based" # Rotate after N requests
    TIME_BASED = "time_based"   # Rotate after time period


class NotificationLevel(str, Enum):
    """Notification levels for key events."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class APIKey(BaseModel):
    """API key model with lifecycle information."""
    
    # Key identification
    key_id: str
    client_id: str
    key_hash: str  # Hashed version of the actual key
    key_prefix: str  # First few characters for identification
    
    # Lifecycle information
    status: KeyStatus = KeyStatus.PENDING
    created_at: datetime
    activated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    
    # Usage tracking
    usage_count: int = 0
    last_used_at: Optional[datetime] = None
    last_used_ip: Optional[str] = None
    
    # Rotation information
    rotation_strategy: KeyRotationStrategy = KeyRotationStrategy.MANUAL
    rotation_interval: Optional[int] = None  # Days for time-based, requests for usage-based
    next_rotation_at: Optional[datetime] = None
    
    # Metadata
    name: Optional[str] = None
    description: Optional[str] = None
    scopes: List[str] = []
    metadata: Dict[str, Any] = {}
    
    # Deprecation warnings
    deprecation_warning_sent: bool = False
    expiry_warning_sent: bool = False
    
    model_config = {"arbitrary_types_allowed": True}
    
    def is_valid(self) -> bool:
        """Check if the key is currently valid."""
        if self.status not in [KeyStatus.ACTIVE, KeyStatus.DEPRECATED]:
            return False
        
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        
        return True
    
    def is_expired(self) -> bool:
        """Check if the key has expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_near_expiry(self, warning_days: int = 7) -> bool:
        """Check if the key is near expiry."""
        if not self.expires_at:
            return False
        
        warning_time = datetime.now(timezone.utc) + timedelta(days=warning_days)
        return warning_time >= self.expires_at
    
    def should_rotate(self) -> bool:
        """Check if the key should be rotated based on strategy."""
        if self.rotation_strategy == KeyRotationStrategy.MANUAL:
            return False
        
        if self.rotation_strategy == KeyRotationStrategy.SCHEDULED:
            return (
                self.next_rotation_at and
                datetime.now(timezone.utc) >= self.next_rotation_at
            )
        
        if self.rotation_strategy == KeyRotationStrategy.TIME_BASED:
            if not self.rotation_interval or not self.activated_at:
                return False
            
            rotation_time = self.activated_at + timedelta(days=self.rotation_interval)
            return datetime.now(timezone.utc) >= rotation_time
        
        if self.rotation_strategy == KeyRotationStrategy.USAGE_BASED:
            return (
                self.rotation_interval and
                self.usage_count >= self.rotation_interval
            )
        
        return False


class KeyRotationEvent(BaseModel):
    """Key rotation event for notifications and logging."""
    
    event_type: str
    client_id: str
    key_id: str
    timestamp: datetime
    level: NotificationLevel
    message: str
    old_key_id: Optional[str] = None
    new_key_id: Optional[str] = None
    metadata: Dict[str, Any] = {}


class KeyStore(ABC):
    """Abstract base class for key storage backends."""
    
    @abstractmethod
    async def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get an API key by ID."""
        pass
    
    @abstractmethod
    async def get_keys_by_client(self, client_id: str) -> List[APIKey]:
        """Get all keys for a client."""
        pass
    
    @abstractmethod
    async def get_key_by_hash(self, key_hash: str) -> Optional[APIKey]:
        """Get a key by its hash."""
        pass
    
    @abstractmethod
    async def store_key(self, api_key: APIKey) -> None:
        """Store an API key."""
        pass
    
    @abstractmethod
    async def update_key(self, api_key: APIKey) -> None:
        """Update an API key."""
        pass
    
    @abstractmethod
    async def delete_key(self, key_id: str) -> None:
        """Delete an API key."""
        pass
    
    @abstractmethod
    async def get_keys_for_rotation(self) -> List[APIKey]:
        """Get keys that need rotation."""
        pass
    
    @abstractmethod
    async def get_keys_near_expiry(self, warning_days: int = 7) -> List[APIKey]:
        """Get keys that are near expiry."""
        pass


class MemoryKeyStore(KeyStore):
    """In-memory key store for development and testing."""
    
    def __init__(self):
        self.keys: Dict[str, APIKey] = {}
        self.client_keys: Dict[str, Set[str]] = {}
        self.key_hashes: Dict[str, str] = {}
        self._lock = asyncio.Lock()
    
    async def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get an API key by ID."""
        return self.keys.get(key_id)
    
    async def get_keys_by_client(self, client_id: str) -> List[APIKey]:
        """Get all keys for a client."""
        key_ids = self.client_keys.get(client_id, set())
        return [self.keys[key_id] for key_id in key_ids if key_id in self.keys]
    
    async def get_key_by_hash(self, key_hash: str) -> Optional[APIKey]:
        """Get a key by its hash."""
        key_id = self.key_hashes.get(key_hash)
        return self.keys.get(key_id) if key_id else None
    
    async def store_key(self, api_key: APIKey) -> None:
        """Store an API key."""
        async with self._lock:
            self.keys[api_key.key_id] = api_key
            
            # Update client index
            if api_key.client_id not in self.client_keys:
                self.client_keys[api_key.client_id] = set()
            self.client_keys[api_key.client_id].add(api_key.key_id)
            
            # Update hash index
            self.key_hashes[api_key.key_hash] = api_key.key_id
    
    async def update_key(self, api_key: APIKey) -> None:
        """Update an API key."""
        async with self._lock:
            if api_key.key_id in self.keys:
                self.keys[api_key.key_id] = api_key
    
    async def delete_key(self, key_id: str) -> None:
        """Delete an API key."""
        async with self._lock:
            if key_id in self.keys:
                api_key = self.keys[key_id]
                
                # Remove from indices
                if api_key.client_id in self.client_keys:
                    self.client_keys[api_key.client_id].discard(key_id)
                
                if api_key.key_hash in self.key_hashes:
                    del self.key_hashes[api_key.key_hash]
                
                # Remove key
                del self.keys[key_id]
    
    async def get_keys_for_rotation(self) -> List[APIKey]:
        """Get keys that need rotation."""
        return [
            key for key in self.keys.values()
            if key.should_rotate()
        ]
    
    async def get_keys_near_expiry(self, warning_days: int = 7) -> List[APIKey]:
        """Get keys that are near expiry."""
        return [
            key for key in self.keys.values()
            if key.is_near_expiry(warning_days)
        ]


class NotificationHandler(ABC):
    """Abstract base class for handling key rotation notifications."""
    
    @abstractmethod
    async def send_notification(self, event: KeyRotationEvent) -> None:
        """Send a notification for a key rotation event."""
        pass


class LoggingNotificationHandler(NotificationHandler):
    """Notification handler that logs events."""
    
    def __init__(self, logger=None):
        import logging
        self.logger = logger or logging.getLogger(__name__)
    
    async def send_notification(self, event: KeyRotationEvent) -> None:
        """Send a notification by logging the event."""
        import logging
        
        level_map = {
            NotificationLevel.INFO: logging.INFO,
            NotificationLevel.WARNING: logging.WARNING,
            NotificationLevel.ERROR: logging.ERROR,
            NotificationLevel.CRITICAL: logging.CRITICAL,
        }
        
        log_level = level_map.get(event.level, logging.INFO)
        self.logger.log(
            log_level,
            f"API Key Event [{event.event_type}] for client {event.client_id}: {event.message}"
        )


class WebhookNotificationHandler(NotificationHandler):
    """Notification handler that sends webhooks."""
    
    def __init__(self, webhook_url: str, headers: Optional[Dict[str, str]] = None):
        self.webhook_url = webhook_url
        self.headers = headers or {}
    
    async def send_notification(self, event: KeyRotationEvent) -> None:
        """Send a notification via webhook."""
        try:
            import httpx
            
            payload = event.model_dump()
            
            async with httpx.AsyncClient() as client:
                await client.post(
                    self.webhook_url,
                    json=payload,
                    headers=self.headers,
                    timeout=10.0
                )
        except Exception as e:
            # Log error but don't fail the rotation process
            import logging
            logging.getLogger(__name__).error(f"Failed to send webhook notification: {e}")


class APIKeyRotationConfig(BaseModel):
    """Configuration for API key rotation."""
    
    # Key generation
    key_length: int = 32
    key_prefix_length: int = 8
    hash_algorithm: str = "sha256"
    
    # Expiration settings
    default_expiry_days: Optional[int] = 90
    deprecation_warning_days: int = 14
    expiry_warning_days: int = 7
    
    # Rotation settings
    default_rotation_strategy: KeyRotationStrategy = KeyRotationStrategy.MANUAL
    default_rotation_interval: Optional[int] = None
    max_active_keys_per_client: int = 3
    
    # Grace periods
    deprecated_key_grace_days: int = 30
    rotation_overlap_days: int = 7
    
    # Validation
    require_key_in_header: bool = True
    key_header_name: str = "X-API-Key"
    allow_query_param: bool = False
    key_query_param: str = "api_key"
    
    # Security
    rate_limit_failed_attempts: bool = True
    max_failed_attempts: int = 5
    failed_attempts_window: int = 300  # seconds
    
    # Notifications
    enable_notifications: bool = True
    notification_handlers: List[NotificationHandler] = []
    
    # Background tasks
    enable_background_rotation: bool = True
    rotation_check_interval: int = 3600  # seconds
    
    model_config = {"arbitrary_types_allowed": True}


class APIKeyRotationShield:
    """API key rotation shield with comprehensive lifecycle management."""
    
    def __init__(
        self,
        key_store: KeyStore,
        config: Optional[APIKeyRotationConfig] = None,
        notification_handlers: Optional[List[NotificationHandler]] = None,
    ):
        """Initialize the API key rotation shield.
        
        Args:
            key_store: Backend for storing and retrieving keys
            config: Configuration for key rotation
            notification_handlers: Handlers for key rotation notifications
        """
        self.key_store = key_store
        self.config = config or APIKeyRotationConfig()
        self.notification_handlers = notification_handlers or []
        
        # Add default logging handler if none provided
        if not self.notification_handlers and self.config.enable_notifications:
            self.notification_handlers.append(LoggingNotificationHandler())
        
        # Background task management
        self._background_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        # Rate limiting for failed attempts
        self._failed_attempts: Dict[str, List[float]] = {}
    
    def _generate_key(self) -> Tuple[str, str, str]:
        """Generate a new API key.
        
        Returns:
            Tuple of (key_id, full_key, key_hash)
        """
        key_id = str(uuid4())
        
        # Generate random key
        key_bytes = secrets.token_bytes(self.config.key_length)
        full_key = secrets.token_urlsafe(self.config.key_length)
        
        # Create hash
        hash_obj = hashlib.new(self.config.hash_algorithm)
        hash_obj.update(full_key.encode())
        key_hash = hash_obj.hexdigest()
        
        return key_id, full_key, key_hash
    
    def _get_key_prefix(self, full_key: str) -> str:
        """Get the key prefix for identification."""
        return full_key[:self.config.key_prefix_length]
    
    def _hash_key(self, key: str) -> str:
        """Hash an API key."""
        hash_obj = hashlib.new(self.config.hash_algorithm)
        hash_obj.update(key.encode())
        return hash_obj.hexdigest()
    
    async def _notify(self, event: KeyRotationEvent) -> None:
        """Send notifications for key events."""
        if not self.config.enable_notifications:
            return
        
        for handler in self.notification_handlers:
            try:
                await handler.send_notification(event)
            except Exception as e:
                # Log notification errors but don't fail the operation
                import logging
                logging.getLogger(__name__).error(f"Notification handler error: {e}")
    
    async def _check_rate_limit(self, identifier: str) -> bool:
        """Check if identifier is rate limited due to failed attempts."""
        if not self.config.rate_limit_failed_attempts:
            return False
        
        now = time.time()
        
        # Clean old attempts
        if identifier in self._failed_attempts:
            self._failed_attempts[identifier] = [
                attempt_time for attempt_time in self._failed_attempts[identifier]
                if now - attempt_time < self.config.failed_attempts_window
            ]
        
        # Check rate limit
        attempts = self._failed_attempts.get(identifier, [])
        return len(attempts) >= self.config.max_failed_attempts
    
    async def _record_failed_attempt(self, identifier: str) -> None:
        """Record a failed authentication attempt."""
        if not self.config.rate_limit_failed_attempts:
            return
        
        now = time.time()
        
        if identifier not in self._failed_attempts:
            self._failed_attempts[identifier] = []
        
        self._failed_attempts[identifier].append(now)
    
    async def create_key(
        self,
        client_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        scopes: Optional[List[str]] = None,
        rotation_strategy: Optional[KeyRotationStrategy] = None,
        rotation_interval: Optional[int] = None,
        auto_activate: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[APIKey, str]:
        """Create a new API key.
        
        Args:
            client_id: Client identifier
            name: Optional name for the key
            description: Optional description
            expires_at: Optional expiration datetime
            scopes: Optional list of scopes
            rotation_strategy: Rotation strategy for the key
            rotation_interval: Rotation interval (days or requests)
            auto_activate: Whether to automatically activate the key
            metadata: Additional metadata
            
        Returns:
            Tuple of (APIKey, full_key_string)
        """
        # Check if client has too many active keys
        existing_keys = await self.key_store.get_keys_by_client(client_id)
        active_keys = [k for k in existing_keys if k.status == KeyStatus.ACTIVE]
        
        if len(active_keys) >= self.config.max_active_keys_per_client:
            raise ValueError(f"Client {client_id} already has maximum number of active keys")
        
        # Generate key
        key_id, full_key, key_hash = self._generate_key()
        key_prefix = self._get_key_prefix(full_key)
        
        # Set defaults
        now = datetime.now(timezone.utc)
        
        if expires_at is None and self.config.default_expiry_days:
            expires_at = now + timedelta(days=self.config.default_expiry_days)
        
        if rotation_strategy is None:
            rotation_strategy = self.config.default_rotation_strategy
        
        if rotation_interval is None:
            rotation_interval = self.config.default_rotation_interval
        
        # Calculate next rotation time for scheduled strategy
        next_rotation_at = None
        if rotation_strategy == KeyRotationStrategy.SCHEDULED and rotation_interval:
            next_rotation_at = now + timedelta(days=rotation_interval)
        
        # Create API key
        api_key = APIKey(
            key_id=key_id,
            client_id=client_id,
            key_hash=key_hash,
            key_prefix=key_prefix,
            status=KeyStatus.ACTIVE if auto_activate else KeyStatus.PENDING,
            created_at=now,
            activated_at=now if auto_activate else None,
            expires_at=expires_at,
            name=name,
            description=description,
            scopes=scopes or [],
            rotation_strategy=rotation_strategy,
            rotation_interval=rotation_interval,
            next_rotation_at=next_rotation_at,
            metadata=metadata or {},
        )
        
        # Store the key
        await self.key_store.store_key(api_key)
        
        # Send notification
        await self._notify(KeyRotationEvent(
            event_type="key_created",
            client_id=client_id,
            key_id=key_id,
            timestamp=now,
            level=NotificationLevel.INFO,
            message=f"New API key created: {key_prefix}...",
            metadata={"auto_activate": auto_activate}
        ))
        
        return api_key, full_key
    
    async def activate_key(self, key_id: str) -> APIKey:
        """Activate a pending API key."""
        api_key = await self.key_store.get_key(key_id)
        if not api_key:
            raise ValueError(f"Key {key_id} not found")
        
        if api_key.status != KeyStatus.PENDING:
            raise ValueError(f"Key {key_id} is not in pending status")
        
        now = datetime.now(timezone.utc)
        api_key.status = KeyStatus.ACTIVE
        api_key.activated_at = now
        
        await self.key_store.update_key(api_key)
        
        await self._notify(KeyRotationEvent(
            event_type="key_activated",
            client_id=api_key.client_id,
            key_id=key_id,
            timestamp=now,
            level=NotificationLevel.INFO,
            message=f"API key activated: {api_key.key_prefix}..."
        ))
        
        return api_key
    
    async def deprecate_key(
        self,
        key_id: str,
        grace_days: Optional[int] = None
    ) -> APIKey:
        """Deprecate an API key."""
        api_key = await self.key_store.get_key(key_id)
        if not api_key:
            raise ValueError(f"Key {key_id} not found")
        
        if api_key.status != KeyStatus.ACTIVE:
            raise ValueError(f"Key {key_id} is not active")
        
        now = datetime.now(timezone.utc)
        grace_days = grace_days or self.config.deprecated_key_grace_days
        
        api_key.status = KeyStatus.DEPRECATED
        api_key.expires_at = now + timedelta(days=grace_days)
        
        await self.key_store.update_key(api_key)
        
        await self._notify(KeyRotationEvent(
            event_type="key_deprecated",
            client_id=api_key.client_id,
            key_id=key_id,
            timestamp=now,
            level=NotificationLevel.WARNING,
            message=f"API key deprecated: {api_key.key_prefix}... (expires in {grace_days} days)"
        ))
        
        return api_key
    
    async def revoke_key(self, key_id: str, reason: Optional[str] = None) -> APIKey:
        """Revoke an API key immediately."""
        api_key = await self.key_store.get_key(key_id)
        if not api_key:
            raise ValueError(f"Key {key_id} not found")
        
        now = datetime.now(timezone.utc)
        api_key.status = KeyStatus.REVOKED
        api_key.revoked_at = now
        
        if reason:
            api_key.metadata["revocation_reason"] = reason
        
        await self.key_store.update_key(api_key)
        
        await self._notify(KeyRotationEvent(
            event_type="key_revoked",
            client_id=api_key.client_id,
            key_id=key_id,
            timestamp=now,
            level=NotificationLevel.ERROR,
            message=f"API key revoked: {api_key.key_prefix}... ({reason or 'No reason provided'})"
        ))
        
        return api_key
    
    async def rotate_key(
        self,
        key_id: str,
        keep_old_key: bool = True,
        grace_days: Optional[int] = None
    ) -> Tuple[APIKey, str]:
        """Rotate an API key by creating a new one and optionally deprecating the old one.
        
        Args:
            key_id: ID of the key to rotate
            keep_old_key: Whether to deprecate the old key instead of revoking it
            grace_days: Grace period for the old key if kept
            
        Returns:
            Tuple of (new_api_key, new_full_key)
        """
        old_key = await self.key_store.get_key(key_id)
        if not old_key:
            raise ValueError(f"Key {key_id} not found")
        
        # Create new key with same properties
        new_key, new_full_key = await self.create_key(
            client_id=old_key.client_id,
            name=old_key.name,
            description=f"Rotated from {old_key.key_prefix}...",
            expires_at=old_key.expires_at,
            scopes=old_key.scopes,
            rotation_strategy=old_key.rotation_strategy,
            rotation_interval=old_key.rotation_interval,
            auto_activate=True,
            metadata=old_key.metadata.copy()
        )
        
        # Handle old key
        if keep_old_key:
            await self.deprecate_key(key_id, grace_days)
        else:
            await self.revoke_key(key_id, "Rotated")
        
        # Send rotation notification
        await self._notify(KeyRotationEvent(
            event_type="key_rotated",
            client_id=old_key.client_id,
            key_id=new_key.key_id,
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.INFO,
            message=f"API key rotated: {old_key.key_prefix}... -> {new_key.key_prefix}...",
            old_key_id=key_id,
            new_key_id=new_key.key_id
        ))
        
        return new_key, new_full_key
    
    async def validate_key(self, key: str, client_ip: Optional[str] = None) -> Optional[APIKey]:
        """Validate an API key and return the associated APIKey if valid.
        
        Args:
            key: The API key to validate
            client_ip: Optional client IP for logging
            
        Returns:
            APIKey if valid, None if invalid
        """
        # Hash the provided key
        key_hash = self._hash_key(key)
        
        # Check rate limiting
        if await self._check_rate_limit(key_hash):
            await self._record_failed_attempt(key_hash)
            return None
        
        # Look up key
        api_key = await self.key_store.get_key_by_hash(key_hash)
        
        if not api_key or not api_key.is_valid():
            await self._record_failed_attempt(key_hash)
            return None
        
        # Update usage statistics
        now = datetime.now(timezone.utc)
        api_key.usage_count += 1
        api_key.last_used_at = now
        if client_ip:
            api_key.last_used_ip = client_ip
        
        await self.key_store.update_key(api_key)
        
        # Check for automatic rotation
        if api_key.should_rotate():
            # Schedule rotation (don't block the current request)
            asyncio.create_task(self._schedule_rotation(api_key.key_id))
        
        return api_key
    
    async def _schedule_rotation(self, key_id: str) -> None:
        """Schedule a key rotation (background task)."""
        try:
            await self.rotate_key(key_id, keep_old_key=True)
        except Exception as e:
            # Log rotation errors
            import logging
            logging.getLogger(__name__).error(f"Failed to rotate key {key_id}: {e}")
    
    async def get_client_keys(self, client_id: str) -> List[APIKey]:
        """Get all keys for a client."""
        return await self.key_store.get_keys_by_client(client_id)
    
    async def cleanup_expired_keys(self) -> int:
        """Clean up expired keys and return count of cleaned keys."""
        all_keys = []
        
        # Get all keys (this is inefficient for large datasets, but works for our use case)
        # In production, you'd want a more efficient query
        try:
            # This is a hack since we don't have a get_all_keys method
            # We'll implement it by iterating through clients
            pass  # For now, skip cleanup in this implementation
        except:
            pass
        
        return 0
    
    async def send_expiry_warnings(self) -> int:
        """Send expiry warnings for keys near expiration."""
        keys_near_expiry = await self.key_store.get_keys_near_expiry(
            self.config.expiry_warning_days
        )
        
        warnings_sent = 0
        for api_key in keys_near_expiry:
            if not api_key.expiry_warning_sent:
                await self._notify(KeyRotationEvent(
                    event_type="key_expiring",
                    client_id=api_key.client_id,
                    key_id=api_key.key_id,
                    timestamp=datetime.now(timezone.utc),
                    level=NotificationLevel.WARNING,
                    message=f"API key expiring soon: {api_key.key_prefix}... (expires {api_key.expires_at})"
                ))
                
                api_key.expiry_warning_sent = True
                await self.key_store.update_key(api_key)
                warnings_sent += 1
        
        return warnings_sent
    
    async def _background_rotation_task(self) -> None:
        """Background task for automatic key rotation and cleanup."""
        while not self._shutdown_event.is_set():
            try:
                # Check for keys that need rotation
                keys_for_rotation = await self.key_store.get_keys_for_rotation()
                for api_key in keys_for_rotation:
                    try:
                        await self.rotate_key(api_key.key_id, keep_old_key=True)
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).error(f"Failed to rotate key {api_key.key_id}: {e}")
                
                # Send expiry warnings
                await self.send_expiry_warnings()
                
                # Clean up expired keys
                await self.cleanup_expired_keys()
                
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Background rotation task error: {e}")
            
            # Wait for next check or shutdown
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.config.rotation_check_interval
                )
                break  # Shutdown requested
            except asyncio.TimeoutError:
                continue  # Continue with next iteration
    
    async def start_background_tasks(self) -> None:
        """Start background tasks for key rotation."""
        if self.config.enable_background_rotation and not self._background_task:
            self._background_task = asyncio.create_task(self._background_rotation_task())
    
    async def stop_background_tasks(self) -> None:
        """Stop background tasks."""
        if self._background_task:
            self._shutdown_event.set()
            try:
                await asyncio.wait_for(self._background_task, timeout=5.0)
            except asyncio.TimeoutError:
                self._background_task.cancel()
                try:
                    await self._background_task
                except asyncio.CancelledError:
                    pass
            
            self._background_task = None
            self._shutdown_event.clear()
    
    def _extract_api_key(self, request: Request) -> Optional[str]:
        """Extract API key from request."""
        # Check header first
        if self.config.require_key_in_header:
            api_key = request.headers.get(self.config.key_header_name)
            if api_key:
                # Remove "Bearer " prefix if present
                if api_key.startswith("Bearer "):
                    api_key = api_key[7:]
                return api_key
        
        # Check query parameter if allowed
        if self.config.allow_query_param:
            return request.query_params.get(self.config.key_query_param)
        
        return None
    
    def create_shield(
        self,
        required_scopes: Optional[List[str]] = None,
        name: str = "APIKeyRotation"
    ) -> Shield:
        """Create a shield for API key validation and rotation.
        
        Args:
            required_scopes: Optional list of required scopes
            name: Shield name
            
        Returns:
            Shield instance
        """
        
        async def api_key_rotation_shield(request: Request) -> Dict[str, Any]:
            """API key rotation shield function."""
            # Extract API key from request
            api_key = self._extract_api_key(request)
            
            if not api_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key required",
                    headers={"WWW-Authenticate": "ApiKey"}
                )
            
            # Get client IP
            client_ip = request.client.host if request.client else None
            
            # Validate key
            key_info = await self.validate_key(api_key, client_ip)
            
            if not key_info:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired API key",
                    headers={"WWW-Authenticate": "ApiKey"}
                )
            
            # Check required scopes
            if required_scopes:
                if not key_info.scopes:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="API key has no scopes"
                    )
                
                missing_scopes = set(required_scopes) - set(key_info.scopes)
                if missing_scopes:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"API key missing required scopes: {', '.join(missing_scopes)}"
                    )
            
            # Add deprecation warning header if key is deprecated
            response_headers = {}
            if key_info.status == KeyStatus.DEPRECATED:
                response_headers["X-API-Key-Deprecated"] = "true"
                if key_info.expires_at:
                    response_headers["X-API-Key-Expires"] = key_info.expires_at.isoformat()
            
            return {
                "api_key_info": key_info,
                "client_id": key_info.client_id,
                "key_id": key_info.key_id,
                "scopes": key_info.scopes,
                "response_headers": response_headers,
            }
        
        return shield(
            api_key_rotation_shield,
            name=name,
            auto_error=True,
        )


# Convenience functions for common API key rotation scenarios
def api_key_rotation_shield(
    key_store: Optional[KeyStore] = None,
    required_scopes: Optional[List[str]] = None,
    key_header_name: str = "X-API-Key",
    allow_query_param: bool = False,
    name: str = "APIKeyRotation",
) -> Shield:
    """Create an API key rotation shield with specified configuration.
    
    Args:
        key_store: Backend for storing keys (defaults to MemoryKeyStore)
        required_scopes: Optional list of required scopes
        key_header_name: Header name for API key
        allow_query_param: Whether to allow key in query parameters
        name: Shield name
        
    Returns:
        Shield: Configured API key rotation shield
        
    Examples:
        ```python
        # Basic API key authentication
        @app.get("/api/protected")
        @api_key_rotation_shield()
        def protected_endpoint():
            return {"message": "Protected data"}
        
        # With required scopes
        @app.post("/api/admin")
        @api_key_rotation_shield(required_scopes=["admin", "write"])
        def admin_endpoint():
            return {"message": "Admin operation"}
        
        # Custom header name
        @app.get("/api/custom")
        @api_key_rotation_shield(key_header_name="Authorization")
        def custom_header_endpoint():
            return {"message": "Custom header"}
        ```
    """
    # Use memory store as default
    if key_store is None:
        key_store = MemoryKeyStore()
    
    config = APIKeyRotationConfig(
        key_header_name=key_header_name,
        allow_query_param=allow_query_param,
    )
    
    rotation_shield = APIKeyRotationShield(key_store=key_store, config=config)
    return rotation_shield.create_shield(required_scopes=required_scopes, name=name)


def scoped_api_key_shield(
    scopes: List[str],
    key_store: Optional[KeyStore] = None,
    name: str = "ScopedAPIKey",
) -> Shield:
    """Create an API key shield that requires specific scopes.
    
    Args:
        scopes: Required scopes for the endpoint
        key_store: Backend for storing keys
        name: Shield name
        
    Returns:
        Shield: Scoped API key shield
    """
    return api_key_rotation_shield(
        key_store=key_store,
        required_scopes=scopes,
        name=name
    )


def admin_api_key_shield(
    key_store: Optional[KeyStore] = None,
    name: str = "AdminAPIKey",
) -> Shield:
    """Create an API key shield for admin endpoints.
    
    Args:
        key_store: Backend for storing keys
        name: Shield name
        
    Returns:
        Shield: Admin API key shield
    """
    return scoped_api_key_shield(
        scopes=["admin"],
        key_store=key_store,
        name=name
    )


def read_only_api_key_shield(
    key_store: Optional[KeyStore] = None,
    name: str = "ReadOnlyAPIKey",
) -> Shield:
    """Create an API key shield for read-only endpoints.
    
    Args:
        key_store: Backend for storing keys
        name: Shield name
        
    Returns:
        Shield: Read-only API key shield
    """
    return scoped_api_key_shield(
        scopes=["read"],
        key_store=key_store,
        name=name
    )