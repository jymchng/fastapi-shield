"""Tests for API key rotation shield functionality."""

import asyncio
import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import List
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield.api_key_rotation import (
    APIKeyRotationShield,
    APIKeyRotationConfig,
    APIKey,
    KeyStatus,
    KeyRotationStrategy,
    NotificationLevel,
    KeyRotationEvent,
    KeyStore,
    MemoryKeyStore,
    NotificationHandler,
    LoggingNotificationHandler,
    WebhookNotificationHandler,
    api_key_rotation_shield,
    scoped_api_key_shield,
    admin_api_key_shield,
    read_only_api_key_shield,
)


class MockNotificationHandler(NotificationHandler):
    """Mock notification handler for testing."""
    
    def __init__(self):
        self.notifications: List[KeyRotationEvent] = []
    
    async def send_notification(self, event: KeyRotationEvent) -> None:
        """Store notification for testing."""
        self.notifications.append(event)


class TestAPIKey:
    """Test APIKey model functionality."""
    
    def test_api_key_creation(self):
        """Test creating an API key."""
        now = datetime.now(timezone.utc)
        api_key = APIKey(
            key_id="test-123",
            client_id="client-1",
            key_hash="hash123",
            key_prefix="sk_test",
            status=KeyStatus.ACTIVE,
            created_at=now,
            activated_at=now,
            expires_at=now + timedelta(days=30),
            scopes=["read", "write"],
        )
        
        assert api_key.key_id == "test-123"
        assert api_key.client_id == "client-1"
        assert api_key.status == KeyStatus.ACTIVE
        assert api_key.scopes == ["read", "write"]
    
    def test_is_valid(self):
        """Test key validity checking."""
        now = datetime.now(timezone.utc)
        
        # Valid active key
        api_key = APIKey(
            key_id="test-123",
            client_id="client-1",
            key_hash="hash123",
            key_prefix="sk_test",
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=30),
        )
        assert api_key.is_valid() is True
        
        # Valid deprecated key
        api_key.status = KeyStatus.DEPRECATED
        assert api_key.is_valid() is True
        
        # Invalid revoked key
        api_key.status = KeyStatus.REVOKED
        assert api_key.is_valid() is False
        
        # Invalid expired key
        api_key.status = KeyStatus.ACTIVE
        api_key.expires_at = now - timedelta(days=1)
        assert api_key.is_valid() is False
    
    def test_is_expired(self):
        """Test expiration checking."""
        now = datetime.now(timezone.utc)
        
        api_key = APIKey(
            key_id="test-123",
            client_id="client-1",
            key_hash="hash123",
            key_prefix="sk_test",
            created_at=now,
            expires_at=now + timedelta(days=1),
        )
        
        # Not expired
        assert api_key.is_expired() is False
        
        # Expired
        api_key.expires_at = now - timedelta(days=1)
        assert api_key.is_expired() is True
        
        # No expiry date
        api_key.expires_at = None
        assert api_key.is_expired() is False
    
    def test_is_near_expiry(self):
        """Test near expiry checking."""
        now = datetime.now(timezone.utc)
        
        api_key = APIKey(
            key_id="test-123",
            client_id="client-1",
            key_hash="hash123",
            key_prefix="sk_test",
            created_at=now,
        )
        
        # Near expiry (5 days)
        api_key.expires_at = now + timedelta(days=5)
        assert api_key.is_near_expiry(warning_days=7) is True
        
        # Not near expiry (10 days)
        api_key.expires_at = now + timedelta(days=10)
        assert api_key.is_near_expiry(warning_days=7) is False
        
        # No expiry date
        api_key.expires_at = None
        assert api_key.is_near_expiry() is False
    
    def test_should_rotate(self):
        """Test rotation checking for different strategies."""
        now = datetime.now(timezone.utc)
        
        api_key = APIKey(
            key_id="test-123",
            client_id="client-1",
            key_hash="hash123",
            key_prefix="sk_test",
            created_at=now,
            activated_at=now,
        )
        
        # Manual strategy - never rotate automatically
        api_key.rotation_strategy = KeyRotationStrategy.MANUAL
        assert api_key.should_rotate() is False
        
        # Scheduled strategy
        api_key.rotation_strategy = KeyRotationStrategy.SCHEDULED
        api_key.next_rotation_at = now - timedelta(hours=1)  # Past rotation time
        assert api_key.should_rotate() is True
        
        api_key.next_rotation_at = now + timedelta(hours=1)  # Future rotation time
        assert api_key.should_rotate() is False
        
        # Time-based strategy
        api_key.rotation_strategy = KeyRotationStrategy.TIME_BASED
        api_key.rotation_interval = 30  # 30 days
        api_key.activated_at = now - timedelta(days=31)  # 31 days ago
        assert api_key.should_rotate() is True
        
        api_key.activated_at = now - timedelta(days=29)  # 29 days ago
        assert api_key.should_rotate() is False
        
        # Usage-based strategy
        api_key.rotation_strategy = KeyRotationStrategy.USAGE_BASED
        api_key.rotation_interval = 1000  # 1000 requests
        api_key.usage_count = 1001
        assert api_key.should_rotate() is True
        
        api_key.usage_count = 999
        assert api_key.should_rotate() is False


class TestMemoryKeyStore:
    """Test the memory key store implementation."""
    
    @pytest.fixture
    def key_store(self):
        """Create a memory key store for testing."""
        return MemoryKeyStore()
    
    @pytest.fixture
    def sample_key(self):
        """Create a sample API key for testing."""
        now = datetime.now(timezone.utc)
        return APIKey(
            key_id="test-123",
            client_id="client-1",
            key_hash="hash123",
            key_prefix="sk_test",
            status=KeyStatus.ACTIVE,
            created_at=now,
            activated_at=now,
            expires_at=now + timedelta(days=30),
            scopes=["read", "write"],
        )
    
    @pytest.mark.asyncio
    async def test_store_and_get_key(self, key_store, sample_key):
        """Test storing and retrieving keys."""
        await key_store.store_key(sample_key)
        
        retrieved_key = await key_store.get_key("test-123")
        assert retrieved_key is not None
        assert retrieved_key.key_id == sample_key.key_id
        assert retrieved_key.client_id == sample_key.client_id
        
        # Test non-existent key
        missing_key = await key_store.get_key("missing-123")
        assert missing_key is None
    
    @pytest.mark.asyncio
    async def test_get_keys_by_client(self, key_store, sample_key):
        """Test getting keys by client ID."""
        # Store keys for different clients
        key1 = sample_key
        key2 = APIKey(
            key_id="test-456",
            client_id="client-1",  # Same client
            key_hash="hash456",
            key_prefix="sk_test2",
            created_at=datetime.now(timezone.utc),
        )
        key3 = APIKey(
            key_id="test-789",
            client_id="client-2",  # Different client
            key_hash="hash789",
            key_prefix="sk_test3",
            created_at=datetime.now(timezone.utc),
        )
        
        await key_store.store_key(key1)
        await key_store.store_key(key2)
        await key_store.store_key(key3)
        
        # Get keys for client-1
        client1_keys = await key_store.get_keys_by_client("client-1")
        assert len(client1_keys) == 2
        assert all(key.client_id == "client-1" for key in client1_keys)
        
        # Get keys for client-2
        client2_keys = await key_store.get_keys_by_client("client-2")
        assert len(client2_keys) == 1
        assert client2_keys[0].client_id == "client-2"
        
        # Get keys for non-existent client
        missing_client_keys = await key_store.get_keys_by_client("missing")
        assert len(missing_client_keys) == 0
    
    @pytest.mark.asyncio
    async def test_get_key_by_hash(self, key_store, sample_key):
        """Test getting key by hash."""
        await key_store.store_key(sample_key)
        
        retrieved_key = await key_store.get_key_by_hash("hash123")
        assert retrieved_key is not None
        assert retrieved_key.key_hash == "hash123"
        
        # Test non-existent hash
        missing_key = await key_store.get_key_by_hash("missing_hash")
        assert missing_key is None
    
    @pytest.mark.asyncio
    async def test_update_key(self, key_store, sample_key):
        """Test updating a key."""
        await key_store.store_key(sample_key)
        
        # Update key
        sample_key.usage_count = 100
        sample_key.status = KeyStatus.DEPRECATED
        await key_store.update_key(sample_key)
        
        # Verify update
        updated_key = await key_store.get_key("test-123")
        assert updated_key.usage_count == 100
        assert updated_key.status == KeyStatus.DEPRECATED
    
    @pytest.mark.asyncio
    async def test_delete_key(self, key_store, sample_key):
        """Test deleting a key."""
        await key_store.store_key(sample_key)
        
        # Verify key exists
        assert await key_store.get_key("test-123") is not None
        
        # Delete key
        await key_store.delete_key("test-123")
        
        # Verify key is gone
        assert await key_store.get_key("test-123") is None
        
        # Verify client index is updated
        client_keys = await key_store.get_keys_by_client("client-1")
        assert len(client_keys) == 0
        
        # Verify hash index is updated
        assert await key_store.get_key_by_hash("hash123") is None
    
    @pytest.mark.asyncio
    async def test_get_keys_for_rotation(self, key_store):
        """Test getting keys that need rotation."""
        now = datetime.now(timezone.utc)
        
        # Key that needs rotation (scheduled)
        key1 = APIKey(
            key_id="test-123",
            client_id="client-1",
            key_hash="hash123",
            key_prefix="sk_test1",
            created_at=now,
            rotation_strategy=KeyRotationStrategy.SCHEDULED,
            next_rotation_at=now - timedelta(hours=1),  # Past rotation time
        )
        
        # Key that doesn't need rotation
        key2 = APIKey(
            key_id="test-456",
            client_id="client-1",
            key_hash="hash456",
            key_prefix="sk_test2",
            created_at=now,
            rotation_strategy=KeyRotationStrategy.MANUAL,
        )
        
        # Key that needs rotation (usage-based)
        key3 = APIKey(
            key_id="test-789",
            client_id="client-1",
            key_hash="hash789",
            key_prefix="sk_test3",
            created_at=now,
            rotation_strategy=KeyRotationStrategy.USAGE_BASED,
            rotation_interval=100,
            usage_count=150,
        )
        
        await key_store.store_key(key1)
        await key_store.store_key(key2)
        await key_store.store_key(key3)
        
        rotation_keys = await key_store.get_keys_for_rotation()
        assert len(rotation_keys) == 2
        
        rotation_key_ids = {key.key_id for key in rotation_keys}
        assert "test-123" in rotation_key_ids
        assert "test-789" in rotation_key_ids
        assert "test-456" not in rotation_key_ids
    
    @pytest.mark.asyncio
    async def test_get_keys_near_expiry(self, key_store):
        """Test getting keys near expiry."""
        now = datetime.now(timezone.utc)
        
        # Key near expiry
        key1 = APIKey(
            key_id="test-123",
            client_id="client-1",
            key_hash="hash123",
            key_prefix="sk_test1",
            created_at=now,
            expires_at=now + timedelta(days=5),  # Expires in 5 days
        )
        
        # Key not near expiry
        key2 = APIKey(
            key_id="test-456",
            client_id="client-1",
            key_hash="hash456",
            key_prefix="sk_test2",
            created_at=now,
            expires_at=now + timedelta(days=30),  # Expires in 30 days
        )
        
        # Key with no expiry
        key3 = APIKey(
            key_id="test-789",
            client_id="client-1",
            key_hash="hash789",
            key_prefix="sk_test3",
            created_at=now,
            expires_at=None,
        )
        
        await key_store.store_key(key1)
        await key_store.store_key(key2)
        await key_store.store_key(key3)
        
        near_expiry_keys = await key_store.get_keys_near_expiry(warning_days=7)
        assert len(near_expiry_keys) == 1
        assert near_expiry_keys[0].key_id == "test-123"


class TestNotificationHandlers:
    """Test notification handlers."""
    
    def test_mock_notification_handler(self):
        """Test mock notification handler."""
        handler = MockNotificationHandler()
        assert len(handler.notifications) == 0
    
    @pytest.mark.asyncio
    async def test_logging_notification_handler(self):
        """Test logging notification handler."""
        with patch('logging.getLogger') as mock_logger_factory:
            mock_logger = Mock()
            mock_logger_factory.return_value = mock_logger
            
            handler = LoggingNotificationHandler()
            
            event = KeyRotationEvent(
                event_type="test_event",
                client_id="client-1",
                key_id="key-123",
                timestamp=datetime.now(timezone.utc),
                level=NotificationLevel.INFO,
                message="Test message"
            )
            
            await handler.send_notification(event)
            
            # Verify logger was called
            mock_logger.log.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_webhook_notification_handler(self):
        """Test webhook notification handler."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            handler = WebhookNotificationHandler(
                webhook_url="https://example.com/webhook",
                headers={"Authorization": "Bearer token"}
            )
            
            event = KeyRotationEvent(
                event_type="test_event",
                client_id="client-1",
                key_id="key-123",
                timestamp=datetime.now(timezone.utc),
                level=NotificationLevel.INFO,
                message="Test message"
            )
            
            await handler.send_notification(event)
            
            # Verify HTTP request was made
            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            assert call_args[1]['json'] == event.model_dump()


class TestAPIKeyRotationShield:
    """Test the API key rotation shield class."""
    
    @pytest.fixture
    def key_store(self):
        """Create a memory key store for testing."""
        return MemoryKeyStore()
    
    @pytest.fixture
    def notification_handler(self):
        """Create a mock notification handler for testing."""
        return MockNotificationHandler()
    
    @pytest.fixture
    def shield(self, key_store, notification_handler):
        """Create an API key rotation shield for testing."""
        config = APIKeyRotationConfig(
            key_length=16,  # Shorter for testing
            default_expiry_days=30,
        )
        return APIKeyRotationShield(
            key_store=key_store,
            config=config,
            notification_handlers=[notification_handler]
        )
    
    def test_shield_initialization(self, shield):
        """Test shield initialization."""
        assert shield.key_store is not None
        assert shield.config is not None
        assert len(shield.notification_handlers) == 1
    
    def test_generate_key(self, shield):
        """Test key generation."""
        key_id, full_key, key_hash = shield._generate_key()
        
        assert len(key_id) == 36  # UUID4 format
        assert len(full_key) > 0
        assert len(key_hash) == 64  # SHA256 hex
        
        # Test uniqueness
        key_id2, full_key2, key_hash2 = shield._generate_key()
        assert key_id != key_id2
        assert full_key != full_key2
        assert key_hash != key_hash2
    
    def test_hash_key(self, shield):
        """Test key hashing."""
        key = "test-key-123"
        key_hash = shield._hash_key(key)
        
        # Verify hash is deterministic
        assert shield._hash_key(key) == key_hash
        
        # Verify different keys produce different hashes
        assert shield._hash_key("different-key") != key_hash
    
    def test_get_key_prefix(self, shield):
        """Test key prefix extraction."""
        key = "sk_test_abcdef123456"
        prefix = shield._get_key_prefix(key)
        
        assert prefix == "sk_test_"
        assert len(prefix) == shield.config.key_prefix_length
    
    @pytest.mark.asyncio
    async def test_create_key(self, shield, notification_handler):
        """Test key creation."""
        api_key, full_key = await shield.create_key(
            client_id="client-1",
            name="Test Key",
            description="A test key",
            scopes=["read", "write"],
            auto_activate=True
        )
        
        assert api_key.client_id == "client-1"
        assert api_key.name == "Test Key"
        assert api_key.description == "A test key"
        assert api_key.scopes == ["read", "write"]
        assert api_key.status == KeyStatus.ACTIVE
        assert api_key.activated_at is not None
        
        # Verify key was stored
        stored_key = await shield.key_store.get_key(api_key.key_id)
        assert stored_key is not None
        assert stored_key.key_id == api_key.key_id
        
        # Verify notification was sent
        assert len(notification_handler.notifications) == 1
        assert notification_handler.notifications[0].event_type == "key_created"
    
    @pytest.mark.asyncio
    async def test_create_key_max_limit(self, shield):
        """Test key creation with maximum limit."""
        # Set low limit for testing
        shield.config.max_active_keys_per_client = 2
        
        # Create maximum number of keys
        await shield.create_key("client-1", auto_activate=True)
        await shield.create_key("client-1", auto_activate=True)
        
        # Try to create one more - should fail
        with pytest.raises(ValueError, match="already has maximum number"):
            await shield.create_key("client-1", auto_activate=True)
    
    @pytest.mark.asyncio
    async def test_activate_key(self, shield, notification_handler):
        """Test key activation."""
        # Create pending key
        api_key, _ = await shield.create_key("client-1", auto_activate=False)
        assert api_key.status == KeyStatus.PENDING
        
        # Activate key
        activated_key = await shield.activate_key(api_key.key_id)
        assert activated_key.status == KeyStatus.ACTIVE
        assert activated_key.activated_at is not None
        
        # Verify notification was sent
        activation_notifications = [
            n for n in notification_handler.notifications
            if n.event_type == "key_activated"
        ]
        assert len(activation_notifications) == 1
    
    @pytest.mark.asyncio
    async def test_activate_key_invalid_status(self, shield):
        """Test activating key with invalid status."""
        # Create and activate key
        api_key, _ = await shield.create_key("client-1", auto_activate=True)
        
        # Try to activate already active key
        with pytest.raises(ValueError, match="not in pending status"):
            await shield.activate_key(api_key.key_id)
    
    @pytest.mark.asyncio
    async def test_deprecate_key(self, shield, notification_handler):
        """Test key deprecation."""
        # Create active key
        api_key, _ = await shield.create_key("client-1", auto_activate=True)
        
        # Deprecate key
        deprecated_key = await shield.deprecate_key(api_key.key_id, grace_days=14)
        assert deprecated_key.status == KeyStatus.DEPRECATED
        assert deprecated_key.expires_at is not None
        
        # Verify notification was sent
        deprecation_notifications = [
            n for n in notification_handler.notifications
            if n.event_type == "key_deprecated"
        ]
        assert len(deprecation_notifications) == 1
    
    @pytest.mark.asyncio
    async def test_revoke_key(self, shield, notification_handler):
        """Test key revocation."""
        # Create active key
        api_key, _ = await shield.create_key("client-1", auto_activate=True)
        
        # Revoke key
        revoked_key = await shield.revoke_key(api_key.key_id, reason="Security breach")
        assert revoked_key.status == KeyStatus.REVOKED
        assert revoked_key.revoked_at is not None
        assert revoked_key.metadata.get("revocation_reason") == "Security breach"
        
        # Verify notification was sent
        revocation_notifications = [
            n for n in notification_handler.notifications
            if n.event_type == "key_revoked"
        ]
        assert len(revocation_notifications) == 1
    
    @pytest.mark.asyncio
    async def test_rotate_key(self, shield, notification_handler):
        """Test key rotation."""
        # Create active key
        old_key, _ = await shield.create_key("client-1", name="Old Key", auto_activate=True)
        
        # Rotate key
        new_key, new_full_key = await shield.rotate_key(old_key.key_id, keep_old_key=True)
        
        # Verify new key
        assert new_key.client_id == old_key.client_id
        assert new_key.key_id != old_key.key_id
        assert new_key.status == KeyStatus.ACTIVE
        assert "Rotated from" in new_key.description
        
        # Verify old key is deprecated
        old_key_updated = await shield.key_store.get_key(old_key.key_id)
        assert old_key_updated.status == KeyStatus.DEPRECATED
        
        # Verify rotation notification was sent
        rotation_notifications = [
            n for n in notification_handler.notifications
            if n.event_type == "key_rotated"
        ]
        assert len(rotation_notifications) == 1
    
    @pytest.mark.asyncio
    async def test_validate_key_valid(self, shield):
        """Test validating a valid key."""
        # Create active key
        api_key, full_key = await shield.create_key("client-1", auto_activate=True)
        
        # Validate key
        validated_key = await shield.validate_key(full_key, client_ip="192.168.1.1")
        
        assert validated_key is not None
        assert validated_key.key_id == api_key.key_id
        assert validated_key.usage_count == 1
        assert validated_key.last_used_at is not None
        assert validated_key.last_used_ip == "192.168.1.1"
    
    @pytest.mark.asyncio
    async def test_validate_key_invalid(self, shield):
        """Test validating an invalid key."""
        # Validate non-existent key
        result = await shield.validate_key("invalid-key")
        assert result is None
        
        # Create and revoke key
        api_key, full_key = await shield.create_key("client-1", auto_activate=True)
        await shield.revoke_key(api_key.key_id)
        
        # Validate revoked key
        result = await shield.validate_key(full_key)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_validate_key_expired(self, shield):
        """Test validating an expired key."""
        now = datetime.now(timezone.utc)
        
        # Create key that expires immediately
        api_key, full_key = await shield.create_key(
            "client-1",
            expires_at=now - timedelta(seconds=1),  # Already expired
            auto_activate=True
        )
        
        # Validate expired key
        result = await shield.validate_key(full_key)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, shield):
        """Test rate limiting for failed attempts."""
        shield.config.rate_limit_failed_attempts = True
        shield.config.max_failed_attempts = 3
        
        # Make failed attempts
        for i in range(3):
            result = await shield.validate_key("invalid-key")
            assert result is None
        
        # Check rate limit is triggered
        key_hash = shield._hash_key("invalid-key")
        is_rate_limited = await shield._check_rate_limit(key_hash)
        assert is_rate_limited is True
        
        # Further attempts should be blocked
        result = await shield.validate_key("invalid-key")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_client_keys(self, shield):
        """Test getting client keys."""
        # Create keys for client
        key1, _ = await shield.create_key("client-1", name="Key 1", auto_activate=True)
        key2, _ = await shield.create_key("client-1", name="Key 2", auto_activate=False)
        key3, _ = await shield.create_key("client-2", name="Key 3", auto_activate=True)
        
        # Get keys for client-1
        client1_keys = await shield.get_client_keys("client-1")
        assert len(client1_keys) == 2
        
        key_names = {key.name for key in client1_keys}
        assert "Key 1" in key_names
        assert "Key 2" in key_names
        assert "Key 3" not in key_names
    
    @pytest.mark.asyncio
    async def test_send_expiry_warnings(self, shield, notification_handler):
        """Test sending expiry warnings."""
        now = datetime.now(timezone.utc)
        
        # Create key near expiry
        api_key, _ = await shield.create_key(
            "client-1",
            expires_at=now + timedelta(days=5),  # Expires in 5 days
            auto_activate=True
        )
        
        # Send expiry warnings
        warnings_sent = await shield.send_expiry_warnings()
        assert warnings_sent == 1
        
        # Verify notification was sent
        warning_notifications = [
            n for n in notification_handler.notifications
            if n.event_type == "key_expiring"
        ]
        assert len(warning_notifications) == 1
        
        # Verify warning flag was set
        updated_key = await shield.key_store.get_key(api_key.key_id)
        assert updated_key.expiry_warning_sent is True
        
        # Second call should not send warning again
        warnings_sent = await shield.send_expiry_warnings()
        assert warnings_sent == 0
    
    def test_extract_api_key_from_header(self, shield):
        """Test extracting API key from request headers."""
        # Mock request with API key in header
        request = Mock()
        request.headers = {"X-API-Key": "sk_test_123456"}
        request.query_params = {}
        
        api_key = shield._extract_api_key(request)
        assert api_key == "sk_test_123456"
        
        # Test with Bearer prefix
        request.headers = {"X-API-Key": "Bearer sk_test_123456"}
        api_key = shield._extract_api_key(request)
        assert api_key == "sk_test_123456"
        
        # Test with no header
        request.headers = {}
        api_key = shield._extract_api_key(request)
        assert api_key is None
    
    def test_extract_api_key_from_query_param(self, shield):
        """Test extracting API key from query parameters."""
        shield.config.allow_query_param = True
        
        request = Mock()
        request.headers = {}
        request.query_params = {"api_key": "sk_test_123456"}
        
        api_key = shield._extract_api_key(request)
        assert api_key == "sk_test_123456"
        
        # Test when query params not allowed
        shield.config.allow_query_param = False
        api_key = shield._extract_api_key(request)
        assert api_key is None


class TestAPIKeyRotationIntegration:
    """Integration tests with FastAPI."""
    
    @pytest.fixture
    def key_store(self):
        """Create a key store for testing."""
        return MemoryKeyStore()
    
    @pytest.fixture
    def shield_instance(self, key_store):
        """Create shield instance for testing."""
        config = APIKeyRotationConfig(enable_background_rotation=False)
        return APIKeyRotationShield(key_store=key_store, config=config)
    
    @pytest.mark.asyncio
    async def test_basic_api_key_shield(self, shield_instance):
        """Test basic API key shield integration."""
        app = FastAPI()
        
        # Create API key
        api_key, full_key = await shield_instance.create_key("client-1", auto_activate=True)
        
        @app.get("/api/protected")
        @api_key_rotation_shield(key_store=shield_instance.key_store)
        def protected_endpoint():
            return {"message": "Protected data"}
        
        client = TestClient(app)
        
        # Test without API key
        response = client.get("/api/protected")
        assert response.status_code == 401
        
        # Test with valid API key
        response = client.get(
            "/api/protected",
            headers={"X-API-Key": full_key}
        )
        assert response.status_code == 200
        assert response.json() == {"message": "Protected data"}
        
        # Test with invalid API key
        response = client.get(
            "/api/protected",
            headers={"X-API-Key": "invalid-key"}
        )
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_scoped_api_key_shield(self, shield_instance):
        """Test scoped API key shield."""
        app = FastAPI()
        
        # Create API key with scopes
        api_key, full_key = await shield_instance.create_key(
            "client-1",
            scopes=["read", "write"],
            auto_activate=True
        )
        
        @app.get("/api/read-only")
        @scoped_api_key_shield(scopes=["read"], key_store=shield_instance.key_store)
        def read_only_endpoint():
            return {"message": "Read-only data"}
        
        @app.post("/api/admin")
        @scoped_api_key_shield(scopes=["admin"], key_store=shield_instance.key_store)
        def admin_endpoint():
            return {"message": "Admin operation"}
        
        client = TestClient(app)
        
        # Test with sufficient scope
        response = client.get(
            "/api/read-only",
            headers={"X-API-Key": full_key}
        )
        assert response.status_code == 200
        
        # Test with insufficient scope
        response = client.post(
            "/api/admin",
            headers={"X-API-Key": full_key}
        )
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_admin_api_key_shield(self, shield_instance):
        """Test admin API key shield."""
        app = FastAPI()
        
        # Create admin API key
        admin_key, admin_full_key = await shield_instance.create_key(
            "admin-client",
            scopes=["admin"],
            auto_activate=True
        )
        
        # Create regular API key
        regular_key, regular_full_key = await shield_instance.create_key(
            "regular-client",
            scopes=["read"],
            auto_activate=True
        )
        
        @app.delete("/api/admin/delete")
        @admin_api_key_shield(key_store=shield_instance.key_store)
        def admin_delete_endpoint():
            return {"message": "Deleted"}
        
        client = TestClient(app)
        
        # Test with admin key
        response = client.delete(
            "/api/admin/delete",
            headers={"X-API-Key": admin_full_key}
        )
        assert response.status_code == 200
        
        # Test with regular key
        response = client.delete(
            "/api/admin/delete",
            headers={"X-API-Key": regular_full_key}
        )
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_deprecated_key_warning(self, shield_instance):
        """Test deprecated key warning headers in shield response."""
        # Create and deprecate API key
        api_key, full_key = await shield_instance.create_key("client-1", auto_activate=True)
        await shield_instance.deprecate_key(api_key.key_id)
        
        # Test shield directly returns deprecation warning data
        shield_result = await shield_instance.create_shield()._guard_func(
            Mock(headers={"X-API-Key": full_key}, client=Mock(host="127.0.0.1"))
        )
        
        assert shield_result["response_headers"]["X-API-Key-Deprecated"] == "true"
        assert "X-API-Key-Expires" in shield_result["response_headers"]
        assert shield_result["api_key_info"].status == KeyStatus.DEPRECATED


class TestConvenienceFunctions:
    """Test convenience functions for API key rotation."""
    
    def test_api_key_rotation_shield_factory(self):
        """Test API key rotation shield factory function."""
        shield = api_key_rotation_shield(
            key_header_name="Authorization",
            allow_query_param=True
        )
        assert isinstance(shield, type(api_key_rotation_shield()))
    
    def test_scoped_api_key_shield_factory(self):
        """Test scoped API key shield factory."""
        shield = scoped_api_key_shield(scopes=["read", "write"])
        assert isinstance(shield, type(api_key_rotation_shield()))
    
    def test_admin_api_key_shield_factory(self):
        """Test admin API key shield factory."""
        shield = admin_api_key_shield()
        assert isinstance(shield, type(api_key_rotation_shield()))
    
    def test_read_only_api_key_shield_factory(self):
        """Test read-only API key shield factory."""
        shield = read_only_api_key_shield()
        assert isinstance(shield, type(api_key_rotation_shield()))


class TestBackgroundTasks:
    """Test background task functionality."""
    
    @pytest.fixture
    def shield_with_background(self):
        """Create shield with background tasks enabled."""
        key_store = MemoryKeyStore()
        config = APIKeyRotationConfig(
            enable_background_rotation=True,
            rotation_check_interval=1  # 1 second for testing
        )
        return APIKeyRotationShield(key_store=key_store, config=config)
    
    @pytest.mark.asyncio
    async def test_background_task_lifecycle(self, shield_with_background):
        """Test starting and stopping background tasks."""
        # Start background tasks
        await shield_with_background.start_background_tasks()
        assert shield_with_background._background_task is not None
        
        # Stop background tasks
        await shield_with_background.stop_background_tasks()
        assert shield_with_background._background_task is None
    
    @pytest.mark.asyncio
    async def test_schedule_rotation(self, shield_with_background):
        """Test scheduling key rotation."""
        # Create key that needs rotation
        api_key, _ = await shield_with_background.create_key(
            "client-1",
            rotation_strategy=KeyRotationStrategy.USAGE_BASED,
            rotation_interval=1,  # Rotate after 1 request
            auto_activate=True
        )
        
        # Use the key to trigger rotation condition
        full_key = list(shield_with_background.key_store.key_hashes.keys())[0]
        await shield_with_background.validate_key(
            [k for k, v in shield_with_background.key_store.key_hashes.items()][0]
        )
        
        # Schedule rotation
        await shield_with_background._schedule_rotation(api_key.key_id)
        
        # Verify rotation occurred
        client_keys = await shield_with_background.get_client_keys("client-1")
        active_keys = [k for k in client_keys if k.status == KeyStatus.ACTIVE]
        deprecated_keys = [k for k in client_keys if k.status == KeyStatus.DEPRECATED]
        
        assert len(active_keys) == 1  # New key
        assert len(deprecated_keys) == 1  # Old key


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.fixture
    def shield(self):
        """Create shield for error testing."""
        return APIKeyRotationShield(key_store=MemoryKeyStore())
    
    @pytest.mark.asyncio
    async def test_create_key_missing_client(self, shield):
        """Test creating key with missing client ID."""
        with pytest.raises(TypeError):
            await shield.create_key()  # Missing required client_id
    
    @pytest.mark.asyncio
    async def test_activate_missing_key(self, shield):
        """Test activating non-existent key."""
        with pytest.raises(ValueError, match="Key .* not found"):
            await shield.activate_key("missing-key-123")
    
    @pytest.mark.asyncio
    async def test_deprecate_missing_key(self, shield):
        """Test deprecating non-existent key."""
        with pytest.raises(ValueError, match="Key .* not found"):
            await shield.deprecate_key("missing-key-123")
    
    @pytest.mark.asyncio
    async def test_revoke_missing_key(self, shield):
        """Test revoking non-existent key."""
        with pytest.raises(ValueError, match="Key .* not found"):
            await shield.revoke_key("missing-key-123")
    
    @pytest.mark.asyncio
    async def test_rotate_missing_key(self, shield):
        """Test rotating non-existent key."""
        with pytest.raises(ValueError, match="Key .* not found"):
            await shield.rotate_key("missing-key-123")
    
    @pytest.mark.asyncio
    async def test_notification_handler_error(self):
        """Test notification handler errors don't break operations."""
        # Create failing notification handler
        class FailingNotificationHandler(NotificationHandler):
            async def send_notification(self, event):
                raise Exception("Notification failed")
        
        key_store = MemoryKeyStore()
        failing_handler = FailingNotificationHandler()
        
        shield = APIKeyRotationShield(
            key_store=key_store,
            notification_handlers=[failing_handler]
        )
        
        # Operation should still succeed despite notification failure
        api_key, full_key = await shield.create_key("client-1", auto_activate=True)
        assert api_key is not None
        assert api_key.status == KeyStatus.ACTIVE


if __name__ == "__main__":
    pytest.main([__file__])