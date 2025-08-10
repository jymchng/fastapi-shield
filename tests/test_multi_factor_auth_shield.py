"""Tests for Multi-Factor Authentication Shield functionality."""

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import quote

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield.multi_factor_auth import (
    MFAShield,
    MFAConfig,
    MFASession,
    MFAChallenge,
    MFAUser,
    MFAManager,
    TOTPGenerator,
    TOTPConfig,
    SMSConfig,
    EmailConfig,
    BackupCodeConfig,
    MFAMethod,
    MFAProvider,
    MFAStatus,
    MockMFAProvider,
    multi_factor_auth_shield,
    enterprise_mfa_shield,
    flexible_mfa_shield,
)
from tests.mocks.mfa_mocks import MockSMSProvider, MockEmailProvider


class TestTOTPGenerator:
    """Test TOTP generator functionality."""
    
    def test_totp_generator_creation(self):
        """Test creating a TOTP generator."""
        config = TOTPConfig()
        generator = TOTPGenerator(config)
        
        assert generator.config == config
    
    def test_generate_secret(self):
        """Test TOTP secret generation."""
        config = TOTPConfig(secret_length=32)
        generator = TOTPGenerator(config)
        
        secret = generator.generate_secret()
        
        assert len(secret) > 0
        assert secret.replace('=', '').replace('-', '').replace('_', '').isalnum()
    
    def test_generate_code(self):
        """Test TOTP code generation."""
        config = TOTPConfig(code_length=6)
        generator = TOTPGenerator(config)
        secret = generator.generate_secret()
        
        code = generator.generate_code(secret)
        
        assert len(code) == 6
        assert code.isdigit()
    
    def test_verify_code(self):
        """Test TOTP code verification."""
        config = TOTPConfig(code_length=6, time_step=30)
        generator = TOTPGenerator(config)
        secret = generator.generate_secret()
        
        timestamp = int(time.time())
        code = generator.generate_code(secret, timestamp)
        
        # Verify the same code
        assert generator.verify_code(secret, code, timestamp)
        
        # Verify with wrong code
        assert not generator.verify_code(secret, "123456", timestamp)
    
    def test_time_window_tolerance(self):
        """Test TOTP time window tolerance."""
        config = TOTPConfig(code_length=6, time_step=30, window=1)
        generator = TOTPGenerator(config)
        secret = generator.generate_secret()
        
        base_timestamp = int(time.time())
        code = generator.generate_code(secret, base_timestamp)
        
        # Should work within same window
        assert generator.verify_code(secret, code, base_timestamp + 15)  # Same window
        
        # Should work within adjacent windows (window=1)
        prev_code = generator.generate_code(secret, base_timestamp - 30)
        next_code = generator.generate_code(secret, base_timestamp + 30)
        
        assert generator.verify_code(secret, prev_code, base_timestamp)  # Previous window code
        assert generator.verify_code(secret, next_code, base_timestamp)  # Next window code
        
        # Should not work outside window
        far_code = generator.generate_code(secret, base_timestamp + 90)
        assert not generator.verify_code(secret, far_code, base_timestamp)  # 2 windows ahead
    
    def test_qr_code_url_generation(self):
        """Test QR code URL generation."""
        config = TOTPConfig(issuer="Test App", code_length=6, time_step=30)
        generator = TOTPGenerator(config)
        secret = generator.generate_secret()
        
        url = generator.generate_qr_code_url(secret, "test@example.com")
        
        assert url.startswith("otpauth://totp/Test%20App%3Atest%40example.com?")
        # Secret might be URL encoded, so check both encoded and unencoded
        assert f"secret={secret}" in url or f"secret={quote(secret)}" in url
        assert "issuer=Test%20App" in url
        assert "digits=6" in url
        assert "period=30" in url
    
    def test_different_algorithms(self):
        """Test TOTP with different hash algorithms."""
        secret = "JBSWY3DPEHPK3PXP"  # Test secret
        timestamp = 1234567890
        
        # Test SHA1
        config_sha1 = TOTPConfig(algorithm="SHA1")
        gen_sha1 = TOTPGenerator(config_sha1)
        code_sha1 = gen_sha1.generate_code(secret, timestamp)
        
        # Test SHA256
        config_sha256 = TOTPConfig(algorithm="SHA256")
        gen_sha256 = TOTPGenerator(config_sha256)
        code_sha256 = gen_sha256.generate_code(secret, timestamp)
        
        # Test SHA512
        config_sha512 = TOTPConfig(algorithm="SHA512")
        gen_sha512 = TOTPGenerator(config_sha512)
        code_sha512 = gen_sha512.generate_code(secret, timestamp)
        
        # Codes should be different for different algorithms
        assert code_sha1 != code_sha256 != code_sha512


class TestMFAUser:
    """Test MFAUser model functionality."""
    
    def test_mfa_user_creation(self):
        """Test creating an MFA user."""
        user = MFAUser(
            user_id="test123",
            phone_number="+1234567890",
            email="test@example.com"
        )
        
        assert user.user_id == "test123"
        assert user.phone_number == "+1234567890"
        assert user.email == "test@example.com"
        assert not user.is_setup_complete
        assert user.failed_attempts == 0
        assert user.locked_until is None
        assert len(user.enabled_methods) == 0
    
    def test_user_with_methods(self):
        """Test user with enabled methods."""
        user = MFAUser(
            user_id="test123",
            enabled_methods={MFAMethod.TOTP, MFAMethod.SMS},
            totp_secret="JBSWY3DPEHPK3PXP"
        )
        
        assert MFAMethod.TOTP in user.enabled_methods
        assert MFAMethod.SMS in user.enabled_methods
        assert user.totp_secret == "JBSWY3DPEHPK3PXP"


class TestMFAManager:
    """Test MFA manager functionality."""
    
    def test_manager_creation(self):
        """Test creating MFA manager."""
        config = MFAConfig()
        provider = MockMFAProvider()
        manager = MFAManager(config, provider)
        
        assert manager.config == config
        assert manager.provider == provider
        assert len(manager.users) == 0
    
    def test_user_registration(self):
        """Test user registration."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP, MFAMethod.BACKUP_CODE})
        manager = MFAManager(config)
        
        user = manager.register_user("test123", "+1234567890", "test@example.com")
        
        assert user.user_id == "test123"
        assert user.phone_number == "+1234567890"
        assert user.email == "test@example.com"
        assert user.totp_secret is not None
        assert len(user.backup_codes) > 0
        assert user.is_setup_complete
        assert MFAMethod.TOTP in user.enabled_methods
        assert MFAMethod.BACKUP_CODE in user.enabled_methods
    
    def test_get_user(self):
        """Test getting user by ID."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        # User doesn't exist
        assert manager.get_user("nonexistent") is None
        
        # Register and get user
        user = manager.register_user("test123")
        retrieved = manager.get_user("test123")
        
        assert retrieved == user
    
    @pytest.mark.asyncio
    async def test_create_totp_challenge(self):
        """Test creating TOTP challenge."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        challenge = await manager.create_challenge("test123", MFAMethod.TOTP)
        
        assert challenge.user_id == "test123"
        assert challenge.method == MFAMethod.TOTP
        assert challenge.status == MFAStatus.PENDING
        assert challenge.code is None  # TOTP doesn't generate stored codes
    
    @pytest.mark.asyncio
    async def test_create_sms_challenge(self):
        """Test creating SMS challenge."""
        sms_config = SMSConfig(
            provider="mock", 
            api_key="test", 
            from_number="+1234567890",
            code_length=6
        )
        config = MFAConfig(enabled_methods={MFAMethod.SMS}, sms_config=sms_config)
        provider = MockSMSProvider()
        manager = MFAManager(config, provider)
        
        user = manager.register_user("test123", "+1987654321")
        user.enabled_methods.add(MFAMethod.SMS)  # Enable SMS for user
        
        challenge = await manager.create_challenge("test123", MFAMethod.SMS)
        
        assert challenge.method == MFAMethod.SMS
        assert challenge.code is not None
        assert len(challenge.code) == 6
        assert len(provider.sent_messages) == 1
        assert provider.sent_messages[0]['phone'] == "+1987654321"
    
    @pytest.mark.asyncio
    async def test_create_email_challenge(self):
        """Test creating email challenge."""
        email_config = EmailConfig(
            provider="mock",
            username="test",
            password="test",
            from_email="noreply@example.com",
            code_length=8
        )
        config = MFAConfig(enabled_methods={MFAMethod.EMAIL}, email_config=email_config)
        provider = MockEmailProvider()
        manager = MFAManager(config, provider)
        
        user = manager.register_user("test123", email="test@example.com")
        user.enabled_methods.add(MFAMethod.EMAIL)  # Enable email for user
        
        challenge = await manager.create_challenge("test123", MFAMethod.EMAIL)
        
        assert challenge.method == MFAMethod.EMAIL
        assert challenge.code is not None
        assert len(challenge.code) == 8
        assert len(provider.sent_emails) == 1
        assert provider.sent_emails[0]['email'] == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_challenge_for_nonexistent_user(self):
        """Test creating challenge for nonexistent user."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        with pytest.raises(HTTPException) as exc_info:
            await manager.create_challenge("nonexistent", MFAMethod.TOTP)
        
        assert exc_info.value.status_code == 404
    
    @pytest.mark.asyncio
    async def test_challenge_for_disabled_method(self):
        """Test creating challenge for disabled method."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        
        with pytest.raises(HTTPException) as exc_info:
            await manager.create_challenge("test123", MFAMethod.SMS)
        
        assert exc_info.value.status_code == 400
    
    @pytest.mark.asyncio
    async def test_verify_totp_challenge(self):
        """Test verifying TOTP challenge."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        challenge = await manager.create_challenge("test123", MFAMethod.TOTP)
        
        # Generate correct code
        correct_code = manager.totp_generator.generate_code(user.totp_secret)
        
        # Verify correct code
        result = await manager.verify_challenge(challenge.challenge_id, correct_code)
        assert result is True
        assert challenge.status == MFAStatus.AUTHENTICATED
    
    @pytest.mark.asyncio
    async def test_verify_sms_challenge(self):
        """Test verifying SMS challenge."""
        sms_config = SMSConfig(
            provider="mock", 
            api_key="test", 
            from_number="+1234567890"
        )
        config = MFAConfig(enabled_methods={MFAMethod.SMS}, sms_config=sms_config)
        provider = MockSMSProvider()
        manager = MFAManager(config, provider)
        
        user = manager.register_user("test123", "+1987654321")
        user.enabled_methods.add(MFAMethod.SMS)
        
        challenge = await manager.create_challenge("test123", MFAMethod.SMS)
        sent_code = provider.get_last_code()
        
        # Verify correct code
        result = await manager.verify_challenge(challenge.challenge_id, sent_code)
        assert result is True
        assert challenge.status == MFAStatus.AUTHENTICATED
    
    @pytest.mark.asyncio
    async def test_verify_backup_code_challenge(self):
        """Test verifying backup code challenge."""
        config = MFAConfig(enabled_methods={MFAMethod.BACKUP_CODE})
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        backup_code = user.backup_codes[0]  # Use first backup code
        
        challenge = await manager.create_challenge("test123", MFAMethod.BACKUP_CODE)
        
        # Verify backup code
        result = await manager.verify_challenge(challenge.challenge_id, backup_code)
        assert result is True
        assert challenge.status == MFAStatus.AUTHENTICATED
        
        # Code should be removed after use (if reuse is disabled)
        if not config.backup_code_config.allow_reuse:
            assert backup_code not in user.backup_codes
    
    @pytest.mark.asyncio
    async def test_verify_wrong_code(self):
        """Test verifying wrong code."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        challenge = await manager.create_challenge("test123", MFAMethod.TOTP)
        
        # Verify wrong code
        result = await manager.verify_challenge(challenge.challenge_id, "000000")
        assert result is False
        assert challenge.status == MFAStatus.FAILED
        assert challenge.attempts == 1
    
    @pytest.mark.asyncio
    async def test_too_many_attempts(self):
        """Test too many verification attempts."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP}, max_attempts=2)
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        challenge = await manager.create_challenge("test123", MFAMethod.TOTP)
        
        # First failed attempt
        result1 = await manager.verify_challenge(challenge.challenge_id, "000000")
        assert result1 is False
        assert challenge.attempts == 1
        
        # Second failed attempt - should still work but increment attempts
        result2 = await manager.verify_challenge(challenge.challenge_id, "000000")
        assert result2 is False
        assert challenge.attempts == 2
        
        # Third attempt - should now lock user
        with pytest.raises(HTTPException) as exc_info:
            await manager.verify_challenge(challenge.challenge_id, "000000")
        
        assert exc_info.value.status_code == 423  # Locked
        assert challenge.attempts == 3
        assert user.locked_until is not None
    
    @pytest.mark.asyncio
    async def test_expired_challenge(self):
        """Test expired challenge verification."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        challenge = await manager.create_challenge("test123", MFAMethod.TOTP)
        
        # Manually expire the challenge
        challenge.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        with pytest.raises(HTTPException) as exc_info:
            await manager.verify_challenge(challenge.challenge_id, "123456")
        
        assert exc_info.value.status_code == 410  # Gone
    
    def test_session_creation(self):
        """Test MFA session creation."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        session = manager.create_session("test123")
        
        assert session.user_id == "test123"
        assert not session.authenticated
        assert len(session.methods_completed) == 0
        assert session.session_id in manager.sessions
    
    def test_session_authentication(self):
        """Test session authentication."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        session = manager.create_session("test123")
        
        # Authenticate with TOTP
        manager.authenticate_session(session.session_id, MFAMethod.TOTP)
        
        assert MFAMethod.TOTP in session.methods_completed
        assert session.authenticated  # Should be authenticated since TOTP is the only required method
    
    def test_session_expiry(self):
        """Test session expiry."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        session = manager.create_session("test123")
        session_id = session.session_id
        
        # Manually expire session
        session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        # Getting expired session should return None and remove it
        retrieved = manager.get_session(session_id)
        assert retrieved is None
        assert session_id not in manager.sessions


class TestMFAShield:
    """Test MFA shield functionality."""
    
    def test_shield_creation(self):
        """Test creating MFA shield."""
        config = MFAConfig()
        shield = MFAShield(config)
        
        assert shield.config == config
        assert shield.mfa_manager is not None
    
    @pytest.mark.asyncio
    async def test_shield_without_session(self):
        """Test shield behavior without session."""
        config = MFAConfig()
        shield = MFAShield(config)
        
        # Mock request without session
        request = Mock()
        request.headers = {}
        request.cookies = {}
        
        result = await shield._mfa_guard(request)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_shield_with_invalid_session(self):
        """Test shield behavior with invalid session."""
        config = MFAConfig()
        shield = MFAShield(config)
        
        # Mock request with invalid session
        request = Mock()
        request.headers = {"X-MFA-Session": "invalid-session"}
        request.cookies = {}
        
        result = await shield._mfa_guard(request)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_shield_with_valid_session(self):
        """Test shield behavior with valid authenticated session."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        shield = MFAShield(config)
        
        # Create user and authenticated session
        user = shield.mfa_manager.register_user("test123")
        session = shield.mfa_manager.create_session("test123")
        session.authenticated = True
        session.methods_completed.add(MFAMethod.TOTP)
        
        # Mock request with valid session
        request = Mock()
        request.headers = {"X-MFA-Session": session.session_id}
        request.cookies = {}
        
        result = await shield._mfa_guard(request)
        
        assert result is not None
        assert result['user_id'] == "test123"
        assert result['session_id'] == session.session_id
        assert MFAMethod.TOTP in result['mfa_methods']


class TestConvenienceFunctions:
    """Test convenience shield creation functions."""
    
    def test_basic_mfa_shield(self):
        """Test basic MFA shield creation."""
        shield = multi_factor_auth_shield()
        
        assert isinstance(shield, MFAShield)
        assert shield.config.enabled_methods == {MFAMethod.TOTP}
    
    def test_enterprise_mfa_shield(self):
        """Test enterprise MFA shield creation."""
        shield = enterprise_mfa_shield(
            enabled_methods={MFAMethod.TOTP, MFAMethod.BACKUP_CODE},
            session_timeout_minutes=30
        )
        
        assert isinstance(shield, MFAShield)
        assert shield.config.enabled_methods == {MFAMethod.TOTP, MFAMethod.BACKUP_CODE}
        assert shield.config.session_timeout_minutes == 30
        assert shield.config.max_attempts == 3
        assert shield.config.require_setup is True
    
    def test_flexible_mfa_shield(self):
        """Test flexible MFA shield creation."""
        shield = flexible_mfa_shield(
            require_setup=False,
            session_timeout_minutes=120
        )
        
        assert isinstance(shield, MFAShield)
        assert shield.config.session_timeout_minutes == 120
        assert shield.config.require_setup is False
        assert shield.config.max_attempts == 5


class TestIntegration:
    """Integration tests with FastAPI."""
    
    def test_mfa_shield_integration(self):
        """Test MFA shield integration with FastAPI."""
        app = FastAPI()
        
        # Create shield with test configuration
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        shield = MFAShield(config)
        
        @app.get("/protected")
        @shield
        def protected_endpoint():
            return {"message": "Protected content"}
        
        @app.get("/public")
        def public_endpoint():
            return {"message": "Public content"}
        
        client = TestClient(app)
        
        # Test access without authentication
        response = client.get("/protected")
        assert response.status_code == 401
        
        # Test public endpoint
        response = client.get("/public")
        assert response.status_code == 200
        assert response.json()["message"] == "Public content"
    
    def test_mfa_shield_with_valid_session(self):
        """Test MFA shield with valid session in FastAPI."""
        app = FastAPI()
        
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        shield = MFAShield(config)
        
        # Setup user and session
        user = shield.mfa_manager.register_user("test123")
        session = shield.mfa_manager.create_session("test123")
        session.authenticated = True
        session.methods_completed.add(MFAMethod.TOTP)
        
        @app.get("/protected")
        @shield
        def protected_endpoint():
            return {"message": "Protected content"}
        
        client = TestClient(app)
        
        # Test with valid session header
        response = client.get(
            "/protected",
            headers={"X-MFA-Session": session.session_id}
        )
        
        assert response.status_code == 200
        assert response.json()["message"] == "Protected content"


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.mark.asyncio
    async def test_locked_user_challenge_creation(self):
        """Test challenge creation for locked user."""
        config = MFAConfig(enabled_methods={MFAMethod.TOTP})
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
        
        with pytest.raises(HTTPException) as exc_info:
            await manager.create_challenge("test123", MFAMethod.TOTP)
        
        assert exc_info.value.status_code == 423
    
    @pytest.mark.asyncio
    async def test_backup_code_reuse_allowed(self):
        """Test backup code reuse when allowed."""
        backup_config = BackupCodeConfig(allow_reuse=True)
        config = MFAConfig(
            enabled_methods={MFAMethod.BACKUP_CODE},
            backup_code_config=backup_config
        )
        manager = MFAManager(config)
        
        user = manager.register_user("test123")
        original_codes = user.backup_codes.copy()
        
        # Use backup code multiple times
        for i in range(3):
            challenge = manager.challenges[f"test{i}"] = MFAChallenge(
                challenge_id=f"test{i}",
                user_id="test123",
                method=MFAMethod.BACKUP_CODE,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
            )
            
            # Should work multiple times since reuse is allowed
            result = await manager.verify_challenge(f"test{i}", original_codes[0])
            assert result is True
            
        # Codes should still be present
        assert original_codes[0] in user.backup_codes
    
    def test_totp_different_code_lengths(self):
        """Test TOTP with different code lengths."""
        for length in [4, 6, 8]:
            config = TOTPConfig(code_length=length)
            generator = TOTPGenerator(config)
            secret = generator.generate_secret()
            
            code = generator.generate_code(secret)
            
            assert len(code) == length
            assert code.isdigit()
            assert generator.verify_code(secret, code)
    
    def test_session_cleanup_on_expiry(self):
        """Test that expired sessions are cleaned up."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        # Create multiple sessions
        session1 = manager.create_session("user1")
        session2 = manager.create_session("user2")
        
        # Expire first session
        session1.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        # Access sessions - expired one should be removed
        assert manager.get_session(session1.session_id) is None
        assert manager.get_session(session2.session_id) is not None
        
        # First session should be removed from storage
        assert session1.session_id not in manager.sessions
        assert session2.session_id in manager.sessions