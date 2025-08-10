"""Tests for Multi-Factor Authentication shield."""

import asyncio
import base64
import json
import pytest
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from unittest.mock import Mock, AsyncMock, patch, MagicMock

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
    CodeGenerator,
    MockMFAProvider,
    multi_factor_auth_shield,
    enterprise_mfa_shield,
    flexible_mfa_shield,
)


class TestTOTPConfig:
    """Test TOTP configuration."""
    
    def test_basic_totp_config(self):
        """Test basic TOTP configuration."""
        config = TOTPConfig()
        
        assert config.issuer == "FastAPI Shield"
        assert config.algorithm == "SHA1"
        assert config.digits == 6
        assert config.period == 30
        assert config.window == 1
        assert config.secret_length == 32
    
    def test_custom_totp_config(self):
        """Test custom TOTP configuration."""
        config = TOTPConfig(
            issuer="My App",
            algorithm="SHA256",
            digits=8,
            period=60,
            window=2,
            secret_length=64
        )
        
        assert config.issuer == "My App"
        assert config.algorithm == "SHA256"
        assert config.digits == 8
        assert config.period == 60
        assert config.window == 2
        assert config.secret_length == 64


class TestMFAConfig:
    """Test MFA configuration."""
    
    def test_basic_mfa_config(self):
        """Test basic MFA configuration."""
        config = MFAConfig()
        
        assert MFAMethod.TOTP in config.required_methods
        assert MFAMethod.SMS in config.optional_methods
        assert config.max_attempts == 3
        assert config.lockout_duration == 900
        assert config.session_duration == 3600
    
    def test_custom_mfa_config(self):
        """Test custom MFA configuration."""
        config = MFAConfig(
            required_methods=[MFAMethod.TOTP, MFAMethod.SMS],
            optional_methods=[MFAMethod.EMAIL, MFAMethod.BACKUP_CODE],
            max_attempts=5,
            lockout_duration=1800,
            session_duration=7200,
            enforce_setup=True
        )
        
        assert config.required_methods == [MFAMethod.TOTP, MFAMethod.SMS]
        assert config.optional_methods == [MFAMethod.EMAIL, MFAMethod.BACKUP_CODE]
        assert config.max_attempts == 5
        assert config.lockout_duration == 1800
        assert config.session_duration == 7200
        assert config.enforce_setup is True
    
    def test_mfa_config_validation_empty_methods(self):
        """Test MFA config validation with empty methods."""
        with pytest.raises(ValueError, match="At least one MFA method must be configured"):
            MFAConfig(required_methods=[], optional_methods=[])


class TestTOTPGenerator:
    """Test TOTP generator."""
    
    @pytest.fixture
    def totp_config(self):
        """Basic TOTP configuration."""
        return TOTPConfig()
    
    @pytest.fixture
    def totp_generator(self, totp_config):
        """TOTP generator instance."""
        return TOTPGenerator(totp_config)
    
    def test_totp_generator_initialization(self, totp_generator):
        """Test TOTP generator initialization."""
        assert totp_generator.config is not None
        assert 'SHA1' in totp_generator._algorithm_map
        assert 'SHA256' in totp_generator._algorithm_map
        assert 'SHA512' in totp_generator._algorithm_map
    
    def test_generate_secret(self, totp_generator):
        """Test secret generation."""
        secret1 = totp_generator.generate_secret()
        secret2 = totp_generator.generate_secret()
        
        assert len(secret1) > 0
        assert len(secret2) > 0
        assert secret1 != secret2
        # Base32 characters
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=' for c in secret1)
    
    def test_generate_code(self, totp_generator):
        """Test TOTP code generation."""
        secret = "JBSWY3DPEHPK3PXP"  # Standard test secret
        timestamp = 1234567890  # Fixed timestamp
        
        code = totp_generator.generate_code(secret, timestamp)
        
        assert len(code) == 6
        assert code.isdigit()
        
        # Should be deterministic
        code2 = totp_generator.generate_code(secret, timestamp)
        assert code == code2
    
    def test_verify_code_success(self, totp_generator):
        """Test successful TOTP code verification."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1234567890
        
        code = totp_generator.generate_code(secret, timestamp)
        verified = totp_generator.verify_code(secret, code, timestamp)
        
        assert verified is True
    
    def test_verify_code_failure(self, totp_generator):
        """Test failed TOTP code verification."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1234567890
        
        verified = totp_generator.verify_code(secret, "000000", timestamp)
        assert verified is False
    
    def test_verify_code_time_window(self, totp_generator):
        """Test TOTP code verification with time window."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1234567890
        
        # Generate code for previous time window
        prev_code = totp_generator.generate_code(secret, timestamp - 30)
        
        # Should verify within window
        verified = totp_generator.verify_code(secret, prev_code, timestamp)
        assert verified is True
    
    def test_generate_qr_url(self, totp_generator):
        """Test QR URL generation."""
        secret = "JBSWY3DPEHPK3PXP"
        account = "user@example.com"
        
        url = totp_generator.generate_qr_url(secret, account)
        
        assert url.startswith("otpauth://totp/")
        assert secret in url
        assert "user%40example.com" in url or "user@example.com" in url
        assert "FastAPI%20Shield" in url or "FastAPI Shield" in url
    
    def test_invalid_secret(self, totp_generator):
        """Test handling of invalid secret."""
        with pytest.raises(ValueError, match="Invalid TOTP secret"):
            totp_generator.generate_code("invalid_secret", 1234567890)


class TestCodeGenerator:
    """Test code generator utilities."""
    
    def test_generate_numeric_code(self):
        """Test numeric code generation."""
        code = CodeGenerator.generate_numeric_code(6)
        
        assert len(code) == 6
        assert code.isdigit()
        
        # Different calls should produce different codes
        code2 = CodeGenerator.generate_numeric_code(6)
        assert code != code2
    
    def test_generate_alphanumeric_code(self):
        """Test alphanumeric code generation."""
        code = CodeGenerator.generate_alphanumeric_code(8)
        
        assert len(code) == 8
        assert code.isalnum()
        assert code.isupper()
        
        code2 = CodeGenerator.generate_alphanumeric_code(8)
        assert code != code2
    
    def test_generate_backup_codes(self):
        """Test backup codes generation."""
        codes = CodeGenerator.generate_backup_codes(10, 8, True)
        
        assert len(codes) == 10
        for code in codes:
            assert len(code) == 9  # 8 chars + 1 dash
            assert '-' in code
        
        # All codes should be unique
        assert len(set(codes)) == 10
    
    def test_generate_backup_codes_no_dashes(self):
        """Test backup codes generation without dashes."""
        codes = CodeGenerator.generate_backup_codes(5, 6, False)
        
        assert len(codes) == 5
        for code in codes:
            assert len(code) == 6
            assert '-' not in code


class TestMockMFAProvider:
    """Test mock MFA provider."""
    
    @pytest.fixture
    def provider(self):
        """Mock MFA provider instance."""
        return MockMFAProvider()
    
    @pytest.mark.asyncio
    async def test_send_sms(self, provider):
        """Test mock SMS sending."""
        result = await provider.send_sms("1234567890", "123456", "Code: {code}")
        
        assert result is True
        assert len(provider.sent_messages) == 1
        
        message = provider.sent_messages[0]
        assert message['type'] == 'sms'
        assert message['to'] == "1234567890"
        assert message['code'] == "123456"
        assert "123456" in message['message']
    
    @pytest.mark.asyncio
    async def test_send_email(self, provider):
        """Test mock email sending."""
        result = await provider.send_email(
            "test@example.com", 
            "ABC123", 
            "Verification Code",
            "Your code is: {code}"
        )
        
        assert result is True
        assert len(provider.sent_messages) == 1
        
        message = provider.sent_messages[0]
        assert message['type'] == 'email'
        assert message['to'] == "test@example.com"
        assert message['subject'] == "Verification Code"
        assert message['code'] == "ABC123"
        assert "ABC123" in message['message']
    
    def test_get_last_code(self, provider):
        """Test getting last sent code."""
        # No messages yet
        code = provider.get_last_code('sms', '1234567890')
        assert code is None
        
        # Add a message
        provider.sent_messages.append({
            'type': 'sms',
            'to': '1234567890',
            'code': '123456',
            'timestamp': time.time()
        })
        
        code = provider.get_last_code('sms', '1234567890')
        assert code == '123456'
        
        # Wrong recipient
        code = provider.get_last_code('sms', '0987654321')
        assert code is None


class TestMFASession:
    """Test MFA session."""
    
    def test_mfa_session_creation(self):
        """Test MFA session creation."""
        session = MFASession(
            user_id="user123",
            methods_required=[MFAMethod.TOTP, MFAMethod.SMS],
            expires_at=time.time() + 3600
        )
        
        assert session.user_id == "user123"
        assert session.methods_required == [MFAMethod.TOTP, MFAMethod.SMS]
        assert len(session.session_id) > 0
        assert session.is_complete is False
        assert session.is_expired() is False
    
    def test_session_expiry(self):
        """Test session expiry check."""
        session = MFASession(
            user_id="user123",
            expires_at=time.time() - 100  # Already expired
        )
        
        assert session.is_expired() is True
    
    def test_method_verification(self):
        """Test method verification tracking."""
        session = MFASession(
            user_id="user123",
            methods_required=[MFAMethod.TOTP, MFAMethod.SMS],
            expires_at=time.time() + 3600
        )
        
        assert session.is_method_verified(MFAMethod.TOTP) is False
        
        session.methods_verified.append(MFAMethod.TOTP)
        assert session.is_method_verified(MFAMethod.TOTP) is True
    
    def test_lockout_check(self):
        """Test method lockout check."""
        session = MFASession(
            user_id="user123",
            expires_at=time.time() + 3600
        )
        
        assert session.is_locked_out(MFAMethod.TOTP, 3) is False
        
        session.attempts[MFAMethod.TOTP] = 3
        assert session.is_locked_out(MFAMethod.TOTP, 3) is True


class TestMFAChallenge:
    """Test MFA challenge."""
    
    def test_mfa_challenge_creation(self):
        """Test MFA challenge creation."""
        challenge = MFAChallenge(
            method=MFAMethod.SMS,
            user_id="user123",
            session_id="session456",
            code="123456",
            expires_at=time.time() + 300
        )
        
        assert challenge.method == MFAMethod.SMS
        assert challenge.user_id == "user123"
        assert challenge.session_id == "session456"
        assert challenge.code == "123456"
        assert challenge.is_expired() is False
        assert challenge.is_used is False
    
    def test_challenge_expiry(self):
        """Test challenge expiry check."""
        challenge = MFAChallenge(
            method=MFAMethod.SMS,
            user_id="user123",
            session_id="session456",
            expires_at=time.time() - 100  # Already expired
        )
        
        assert challenge.is_expired() is True


class TestMFAUser:
    """Test MFA user."""
    
    def test_mfa_user_creation(self):
        """Test MFA user creation."""
        user = MFAUser(user_id="user123")
        
        assert user.user_id == "user123"
        assert len(user.enabled_methods) == 0
        assert user.totp_secret is None
        assert user.phone_number is None
        assert user.email is None
        assert len(user.backup_codes) == 0
        assert user.setup_completed is False
        assert user.setup_required is True
    
    def test_user_method_enablement(self):
        """Test enabling MFA methods for user."""
        user = MFAUser(user_id="user123")
        
        user.enabled_methods[MFAMethod.TOTP] = True
        user.enabled_methods[MFAMethod.SMS] = False
        
        assert user.enabled_methods[MFAMethod.TOTP] is True
        assert user.enabled_methods[MFAMethod.SMS] is False


class TestMFAManager:
    """Test MFA manager."""
    
    @pytest.fixture
    def mfa_config(self):
        """Basic MFA configuration."""
        return MFAConfig(
            required_methods=[MFAMethod.TOTP],
            optional_methods=[MFAMethod.SMS, MFAMethod.EMAIL],
            max_attempts=3,
            session_duration=3600
        )
    
    @pytest.fixture
    def mfa_manager(self, mfa_config):
        """MFA manager instance."""
        return MFAManager(mfa_config)
    
    def test_manager_initialization(self, mfa_manager):
        """Test MFA manager initialization."""
        assert mfa_manager.config is not None
        assert isinstance(mfa_manager.totp_generator, TOTPGenerator)
        assert isinstance(mfa_manager.provider, MockMFAProvider)
        assert isinstance(mfa_manager.sessions, dict)
        assert isinstance(mfa_manager.challenges, dict)
        assert isinstance(mfa_manager.users, dict)
    
    def test_get_user(self, mfa_manager):
        """Test getting/creating MFA user."""
        user = mfa_manager.get_user("user123")
        
        assert user.user_id == "user123"
        assert "user123" in mfa_manager.users
        
        # Should return same user on subsequent calls
        user2 = mfa_manager.get_user("user123")
        assert user is user2
    
    def test_user_lockout(self, mfa_manager):
        """Test user lockout functionality."""
        user_id = "user123"
        
        assert mfa_manager.is_user_locked_out(user_id) is False
        
        mfa_manager.lockout_user(user_id)
        assert mfa_manager.is_user_locked_out(user_id) is True
        
        # Mock expiry by setting past time
        mfa_manager.lockouts[user_id] = time.time() - 100
        assert mfa_manager.is_user_locked_out(user_id) is False
    
    @pytest.mark.asyncio
    async def test_setup_totp(self, mfa_manager):
        """Test TOTP setup."""
        setup_info = await mfa_manager.setup_totp("user123")
        
        assert 'secret' in setup_info
        assert 'qr_url' in setup_info
        assert 'backup_url' in setup_info
        
        # User should have TOTP enabled
        user = mfa_manager.get_user("user123")
        assert user.enabled_methods[MFAMethod.TOTP] is True
        assert user.totp_secret == setup_info['secret']
        
        # QR URL should be valid
        assert setup_info['qr_url'].startswith('otpauth://totp/')
        # Check URL-encoded secret is in QR URL
        import urllib.parse
        encoded_secret = urllib.parse.quote(setup_info['secret'])
        assert encoded_secret in setup_info['qr_url']
    
    @pytest.mark.asyncio
    async def test_setup_sms(self, mfa_manager):
        """Test SMS setup."""
        result = await mfa_manager.setup_sms("user123", "1234567890")
        
        assert result is True
        
        user = mfa_manager.get_user("user123")
        assert user.enabled_methods[MFAMethod.SMS] is True
        assert user.phone_number == "1234567890"
    
    @pytest.mark.asyncio
    async def test_setup_email(self, mfa_manager):
        """Test email setup."""
        result = await mfa_manager.setup_email("user123", "test@example.com")
        
        assert result is True
        
        user = mfa_manager.get_user("user123")
        assert user.enabled_methods[MFAMethod.EMAIL] is True
        assert user.email == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_generate_backup_codes(self, mfa_manager):
        """Test backup codes generation."""
        codes = await mfa_manager.generate_backup_codes("user123")
        
        assert len(codes) == 10  # Default count
        assert all(len(code) == 9 for code in codes)  # 8 chars + dash
        assert len(set(codes)) == 10  # All unique
        
        user = mfa_manager.get_user("user123")
        assert user.enabled_methods[MFAMethod.BACKUP_CODE] is True
        assert user.backup_codes == codes
    
    @pytest.mark.asyncio
    async def test_start_mfa_session(self, mfa_manager):
        """Test starting MFA session."""
        # Setup user with TOTP
        await mfa_manager.setup_totp("user123")
        
        session = await mfa_manager.start_mfa_session("user123")
        
        assert session.user_id == "user123"
        assert MFAMethod.TOTP in session.methods_required
        assert session.is_complete is False
        assert session.session_id in mfa_manager.sessions
    
    @pytest.mark.asyncio
    async def test_start_session_locked_user(self, mfa_manager):
        """Test starting session for locked user."""
        user_id = "user123"
        mfa_manager.lockout_user(user_id)
        
        with pytest.raises(HTTPException) as exc_info:
            await mfa_manager.start_mfa_session(user_id)
        
        assert exc_info.value.status_code == 429
        assert "temporarily locked" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_totp_challenge(self, mfa_manager):
        """Test creating TOTP challenge."""
        # Setup and start session
        await mfa_manager.setup_totp("user123")
        session = await mfa_manager.start_mfa_session("user123")
        
        challenge = await mfa_manager.create_challenge(session.session_id, MFAMethod.TOTP)
        
        assert challenge.method == MFAMethod.TOTP
        assert challenge.user_id == "user123"
        assert challenge.session_id == session.session_id
        assert challenge.challenge_id in mfa_manager.challenges
    
    @pytest.mark.asyncio
    async def test_create_sms_challenge(self, mfa_manager):
        """Test creating SMS challenge."""
        # Setup and start session
        await mfa_manager.setup_sms("user123", "1234567890")
        session = await mfa_manager.start_mfa_session("user123")
        
        challenge = await mfa_manager.create_challenge(session.session_id, MFAMethod.SMS)
        
        assert challenge.method == MFAMethod.SMS
        assert challenge.code is not None
        assert len(challenge.code) == 6
        
        # Should have sent SMS
        last_code = mfa_manager.provider.get_last_code('sms', '1234567890')
        assert last_code == challenge.code
    
    @pytest.mark.asyncio
    async def test_verify_totp_challenge(self, mfa_manager):
        """Test verifying TOTP challenge."""
        # Setup user and session
        setup_info = await mfa_manager.setup_totp("user123")
        session = await mfa_manager.start_mfa_session("user123")
        challenge = await mfa_manager.create_challenge(session.session_id, MFAMethod.TOTP)
        
        # Generate valid TOTP code
        code = mfa_manager.totp_generator.generate_code(setup_info['secret'])
        
        result = await mfa_manager.verify_challenge(challenge.challenge_id, code)
        
        assert result is True
        assert challenge.is_used is True
        
        # Session should be updated
        updated_session = mfa_manager.get_session(session.session_id)
        assert MFAMethod.TOTP in updated_session.methods_verified
    
    @pytest.mark.asyncio
    async def test_verify_sms_challenge(self, mfa_manager):
        """Test verifying SMS challenge."""
        # Setup user and session
        await mfa_manager.setup_sms("user123", "1234567890")
        session = await mfa_manager.start_mfa_session("user123")
        challenge = await mfa_manager.create_challenge(session.session_id, MFAMethod.SMS)
        
        result = await mfa_manager.verify_challenge(challenge.challenge_id, challenge.code)
        
        assert result is True
        assert challenge.is_used is True
    
    @pytest.mark.asyncio
    async def test_verify_backup_code(self, mfa_manager):
        """Test verifying backup code."""
        # Setup user with backup codes
        codes = await mfa_manager.generate_backup_codes("user123")
        session = await mfa_manager.start_mfa_session("user123")
        challenge = await mfa_manager.create_challenge(session.session_id, MFAMethod.BACKUP_CODE)
        
        # Use first backup code
        backup_code = codes[0]
        result = await mfa_manager.verify_challenge(challenge.challenge_id, backup_code)
        
        assert result is True
        
        # Code should be consumed
        user = mfa_manager.get_user("user123")
        assert backup_code not in user.backup_codes
    
    @pytest.mark.asyncio
    async def test_verify_invalid_challenge(self, mfa_manager):
        """Test verifying invalid challenge."""
        result = await mfa_manager.verify_challenge("invalid_id", "123456")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_session_completion(self, mfa_manager):
        """Test MFA session completion."""
        # Setup user with single required method
        await mfa_manager.setup_totp("user123")
        session = await mfa_manager.start_mfa_session("user123")
        
        assert session.is_complete is False
        
        # Complete TOTP verification
        setup_info = await mfa_manager.setup_totp("user123")
        challenge = await mfa_manager.create_challenge(session.session_id, MFAMethod.TOTP)
        code = mfa_manager.totp_generator.generate_code(setup_info['secret'])
        
        await mfa_manager.verify_challenge(challenge.challenge_id, code)
        
        # Session should now be complete
        updated_session = mfa_manager.get_session(session.session_id)
        assert updated_session.is_complete is True
    
    @pytest.mark.asyncio
    async def test_cleanup_expired(self, mfa_manager):
        """Test cleanup of expired sessions and challenges."""
        # Create expired session
        expired_session = MFASession(
            user_id="user123",
            expires_at=time.time() - 100
        )
        mfa_manager.sessions[expired_session.session_id] = expired_session
        
        # Create expired challenge
        expired_challenge = MFAChallenge(
            method=MFAMethod.SMS,
            user_id="user123",
            session_id="session456",
            expires_at=time.time() - 100
        )
        mfa_manager.challenges[expired_challenge.challenge_id] = expired_challenge
        
        assert len(mfa_manager.sessions) == 1
        assert len(mfa_manager.challenges) == 1
        
        await mfa_manager.cleanup_expired()
        
        assert len(mfa_manager.sessions) == 0
        assert len(mfa_manager.challenges) == 0


class TestMFAShield:
    """Test MFA shield."""
    
    @pytest.fixture
    def mfa_config(self):
        """MFA shield configuration."""
        return MFAConfig(
            required_methods=[MFAMethod.TOTP],
            session_duration=3600
        )
    
    def create_test_app(self, config):
        """Create test FastAPI application."""
        app = FastAPI()
        shield = MFAShield(config)
        shield_func = shield.create_shield("TestMFA")
        
        @app.get("/protected")
        @shield_func
        def protected_endpoint():
            return {"message": "MFA verified"}
        
        @app.get("/public")
        def public_endpoint():
            return {"message": "Public access"}
        
        return app, shield
    
    def test_protected_endpoint_without_session(self, mfa_config):
        """Test protected endpoint without MFA session."""
        app, shield = self.create_test_app(mfa_config)
        
        with TestClient(app) as client:
            response = client.get("/protected")
            assert response.status_code == 401
            assert "MFA session required" in response.json()["detail"]
            assert "X-MFA-Required" in response.headers
    
    def test_protected_endpoint_invalid_session(self, mfa_config):
        """Test protected endpoint with invalid MFA session."""
        app, shield = self.create_test_app(mfa_config)
        
        with TestClient(app) as client:
            response = client.get("/protected", headers={
                "X-MFA-Session": "invalid-session-id"
            })
            assert response.status_code == 401
            assert "Invalid or expired MFA session" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_incomplete_session(self, mfa_config):
        """Test protected endpoint with incomplete MFA session."""
        app, shield = self.create_test_app(mfa_config)
        manager = shield.get_manager()
        
        # Setup user and create incomplete session
        await manager.setup_totp("user123")
        session = await manager.start_mfa_session("user123")
        
        with TestClient(app) as client:
            response = client.get("/protected", headers={
                "X-MFA-Session": session.session_id
            })
            assert response.status_code == 401
            assert "MFA verification incomplete" in response.json()["detail"]
            assert "X-MFA-Methods-Required" in response.headers
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_complete_session(self, mfa_config):
        """Test protected endpoint with complete MFA session."""
        app, shield = self.create_test_app(mfa_config)
        manager = shield.get_manager()
        
        # Setup and complete MFA
        setup_info = await manager.setup_totp("user123")
        session = await manager.start_mfa_session("user123")
        challenge = await manager.create_challenge(session.session_id, MFAMethod.TOTP)
        
        # Generate and verify TOTP code
        code = manager.totp_generator.generate_code(setup_info['secret'])
        await manager.verify_challenge(challenge.challenge_id, code)
        
        with TestClient(app) as client:
            response = client.get("/protected", headers={
                "X-MFA-Session": session.session_id
            })
            assert response.status_code == 200
            assert response.json() == {"message": "MFA verified"}
    
    def test_public_endpoint_access(self, mfa_config):
        """Test public endpoint access."""
        app, shield = self.create_test_app(mfa_config)
        
        with TestClient(app) as client:
            response = client.get("/public")
            assert response.status_code == 200
            assert response.json() == {"message": "Public access"}


class TestConvenienceFunctions:
    """Test MFA convenience functions."""
    
    def test_multi_factor_auth_shield_creation(self):
        """Test basic MFA shield creation."""
        shield_func = multi_factor_auth_shield(
            required_methods=[MFAMethod.TOTP],
            max_attempts=5,
            session_duration=7200
        )
        
        assert shield_func is not None
        assert hasattr(shield_func, '_guard_func')
    
    def test_enterprise_mfa_shield_creation(self):
        """Test enterprise MFA shield creation."""
        shield_func = enterprise_mfa_shield(
            required_methods=[MFAMethod.TOTP, MFAMethod.SMS],
            backup_codes_required=True,
            enforce_setup=True
        )
        
        assert shield_func is not None
    
    def test_flexible_mfa_shield_creation(self):
        """Test flexible MFA shield creation."""
        shield_func = flexible_mfa_shield(
            totp_enabled=True,
            sms_enabled=True,
            email_enabled=False
        )
        
        assert shield_func is not None


class TestMFAIntegration:
    """Test MFA integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_complete_mfa_flow_totp(self):
        """Test complete MFA flow with TOTP."""
        config = MFAConfig(required_methods=[MFAMethod.TOTP])
        manager = MFAManager(config)
        
        user_id = "user123"
        
        # 1. Setup TOTP
        setup_info = await manager.setup_totp(user_id)
        assert 'secret' in setup_info
        assert 'qr_url' in setup_info
        
        # 2. Start MFA session
        session = await manager.start_mfa_session(user_id)
        assert session.user_id == user_id
        assert not session.is_complete
        
        # 3. Create TOTP challenge
        challenge = await manager.create_challenge(session.session_id, MFAMethod.TOTP)
        assert challenge.method == MFAMethod.TOTP
        
        # 4. Verify TOTP code
        code = manager.totp_generator.generate_code(setup_info['secret'])
        result = await manager.verify_challenge(challenge.challenge_id, code)
        assert result is True
        
        # 5. Check session completion
        updated_session = manager.get_session(session.session_id)
        assert updated_session.is_complete is True
    
    @pytest.mark.asyncio
    async def test_complete_mfa_flow_sms(self):
        """Test complete MFA flow with SMS."""
        config = MFAConfig(required_methods=[MFAMethod.SMS])
        manager = MFAManager(config)
        
        user_id = "user123"
        phone = "1234567890"
        
        # 1. Setup SMS
        await manager.setup_sms(user_id, phone)
        user = manager.get_user(user_id)
        assert user.enabled_methods[MFAMethod.SMS] is True
        
        # 2. Start session and create challenge
        session = await manager.start_mfa_session(user_id)
        challenge = await manager.create_challenge(session.session_id, MFAMethod.SMS)
        
        # 3. Verify SMS code
        sent_code = manager.provider.get_last_code('sms', phone)
        result = await manager.verify_challenge(challenge.challenge_id, sent_code)
        assert result is True
        
        # 4. Check completion
        updated_session = manager.get_session(session.session_id)
        assert updated_session.is_complete is True
    
    @pytest.mark.asyncio
    async def test_multi_method_mfa_flow(self):
        """Test MFA flow with multiple required methods."""
        config = MFAConfig(required_methods=[MFAMethod.TOTP, MFAMethod.SMS])
        manager = MFAManager(config)
        
        user_id = "user123"
        
        # Setup both methods
        totp_info = await manager.setup_totp(user_id)
        await manager.setup_sms(user_id, "1234567890")
        
        # Start session
        session = await manager.start_mfa_session(user_id)
        assert len(session.methods_required) == 2
        
        # Verify TOTP
        totp_challenge = await manager.create_challenge(session.session_id, MFAMethod.TOTP)
        totp_code = manager.totp_generator.generate_code(totp_info['secret'])
        await manager.verify_challenge(totp_challenge.challenge_id, totp_code)
        
        # Session should not be complete yet
        session = manager.get_session(session.session_id)
        assert not session.is_complete
        
        # Verify SMS
        sms_challenge = await manager.create_challenge(session.session_id, MFAMethod.SMS)
        sms_code = manager.provider.get_last_code('sms', '1234567890')
        await manager.verify_challenge(sms_challenge.challenge_id, sms_code)
        
        # Now session should be complete
        session = manager.get_session(session.session_id)
        assert session.is_complete is True


class TestMFAErrorHandling:
    """Test MFA error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_too_many_attempts_lockout(self):
        """Test lockout after too many failed attempts."""
        config = MFAConfig(required_methods=[MFAMethod.TOTP], max_attempts=2)
        manager = MFAManager(config)
        
        # Setup user
        await manager.setup_totp("user123")
        session = await manager.start_mfa_session("user123")
        
        # Make failed attempts
        for i in range(2):  # Equal to max_attempts
            challenge = await manager.create_challenge(session.session_id, MFAMethod.TOTP)
            result = await manager.verify_challenge(challenge.challenge_id, "000000")
            assert result is False
        
        # Try one more attempt - should trigger lockout
        try:
            challenge = await manager.create_challenge(session.session_id, MFAMethod.TOTP)
            await manager.verify_challenge(challenge.challenge_id, "000000")
        except HTTPException:
            pass  # Method lockout expected
        
        # User should be locked out
        assert manager.is_user_locked_out("user123") is True
    
    @pytest.mark.asyncio
    async def test_expired_challenge_verification(self):
        """Test verification of expired challenge."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        # Create expired challenge manually
        challenge = MFAChallenge(
            method=MFAMethod.SMS,
            user_id="user123",
            session_id="session456",
            code="123456",
            expires_at=time.time() - 100  # Expired
        )
        manager.challenges[challenge.challenge_id] = challenge
        
        result = await manager.verify_challenge(challenge.challenge_id, "123456")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_used_challenge_verification(self):
        """Test verification of already used challenge."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        await manager.setup_sms("user123", "1234567890")
        session = await manager.start_mfa_session("user123")
        challenge = await manager.create_challenge(session.session_id, MFAMethod.SMS)
        
        # Use challenge once
        result1 = await manager.verify_challenge(challenge.challenge_id, challenge.code)
        assert result1 is True
        
        # Try to use again
        result2 = await manager.verify_challenge(challenge.challenge_id, challenge.code)
        assert result2 is False
    
    @pytest.mark.asyncio
    async def test_invalid_method_challenge(self):
        """Test creating challenge for non-enabled method."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        # Setup user without SMS
        await manager.setup_totp("user123")
        session = await manager.start_mfa_session("user123")
        
        with pytest.raises(HTTPException) as exc_info:
            await manager.create_challenge(session.session_id, MFAMethod.SMS)
        
        assert exc_info.value.status_code == 400
        assert "not enabled" in exc_info.value.detail


class TestMFAPerformance:
    """Test MFA performance scenarios."""
    
    @pytest.mark.asyncio
    async def test_concurrent_sessions(self):
        """Test concurrent MFA sessions."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        # Setup users
        for i in range(5):
            await manager.setup_totp(f"user{i}")
        
        # Create concurrent sessions
        tasks = []
        for i in range(5):
            task = manager.start_mfa_session(f"user{i}")
            tasks.append(task)
        
        sessions = await asyncio.gather(*tasks)
        
        assert len(sessions) == 5
        assert len(set(s.session_id for s in sessions)) == 5  # All unique
    
    @pytest.mark.asyncio
    async def test_cleanup_performance(self):
        """Test cleanup performance with many expired items."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        # Create many expired sessions and challenges
        for i in range(100):
            expired_session = MFASession(
                user_id=f"user{i}",
                expires_at=time.time() - 100
            )
            manager.sessions[expired_session.session_id] = expired_session
            
            expired_challenge = MFAChallenge(
                method=MFAMethod.SMS,
                user_id=f"user{i}",
                session_id=expired_session.session_id,
                expires_at=time.time() - 100
            )
            manager.challenges[expired_challenge.challenge_id] = expired_challenge
        
        assert len(manager.sessions) == 100
        assert len(manager.challenges) == 100
        
        # Cleanup should be fast
        start_time = time.time()
        await manager.cleanup_expired()
        cleanup_time = time.time() - start_time
        
        assert cleanup_time < 1.0  # Should be very fast
        assert len(manager.sessions) == 0
        assert len(manager.challenges) == 0


class TestMFAAdvancedFeatures:
    """Test advanced MFA features."""
    
    @pytest.mark.asyncio
    async def test_backup_code_recovery(self):
        """Test recovery using backup codes."""
        config = MFAConfig()
        manager = MFAManager(config)
        
        # Generate backup codes
        codes = await manager.generate_backup_codes("user123")
        assert len(codes) == 10
        
        # Use backup code for authentication
        session = await manager.start_mfa_session("user123")
        challenge = await manager.create_challenge(session.session_id, MFAMethod.BACKUP_CODE)
        
        # Use one backup code
        backup_code = codes[0]
        result = await manager.verify_challenge(challenge.challenge_id, backup_code)
        assert result is True
        
        # Code should be consumed
        user = manager.get_user("user123")
        assert backup_code not in user.backup_codes
        assert len(user.backup_codes) == 9
    
    @pytest.mark.asyncio
    async def test_setup_enforcement(self):
        """Test MFA setup enforcement."""
        config = MFAConfig(enforce_setup=True)
        manager = MFAManager(config)
        
        # User without MFA setup should be rejected
        with pytest.raises(HTTPException) as exc_info:
            await manager.start_mfa_session("user123")
        
        assert exc_info.value.status_code == 400
        assert "setup required" in exc_info.value.detail
    
    def test_qr_code_generation(self):
        """Test QR code generation for TOTP setup."""
        config = TOTPConfig(issuer="Test App")
        generator = TOTPGenerator(config)
        
        secret = "JBSWY3DPEHPK3PXP"
        qr_url = generator.generate_qr_url(secret, "test@example.com", "Test App")
        
        assert qr_url.startswith("otpauth://totp/")
        assert secret in qr_url
        assert "Test%20App" in qr_url or "Test App" in qr_url
        assert "test%40example.com" in qr_url or "test@example.com" in qr_url