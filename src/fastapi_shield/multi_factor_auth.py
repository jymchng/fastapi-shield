"""Multi-Factor Authentication Shield for FastAPI Shield.

This module provides comprehensive MFA functionality including TOTP (Time-based OTP),
SMS/Email codes, backup codes, and integration with MFA providers like Auth0 and Okta.
"""

import base64
import hashlib
import hmac
import io
import json
import random
import secrets
import struct
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import quote

from fastapi import HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from fastapi_shield.shield import Shield, shield


class MFAMethod(str, Enum):
    """Multi-factor authentication methods."""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BACKUP_CODE = "backup_code"


class MFAProvider(str, Enum):
    """MFA provider integrations."""
    INTERNAL = "internal"
    AUTH0 = "auth0"
    OKTA = "okta"
    GOOGLE = "google"
    MICROSOFT = "microsoft"


class MFAStatus(str, Enum):
    """MFA authentication status."""
    PENDING = "pending"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"
    EXPIRED = "expired"
    LOCKED = "locked"


class TOTPConfig(BaseModel):
    """TOTP configuration."""
    secret_length: int = Field(default=32, description="Length of the TOTP secret")
    code_length: int = Field(default=6, description="Length of generated codes")
    time_step: int = Field(default=30, description="Time step in seconds")
    window: int = Field(default=1, description="Acceptable time window for codes")
    issuer: str = Field(default="FastAPI Shield", description="Issuer name for QR codes")
    algorithm: str = Field(default="SHA1", description="Hash algorithm")


class SMSConfig(BaseModel):
    """SMS configuration."""
    provider: str = Field(description="SMS provider (twilio, aws_sns, etc.)")
    api_key: str = Field(description="SMS provider API key")
    from_number: str = Field(description="Sender phone number")
    template: str = Field(default="Your verification code is: {code}", description="SMS template")
    code_length: int = Field(default=6, description="SMS code length")
    expiry_minutes: int = Field(default=5, description="Code expiry in minutes")


class EmailConfig(BaseModel):
    """Email configuration."""
    provider: str = Field(description="Email provider (smtp, sendgrid, etc.)")
    smtp_host: Optional[str] = Field(default=None, description="SMTP host")
    smtp_port: Optional[int] = Field(default=587, description="SMTP port")
    username: str = Field(description="Email username/API key")
    password: str = Field(description="Email password/API secret")
    from_email: str = Field(description="Sender email address")
    subject: str = Field(default="Your Verification Code", description="Email subject")
    template: str = Field(default="Your verification code is: {code}", description="Email template")
    code_length: int = Field(default=8, description="Email code length")
    expiry_minutes: int = Field(default=10, description="Code expiry in minutes")


class BackupCodeConfig(BaseModel):
    """Backup code configuration."""
    code_count: int = Field(default=10, description="Number of backup codes to generate")
    code_length: int = Field(default=12, description="Length of each backup code")
    allow_reuse: bool = Field(default=False, description="Allow backup code reuse")


class MFAConfig(BaseModel):
    """Multi-factor authentication configuration."""
    enabled_methods: Set[MFAMethod] = Field(default={MFAMethod.TOTP}, description="Enabled MFA methods")
    provider: MFAProvider = Field(default=MFAProvider.INTERNAL, description="MFA provider")
    totp_config: TOTPConfig = Field(default_factory=TOTPConfig, description="TOTP configuration")
    sms_config: Optional[SMSConfig] = Field(default=None, description="SMS configuration")
    email_config: Optional[EmailConfig] = Field(default=None, description="Email configuration")
    backup_code_config: BackupCodeConfig = Field(default_factory=BackupCodeConfig, description="Backup code configuration")
    session_timeout_minutes: int = Field(default=60, description="MFA session timeout")
    max_attempts: int = Field(default=3, description="Maximum verification attempts")
    lockout_duration_minutes: int = Field(default=15, description="Account lockout duration")
    require_setup: bool = Field(default=True, description="Require MFA setup for new users")


class MFAUser(BaseModel):
    """MFA user information."""
    user_id: str = Field(description="Unique user identifier")
    totp_secret: Optional[str] = Field(default=None, description="TOTP secret key")
    backup_codes: List[str] = Field(default_factory=list, description="Active backup codes")
    phone_number: Optional[str] = Field(default=None, description="Phone number for SMS")
    email: Optional[str] = Field(default=None, description="Email for email codes")
    enabled_methods: Set[MFAMethod] = Field(default_factory=set, description="User's enabled methods")
    is_setup_complete: bool = Field(default=False, description="Whether MFA setup is complete")
    failed_attempts: int = Field(default=0, description="Failed verification attempts")
    locked_until: Optional[datetime] = Field(default=None, description="Lock expiry time")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MFAChallenge(BaseModel):
    """MFA challenge information."""
    challenge_id: str = Field(description="Unique challenge identifier")
    user_id: str = Field(description="User identifier")
    method: MFAMethod = Field(description="MFA method used")
    code: Optional[str] = Field(default=None, description="Generated code (for internal tracking)")
    status: MFAStatus = Field(default=MFAStatus.PENDING, description="Challenge status")
    attempts: int = Field(default=0, description="Verification attempts")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(description="Challenge expiry time")


class MFASession(BaseModel):
    """MFA session information."""
    session_id: str = Field(description="Unique session identifier")
    user_id: str = Field(description="User identifier")
    authenticated: bool = Field(default=False, description="Whether user is authenticated")
    methods_completed: Set[MFAMethod] = Field(default_factory=set, description="Completed methods")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(description="Session expiry time")


class CodeGenerator(ABC):
    """Abstract base class for code generators."""
    
    @abstractmethod
    def generate_code(self, length: int) -> str:
        """Generate a random code."""
        pass


class TOTPGenerator:
    """Time-based One-Time Password generator."""
    
    def __init__(self, config: TOTPConfig):
        self.config = config
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret."""
        return base64.b32encode(secrets.token_bytes(self.config.secret_length)).decode('ascii')
    
    def generate_code(self, secret: str, timestamp: Optional[int] = None) -> str:
        """Generate TOTP code for given secret and timestamp."""
        if timestamp is None:
            timestamp = int(time.time())
        
        counter = timestamp // self.config.time_step
        return self._generate_hotp(secret, counter)
    
    def verify_code(self, secret: str, code: str, timestamp: Optional[int] = None) -> bool:
        """Verify TOTP code with time window tolerance."""
        if timestamp is None:
            timestamp = int(time.time())
        
        counter = timestamp // self.config.time_step
        
        # Check current and adjacent time windows
        for i in range(-self.config.window, self.config.window + 1):
            if self._generate_hotp(secret, counter + i) == code:
                return True
        
        return False
    
    def _generate_hotp(self, secret: str, counter: int) -> str:
        """Generate HOTP code."""
        key = base64.b32decode(secret)
        counter_bytes = struct.pack('>Q', counter)
        
        # Use specified algorithm
        if self.config.algorithm.upper() == 'SHA256':
            hash_func = hashlib.sha256
        elif self.config.algorithm.upper() == 'SHA512':
            hash_func = hashlib.sha512
        else:
            hash_func = hashlib.sha1
        
        hmac_digest = hmac.new(key, counter_bytes, hash_func).digest()
        
        # Extract dynamic binary code
        offset = hmac_digest[-1] & 0xf
        code = struct.unpack('>I', hmac_digest[offset:offset + 4])[0]
        code &= 0x7fffffff
        code %= 10 ** self.config.code_length
        
        return str(code).zfill(self.config.code_length)
    
    def generate_qr_code_url(self, secret: str, account_name: str) -> str:
        """Generate Google Authenticator compatible QR code URL."""
        params = {
            'secret': secret,
            'issuer': self.config.issuer,
            'algorithm': self.config.algorithm,
            'digits': str(self.config.code_length),
            'period': str(self.config.time_step)
        }
        
        param_string = '&'.join(f'{k}={quote(str(v))}' for k, v in params.items())
        account_encoded = quote(f'{self.config.issuer}:{account_name}')
        
        return f'otpauth://totp/{account_encoded}?{param_string}'


class MFAProvider(ABC):
    """Abstract base class for MFA providers."""
    
    @abstractmethod
    async def send_sms_code(self, phone_number: str, code: str) -> bool:
        """Send SMS verification code."""
        pass
    
    @abstractmethod
    async def send_email_code(self, email: str, code: str) -> bool:
        """Send email verification code."""
        pass
    
    @abstractmethod
    async def validate_provider_config(self) -> bool:
        """Validate provider configuration."""
        pass


class MockMFAProvider(MFAProvider):
    """Mock MFA provider for testing."""
    
    def __init__(self):
        self.sent_sms: List[Dict[str, str]] = []
        self.sent_emails: List[Dict[str, str]] = []
    
    async def send_sms_code(self, phone_number: str, code: str) -> bool:
        """Mock SMS sending."""
        self.sent_sms.append({'phone': phone_number, 'code': code})
        return True
    
    async def send_email_code(self, email: str, code: str) -> bool:
        """Mock email sending."""
        self.sent_emails.append({'email': email, 'code': code})
        return True
    
    async def validate_provider_config(self) -> bool:
        """Mock validation."""
        return True


class MFAManager:
    """Multi-factor authentication manager."""
    
    def __init__(self, config: MFAConfig, provider: Optional[MFAProvider] = None):
        self.config = config
        self.provider = provider or MockMFAProvider()
        self.totp_generator = TOTPGenerator(config.totp_config)
        self.users: Dict[str, MFAUser] = {}
        self.challenges: Dict[str, MFAChallenge] = {}
        self.sessions: Dict[str, MFASession] = {}
    
    def register_user(self, user_id: str, phone_number: Optional[str] = None, 
                     email: Optional[str] = None) -> MFAUser:
        """Register a new user for MFA."""
        user = MFAUser(
            user_id=user_id,
            phone_number=phone_number,
            email=email
        )
        
        # Generate TOTP secret if TOTP is enabled
        if MFAMethod.TOTP in self.config.enabled_methods:
            user.totp_secret = self.totp_generator.generate_secret()
            user.enabled_methods.add(MFAMethod.TOTP)
        
        # Generate backup codes if enabled
        if MFAMethod.BACKUP_CODE in self.config.enabled_methods:
            user.backup_codes = self._generate_backup_codes()
            user.enabled_methods.add(MFAMethod.BACKUP_CODE)
        
        # Enable SMS if phone provided and SMS enabled
        if phone_number and MFAMethod.SMS in self.config.enabled_methods:
            user.enabled_methods.add(MFAMethod.SMS)
        
        # Enable email if email provided and email enabled
        if email and MFAMethod.EMAIL in self.config.enabled_methods:
            user.enabled_methods.add(MFAMethod.EMAIL)
        
        user.is_setup_complete = len(user.enabled_methods) > 0
        self.users[user_id] = user
        
        return user
    
    def get_user(self, user_id: str) -> Optional[MFAUser]:
        """Get user by ID."""
        return self.users.get(user_id)
    
    def _generate_backup_codes(self) -> List[str]:
        """Generate backup codes."""
        codes = []
        for _ in range(self.config.backup_code_config.code_count):
            code = ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', 
                                        k=self.config.backup_code_config.code_length))
            codes.append(code)
        return codes
    
    async def create_challenge(self, user_id: str, method: MFAMethod) -> MFAChallenge:
        """Create a new MFA challenge."""
        user = self.get_user(user_id)
        if not user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            raise HTTPException(status.HTTP_423_LOCKED, "Account is locked")
        
        if method not in user.enabled_methods:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"MFA method {method} not enabled")
        
        challenge_id = secrets.token_urlsafe(32)
        
        # Set expiry based on method
        if method == MFAMethod.SMS and self.config.sms_config:
            expiry = datetime.now(timezone.utc) + timedelta(minutes=self.config.sms_config.expiry_minutes)
        elif method == MFAMethod.EMAIL and self.config.email_config:
            expiry = datetime.now(timezone.utc) + timedelta(minutes=self.config.email_config.expiry_minutes)
        else:
            expiry = datetime.now(timezone.utc) + timedelta(minutes=5)  # Default 5 minutes
        
        challenge = MFAChallenge(
            challenge_id=challenge_id,
            user_id=user_id,
            method=method,
            expires_at=expiry
        )
        
        # Generate and send code for SMS/Email methods
        if method == MFAMethod.SMS and self.config.sms_config and user.phone_number:
            code = self._generate_numeric_code(self.config.sms_config.code_length)
            challenge.code = code
            await self.provider.send_sms_code(user.phone_number, code)
        elif method == MFAMethod.EMAIL and self.config.email_config and user.email:
            code = self._generate_alphanumeric_code(self.config.email_config.code_length)
            challenge.code = code
            await self.provider.send_email_code(user.email, code)
        
        self.challenges[challenge_id] = challenge
        return challenge
    
    def _generate_numeric_code(self, length: int) -> str:
        """Generate numeric code."""
        return ''.join(random.choices('0123456789', k=length))
    
    def _generate_alphanumeric_code(self, length: int) -> str:
        """Generate alphanumeric code."""
        return ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=length))
    
    async def verify_challenge(self, challenge_id: str, code: str) -> bool:
        """Verify MFA challenge."""
        challenge = self.challenges.get(challenge_id)
        if not challenge:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Challenge not found")
        
        if challenge.expires_at < datetime.now(timezone.utc):
            challenge.status = MFAStatus.EXPIRED
            raise HTTPException(status.HTTP_410_GONE, "Challenge expired")
        
        challenge.attempts += 1
        
        if challenge.attempts > self.config.max_attempts:
            challenge.status = MFAStatus.FAILED
            await self._lock_user(challenge.user_id)
            raise HTTPException(status.HTTP_423_LOCKED, "Too many attempts")
        user = self.get_user(challenge.user_id)
        
        verified = False
        
        if challenge.method == MFAMethod.TOTP:
            if user.totp_secret:
                verified = self.totp_generator.verify_code(user.totp_secret, code)
        elif challenge.method == MFAMethod.SMS or challenge.method == MFAMethod.EMAIL:
            verified = challenge.code == code.upper()
        elif challenge.method == MFAMethod.BACKUP_CODE:
            if code.upper() in user.backup_codes:
                verified = True
                if not self.config.backup_code_config.allow_reuse:
                    user.backup_codes.remove(code.upper())
        
        if verified:
            challenge.status = MFAStatus.AUTHENTICATED
            user.failed_attempts = 0  # Reset failed attempts on success
            return True
        else:
            challenge.status = MFAStatus.FAILED
            user.failed_attempts += 1
            
            # Lock user if too many failed attempts
            if user.failed_attempts >= self.config.max_attempts:
                await self._lock_user(challenge.user_id)
            
            return False
    
    async def _lock_user(self, user_id: str):
        """Lock user account."""
        user = self.get_user(user_id)
        if user:
            user.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=self.config.lockout_duration_minutes
            )
            user.failed_attempts = 0
    
    def create_session(self, user_id: str) -> MFASession:
        """Create MFA session."""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=self.config.session_timeout_minutes
        )
        
        session = MFASession(
            session_id=session_id,
            user_id=user_id,
            expires_at=expires_at
        )
        
        self.sessions[session_id] = session
        return session
    
    def get_session(self, session_id: str) -> Optional[MFASession]:
        """Get session by ID."""
        session = self.sessions.get(session_id)
        if session and session.expires_at < datetime.now(timezone.utc):
            del self.sessions[session_id]
            return None
        return session
    
    def authenticate_session(self, session_id: str, method: MFAMethod):
        """Mark session as authenticated for specific method."""
        session = self.get_session(session_id)
        if session:
            session.methods_completed.add(method)
            # Check if all required methods are completed
            user = self.get_user(session.user_id)
            if user and user.enabled_methods.issubset(session.methods_completed):
                session.authenticated = True


class MFAShield(Shield):
    """Multi-factor authentication shield for FastAPI endpoints."""
    
    def __init__(self, config: MFAConfig, mfa_manager: Optional[MFAManager] = None, **kwargs):
        self.config = config
        self.mfa_manager = mfa_manager or MFAManager(config)
        
        super().__init__(
            self._mfa_guard,
            name=kwargs.get('name', 'MFA'),
            auto_error=kwargs.get('auto_error', True),
            exception_to_raise_if_fail=kwargs.get('exception_to_raise_if_fail', 
                HTTPException(status.HTTP_401_UNAUTHORIZED, "MFA required")),
            default_response_to_return_if_fail=kwargs.get('default_response_to_return_if_fail', 
                Response(content="MFA required", status_code=401))
        )
    
    async def _mfa_guard(self, request: Request) -> Optional[Dict[str, Any]]:
        """MFA guard function."""
        # Extract session ID from headers or cookies
        session_id = request.headers.get('X-MFA-Session') or request.cookies.get('mfa_session')
        
        if not session_id:
            return None
        
        session = self.mfa_manager.get_session(session_id)
        if not session or not session.authenticated:
            return None
        
        user = self.mfa_manager.get_user(session.user_id)
        if not user:
            return None
        
        return {
            'user_id': user.user_id,
            'session_id': session_id,
            'mfa_methods': list(session.methods_completed),
            'user': user
        }


# Convenience functions for creating common MFA shields

def multi_factor_auth_shield(
    config: Optional[MFAConfig] = None,
    mfa_manager: Optional[MFAManager] = None,
    **kwargs
) -> MFAShield:
    """Create a basic multi-factor authentication shield."""
    if config is None:
        config = MFAConfig()
    
    return MFAShield(config=config, mfa_manager=mfa_manager, **kwargs)


def enterprise_mfa_shield(
    enabled_methods: Optional[Set[MFAMethod]] = None,
    session_timeout_minutes: int = 30,
    max_attempts: int = 3,
    **kwargs
) -> MFAShield:
    """Create an enterprise-grade MFA shield with strict security."""
    if enabled_methods is None:
        enabled_methods = {MFAMethod.TOTP, MFAMethod.BACKUP_CODE}
    
    config = MFAConfig(
        enabled_methods=enabled_methods,
        session_timeout_minutes=session_timeout_minutes,
        max_attempts=max_attempts,
        lockout_duration_minutes=30,
        require_setup=True
    )
    
    return MFAShield(config=config, **kwargs)


def flexible_mfa_shield(
    enabled_methods: Optional[Set[MFAMethod]] = None,
    require_setup: bool = False,
    session_timeout_minutes: int = 120,
    **kwargs
) -> MFAShield:
    """Create a flexible MFA shield suitable for development/testing."""
    if enabled_methods is None:
        enabled_methods = {MFAMethod.TOTP, MFAMethod.SMS, MFAMethod.EMAIL, MFAMethod.BACKUP_CODE}
    
    config = MFAConfig(
        enabled_methods=enabled_methods,
        session_timeout_minutes=session_timeout_minutes,
        require_setup=require_setup,
        max_attempts=5,
        lockout_duration_minutes=5
    )
    
    return MFAShield(config=config, **kwargs)