"""Multi-Factor Authentication Shield for FastAPI Shield.

This module provides comprehensive MFA capabilities including TOTP, SMS, email codes,
backup codes, provider integration, and complete enrollment/recovery flows for
enterprise-grade multi-factor authentication.
"""

import base64
import hashlib
import hmac
import io
import json
import secrets
import struct
import time
import uuid
from collections import defaultdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Callable
from urllib.parse import quote

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from fastapi_shield.shield import Shield, shield


class MFAMethod(str, Enum):
    """Multi-factor authentication methods."""
    TOTP = "totp"
    SMS = "sms" 
    EMAIL = "email"
    BACKUP_CODE = "backup_code"
    PUSH = "push"
    HARDWARE_TOKEN = "hardware_token"


class MFAProvider(str, Enum):
    """MFA provider services."""
    BUILTIN = "builtin"
    AUTH0 = "auth0"
    OKTA = "okta"
    TWILIO = "twilio"
    SENDGRID = "sendgrid"
    AUTHY = "authy"
    DUO = "duo"


class MFAStatus(str, Enum):
    """MFA verification status."""
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"
    RATE_LIMITED = "rate_limited"


class TOTPConfig(BaseModel):
    """TOTP configuration."""
    
    issuer: str = Field(default="FastAPI Shield", description="TOTP issuer name")
    algorithm: str = Field(default="SHA1", description="HMAC algorithm")
    digits: int = Field(default=6, ge=6, le=8, description="Number of digits in TOTP code")
    period: int = Field(default=30, ge=15, le=300, description="Time period in seconds")
    window: int = Field(default=1, ge=0, le=5, description="Time window tolerance")
    secret_length: int = Field(default=32, ge=16, le=64, description="Secret key length")


class SMSConfig(BaseModel):
    """SMS configuration."""
    
    provider: MFAProvider = Field(default=MFAProvider.TWILIO)
    account_sid: Optional[str] = None
    auth_token: Optional[str] = None
    from_number: Optional[str] = None
    message_template: str = Field(
        default="Your verification code is: {code}",
        description="SMS message template"
    )
    code_length: int = Field(default=6, ge=4, le=10)
    code_expiry: int = Field(default=300, ge=60, le=3600, description="Code expiry in seconds")


class EmailConfig(BaseModel):
    """Email configuration."""
    
    provider: MFAProvider = Field(default=MFAProvider.SENDGRID)
    api_key: Optional[str] = None
    from_email: str = Field(default="noreply@example.com")
    from_name: str = Field(default="FastAPI Shield")
    subject: str = Field(default="Your Verification Code")
    template: str = Field(
        default="Your verification code is: {code}",
        description="Email body template"
    )
    code_length: int = Field(default=8, ge=6, le=12)
    code_expiry: int = Field(default=600, ge=300, le=3600, description="Code expiry in seconds")


class BackupCodeConfig(BaseModel):
    """Backup code configuration."""
    
    count: int = Field(default=10, ge=5, le=20, description="Number of backup codes to generate")
    length: int = Field(default=8, ge=6, le=16, description="Length of each backup code")
    use_dashes: bool = Field(default=True, description="Add dashes to backup codes")


class MFAConfig(BaseModel):
    """Multi-factor authentication configuration."""
    
    # General settings
    required_methods: List[MFAMethod] = Field(
        default_factory=lambda: [MFAMethod.TOTP],
        description="Required MFA methods"
    )
    optional_methods: List[MFAMethod] = Field(
        default_factory=lambda: [MFAMethod.SMS, MFAMethod.EMAIL, MFAMethod.BACKUP_CODE],
        description="Optional MFA methods"
    )
    
    # Verification settings
    max_attempts: int = Field(default=3, ge=1, le=10, description="Max verification attempts")
    lockout_duration: int = Field(default=900, ge=300, le=3600, description="Lockout duration in seconds")
    session_duration: int = Field(default=3600, ge=300, le=86400, description="MFA session duration")
    
    # Method configurations
    totp_config: TOTPConfig = Field(default_factory=TOTPConfig)
    sms_config: SMSConfig = Field(default_factory=SMSConfig)
    email_config: EmailConfig = Field(default_factory=EmailConfig)
    backup_code_config: BackupCodeConfig = Field(default_factory=BackupCodeConfig)
    
    # Provider settings
    default_provider: MFAProvider = Field(default=MFAProvider.BUILTIN)
    provider_fallback: bool = Field(default=True, description="Fallback to builtin if provider fails")
    
    # Security settings
    enforce_setup: bool = Field(default=False, description="Enforce MFA setup for all users")
    allow_recovery: bool = Field(default=True, description="Allow MFA recovery methods")
    require_backup_codes: bool = Field(default=True, description="Require backup codes setup")
    
    @field_validator('required_methods', 'optional_methods')
    @classmethod
    def validate_methods(cls, v):
        """Validate MFA methods."""
        if not v:
            raise ValueError("At least one MFA method must be configured")
        return v


class MFASession(BaseModel):
    """MFA session information."""
    
    user_id: str
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    methods_verified: List[MFAMethod] = Field(default_factory=list)
    methods_required: List[MFAMethod] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    expires_at: float
    is_complete: bool = False
    attempts: Dict[MFAMethod, int] = Field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return time.time() > self.expires_at
    
    def is_method_verified(self, method: MFAMethod) -> bool:
        """Check if method is verified."""
        return method in self.methods_verified
    
    def is_locked_out(self, method: MFAMethod, max_attempts: int) -> bool:
        """Check if method is locked out."""
        return self.attempts.get(method, 0) >= max_attempts


class MFAChallenge(BaseModel):
    """MFA challenge information."""
    
    challenge_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    method: MFAMethod
    user_id: str
    session_id: str
    code: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    expires_at: float
    attempts: int = 0
    is_used: bool = False
    
    def is_expired(self) -> bool:
        """Check if challenge is expired."""
        return time.time() > self.expires_at


class MFAUser(BaseModel):
    """MFA user configuration."""
    
    user_id: str
    enabled_methods: Dict[MFAMethod, bool] = Field(default_factory=dict)
    totp_secret: Optional[str] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    backup_codes: List[str] = Field(default_factory=list)
    recovery_codes: List[str] = Field(default_factory=list)
    last_used: Dict[MFAMethod, float] = Field(default_factory=dict)
    setup_completed: bool = False
    setup_required: bool = True


class TOTPGenerator:
    """TOTP (Time-based One-Time Password) generator."""
    
    def __init__(self, config: TOTPConfig):
        """Initialize TOTP generator.
        
        Args:
            config: TOTP configuration
        """
        self.config = config
        self._algorithm_map = {
            'SHA1': hashlib.sha1,
            'SHA256': hashlib.sha256,
            'SHA512': hashlib.sha512
        }
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret.
        
        Returns:
            Base32 encoded secret
        """
        secret = secrets.token_bytes(self.config.secret_length)
        return base64.b32encode(secret).decode('ascii')
    
    def generate_code(self, secret: str, timestamp: Optional[int] = None) -> str:
        """Generate TOTP code.
        
        Args:
            secret: Base32 encoded secret
            timestamp: Unix timestamp (current time if None)
            
        Returns:
            TOTP code string
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Convert secret from base32
        try:
            key = base64.b32decode(secret.upper().encode('ascii'))
        except Exception:
            raise ValueError("Invalid TOTP secret")
        
        # Calculate time counter
        counter = timestamp // self.config.period
        
        # Generate HMAC
        hmac_digest = hmac.new(
            key,
            struct.pack('>Q', counter),
            self._algorithm_map[self.config.algorithm]
        ).digest()
        
        # Dynamic truncation
        offset = hmac_digest[-1] & 0xf
        code = struct.unpack('>I', hmac_digest[offset:offset+4])[0] & 0x7fffffff
        
        # Generate final code
        code = code % (10 ** self.config.digits)
        return f"{code:0{self.config.digits}d}"
    
    def verify_code(self, secret: str, code: str, timestamp: Optional[int] = None) -> bool:
        """Verify TOTP code.
        
        Args:
            secret: Base32 encoded secret
            code: TOTP code to verify
            timestamp: Unix timestamp (current time if None)
            
        Returns:
            True if code is valid
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Check current and previous/next time windows
        for i in range(-self.config.window, self.config.window + 1):
            test_timestamp = timestamp + (i * self.config.period)
            if self.generate_code(secret, test_timestamp) == code:
                return True
        
        return False
    
    def generate_qr_url(self, secret: str, account_name: str, issuer: Optional[str] = None) -> str:
        """Generate QR code URL for TOTP setup.
        
        Args:
            secret: Base32 encoded secret
            account_name: Account identifier
            issuer: Service issuer name
            
        Returns:
            TOTP URI for QR code generation
        """
        issuer = issuer or self.config.issuer
        label = f"{issuer}:{account_name}" if issuer else account_name
        
        params = {
            'secret': secret,
            'issuer': issuer,
            'algorithm': self.config.algorithm,
            'digits': self.config.digits,
            'period': self.config.period
        }
        
        param_string = '&'.join([f"{k}={quote(str(v))}" for k, v in params.items()])
        return f"otpauth://totp/{quote(label)}?{param_string}"


class CodeGenerator:
    """Generate verification codes for SMS/Email."""
    
    @staticmethod
    def generate_numeric_code(length: int = 6) -> str:
        """Generate numeric verification code.
        
        Args:
            length: Code length
            
        Returns:
            Numeric code string
        """
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])
    
    @staticmethod
    def generate_alphanumeric_code(length: int = 8) -> str:
        """Generate alphanumeric verification code.
        
        Args:
            length: Code length
            
        Returns:
            Alphanumeric code string
        """
        alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def generate_backup_codes(count: int = 10, length: int = 8, use_dashes: bool = True) -> List[str]:
        """Generate backup codes.
        
        Args:
            count: Number of codes to generate
            length: Length of each code
            use_dashes: Add dashes to codes
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            code = CodeGenerator.generate_alphanumeric_code(length)
            if use_dashes and len(code) >= 6:
                # Add dashes for readability
                mid = len(code) // 2
                code = f"{code[:mid]}-{code[mid:]}"
            codes.append(code)
        return codes


class MFAProvider_Interface:
    """Interface for MFA providers."""
    
    async def send_sms(self, phone: str, code: str, template: str) -> bool:
        """Send SMS code.
        
        Args:
            phone: Phone number
            code: Verification code
            template: Message template
            
        Returns:
            True if sent successfully
        """
        raise NotImplementedError
    
    async def send_email(self, email: str, code: str, subject: str, template: str) -> bool:
        """Send email code.
        
        Args:
            email: Email address
            code: Verification code
            subject: Email subject
            template: Email template
            
        Returns:
            True if sent successfully
        """
        raise NotImplementedError


class MockMFAProvider(MFAProvider_Interface):
    """Mock MFA provider for testing."""
    
    def __init__(self):
        """Initialize mock provider."""
        self.sent_messages = []
    
    async def send_sms(self, phone: str, code: str, template: str) -> bool:
        """Mock send SMS."""
        message = template.format(code=code)
        self.sent_messages.append({
            'type': 'sms',
            'to': phone,
            'message': message,
            'code': code,
            'timestamp': time.time()
        })
        return True
    
    async def send_email(self, email: str, code: str, subject: str, template: str) -> bool:
        """Mock send email."""
        message = template.format(code=code)
        self.sent_messages.append({
            'type': 'email',
            'to': email,
            'subject': subject,
            'message': message,
            'code': code,
            'timestamp': time.time()
        })
        return True
    
    def get_last_code(self, method: str, recipient: str) -> Optional[str]:
        """Get last sent code for testing."""
        for msg in reversed(self.sent_messages):
            if msg['type'] == method and msg['to'] == recipient:
                return msg['code']
        return None


class MFAManager:
    """Multi-factor authentication manager."""
    
    def __init__(self, config: MFAConfig):
        """Initialize MFA manager.
        
        Args:
            config: MFA configuration
        """
        self.config = config
        self.totp_generator = TOTPGenerator(config.totp_config)
        self.provider = MockMFAProvider()  # Default to mock for testing
        
        # Storage (in production, use database)
        self.sessions: Dict[str, MFASession] = {}
        self.challenges: Dict[str, MFAChallenge] = {}
        self.users: Dict[str, MFAUser] = {}
        self.lockouts: Dict[str, float] = {}  # user_id -> unlock_time
    
    def set_provider(self, provider: MFAProvider_Interface):
        """Set MFA provider.
        
        Args:
            provider: MFA provider instance
        """
        self.provider = provider
    
    def get_user(self, user_id: str) -> MFAUser:
        """Get or create MFA user.
        
        Args:
            user_id: User identifier
            
        Returns:
            MFA user configuration
        """
        if user_id not in self.users:
            self.users[user_id] = MFAUser(user_id=user_id)
        return self.users[user_id]
    
    def is_user_locked_out(self, user_id: str) -> bool:
        """Check if user is locked out.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if user is locked out
        """
        if user_id in self.lockouts:
            if time.time() < self.lockouts[user_id]:
                return True
            else:
                del self.lockouts[user_id]
        return False
    
    def lockout_user(self, user_id: str):
        """Lock out user for configured duration.
        
        Args:
            user_id: User identifier
        """
        self.lockouts[user_id] = time.time() + self.config.lockout_duration
    
    async def setup_totp(self, user_id: str) -> Dict[str, str]:
        """Setup TOTP for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dict with secret and QR code URL
        """
        user = self.get_user(user_id)
        
        # Generate new secret
        secret = self.totp_generator.generate_secret()
        user.totp_secret = secret
        user.enabled_methods[MFAMethod.TOTP] = True
        
        # Generate QR code URL
        qr_url = self.totp_generator.generate_qr_url(secret, user_id)
        
        return {
            'secret': secret,
            'qr_url': qr_url,
            'backup_url': f"data:image/svg+xml;base64,{self._generate_qr_svg(qr_url)}"
        }
    
    def _generate_qr_svg(self, data: str) -> str:
        """Generate QR code SVG (mock implementation).
        
        Args:
            data: Data to encode
            
        Returns:
            Base64 encoded SVG
        """
        # Mock QR code SVG
        svg = f'''<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
            <rect width="200" height="200" fill="white"/>
            <text x="100" y="100" text-anchor="middle" fill="black" font-size="10">
                QR Code: {data[:20]}...
            </text>
        </svg>'''
        return base64.b64encode(svg.encode()).decode()
    
    async def setup_sms(self, user_id: str, phone_number: str) -> bool:
        """Setup SMS MFA for user.
        
        Args:
            user_id: User identifier
            phone_number: Phone number
            
        Returns:
            True if setup successful
        """
        user = self.get_user(user_id)
        user.phone_number = phone_number
        user.enabled_methods[MFAMethod.SMS] = True
        return True
    
    async def setup_email(self, user_id: str, email: str) -> bool:
        """Setup email MFA for user.
        
        Args:
            user_id: User identifier
            email: Email address
            
        Returns:
            True if setup successful
        """
        user = self.get_user(user_id)
        user.email = email
        user.enabled_methods[MFAMethod.EMAIL] = True
        return True
    
    async def generate_backup_codes(self, user_id: str, force: bool = False) -> List[str]:
        """Generate backup codes for user.
        
        Args:
            user_id: User identifier
            force: Force regeneration
            
        Returns:
            List of backup codes
        """
        user = self.get_user(user_id)
        
        if not user.backup_codes or force:
            user.backup_codes = CodeGenerator.generate_backup_codes(
                self.config.backup_code_config.count,
                self.config.backup_code_config.length,
                self.config.backup_code_config.use_dashes
            )
            user.enabled_methods[MFAMethod.BACKUP_CODE] = True
        
        return user.backup_codes.copy()
    
    async def start_mfa_session(self, user_id: str) -> MFASession:
        """Start MFA verification session.
        
        Args:
            user_id: User identifier
            
        Returns:
            MFA session
        """
        if self.is_user_locked_out(user_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account temporarily locked due to failed attempts"
            )
        
        user = self.get_user(user_id)
        
        # Determine required methods
        required_methods = []
        for method in self.config.required_methods:
            if user.enabled_methods.get(method, False):
                required_methods.append(method)
        
        # If no required methods are set up, enforce setup
        if not required_methods and self.config.enforce_setup:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA setup required"
            )
        
        # Create session
        session = MFASession(
            user_id=user_id,
            methods_required=required_methods,
            expires_at=time.time() + self.config.session_duration
        )
        
        self.sessions[session.session_id] = session
        return session
    
    async def create_challenge(self, session_id: str, method: MFAMethod) -> MFAChallenge:
        """Create MFA challenge.
        
        Args:
            session_id: MFA session ID
            method: MFA method
            
        Returns:
            MFA challenge
        """
        session = self.sessions.get(session_id)
        if not session or session.is_expired():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired MFA session"
            )
        
        if session.is_locked_out(method, self.config.max_attempts):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"{method.value} method locked due to failed attempts"
            )
        
        user = self.get_user(session.user_id)
        if not user.enabled_methods.get(method, False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{method.value} not enabled for user"
            )
        
        # Determine expiry based on method
        if method == MFAMethod.SMS:
            expires_at = time.time() + self.config.sms_config.code_expiry
        elif method == MFAMethod.EMAIL:
            expires_at = time.time() + self.config.email_config.code_expiry
        else:
            expires_at = time.time() + 300  # 5 minutes default
        
        # Create challenge
        challenge = MFAChallenge(
            method=method,
            user_id=session.user_id,
            session_id=session_id,
            expires_at=expires_at
        )
        
        # Generate and send code if needed
        if method == MFAMethod.SMS:
            code = CodeGenerator.generate_numeric_code(self.config.sms_config.code_length)
            challenge.code = code
            await self.provider.send_sms(
                user.phone_number,
                code,
                self.config.sms_config.message_template
            )
        elif method == MFAMethod.EMAIL:
            code = CodeGenerator.generate_alphanumeric_code(self.config.email_config.code_length)
            challenge.code = code
            await self.provider.send_email(
                user.email,
                code,
                self.config.email_config.subject,
                self.config.email_config.template
            )
        
        self.challenges[challenge.challenge_id] = challenge
        return challenge
    
    async def verify_challenge(self, challenge_id: str, code: str) -> bool:
        """Verify MFA challenge.
        
        Args:
            challenge_id: Challenge identifier
            code: Verification code
            
        Returns:
            True if verification successful
        """
        challenge = self.challenges.get(challenge_id)
        if not challenge:
            return False
        
        if challenge.is_expired() or challenge.is_used:
            return False
        
        challenge.attempts += 1
        session = self.sessions.get(challenge.session_id)
        
        # Update session attempts
        if session:
            session.attempts[challenge.method] = session.attempts.get(challenge.method, 0) + 1
        
        user = self.get_user(challenge.user_id)
        verified = False
        
        # Verify based on method
        if challenge.method == MFAMethod.TOTP:
            if user.totp_secret:
                verified = self.totp_generator.verify_code(user.totp_secret, code)
        elif challenge.method in [MFAMethod.SMS, MFAMethod.EMAIL]:
            verified = (challenge.code == code)
        elif challenge.method == MFAMethod.BACKUP_CODE:
            # Check backup codes
            if code in user.backup_codes:
                user.backup_codes.remove(code)  # Use once
                verified = True
        
        if verified:
            challenge.is_used = True
            if session:
                session.methods_verified.append(challenge.method)
                session.is_complete = all(
                    method in session.methods_verified
                    for method in session.methods_required
                )
            user.last_used[challenge.method] = time.time()
            return True
        else:
            # Check for lockout
            if session and session.attempts.get(challenge.method, 0) >= self.config.max_attempts:
                self.lockout_user(challenge.user_id)
            return False
    
    def get_session(self, session_id: str) -> Optional[MFASession]:
        """Get MFA session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            MFA session if exists and valid
        """
        session = self.sessions.get(session_id)
        if session and not session.is_expired():
            return session
        return None
    
    async def cleanup_expired(self):
        """Clean up expired sessions and challenges."""
        current_time = time.time()
        
        # Clean up expired sessions
        expired_sessions = [
            sid for sid, session in self.sessions.items()
            if session.is_expired()
        ]
        for sid in expired_sessions:
            del self.sessions[sid]
        
        # Clean up expired challenges
        expired_challenges = [
            cid for cid, challenge in self.challenges.items()
            if challenge.is_expired()
        ]
        for cid in expired_challenges:
            del self.challenges[cid]


class MFAShield:
    """Multi-factor authentication shield for FastAPI endpoints."""
    
    def __init__(self, config: MFAConfig):
        """Initialize MFA shield.
        
        Args:
            config: MFA configuration
        """
        self.config = config
        self.manager = MFAManager(config)
    
    def create_shield(self, name: str = "MFAAuthentication") -> Shield:
        """Create MFA authentication shield.
        
        Args:
            name: Shield name
            
        Returns:
            Shield instance
        """
        
        async def mfa_auth_shield(request: Request) -> Dict[str, Any]:
            """MFA authentication shield function."""
            
            # Check for MFA session in headers or cookies
            session_id = (
                request.headers.get("X-MFA-Session") or
                request.cookies.get("mfa_session")
            )
            
            if not session_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="MFA session required",
                    headers={"X-MFA-Required": "true"}
                )
            
            # Verify MFA session
            session = self.manager.get_session(session_id)
            if not session:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired MFA session",
                    headers={"X-MFA-Required": "true"}
                )
            
            if not session.is_complete:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="MFA verification incomplete",
                    headers={
                        "X-MFA-Required": "true",
                        "X-MFA-Methods-Required": ",".join(session.methods_required),
                        "X-MFA-Methods-Verified": ",".join(session.methods_verified)
                    }
                )
            
            # Return session information
            user = self.manager.get_user(session.user_id)
            return {
                "mfa_verified": True,
                "user_id": session.user_id,
                "session_id": session.session_id,
                "methods_verified": session.methods_verified,
                "verified_at": session.created_at,
                "enabled_methods": list(user.enabled_methods.keys()),
                "setup_completed": user.setup_completed,
            }
        
        return shield(
            mfa_auth_shield,
            name=name,
            auto_error=True,
        )
    
    def get_manager(self) -> MFAManager:
        """Get MFA manager for API operations.
        
        Returns:
            MFA manager instance
        """
        return self.manager


def multi_factor_auth_shield(
    required_methods: List[MFAMethod] = None,
    max_attempts: int = 3,
    session_duration: int = 3600,
    name: str = "MultiFactorAuth",
) -> Shield:
    """Create a multi-factor authentication shield with basic configuration.
    
    Args:
        required_methods: Required MFA methods
        max_attempts: Maximum verification attempts
        session_duration: MFA session duration in seconds
        name: Shield name
        
    Returns:
        MFA authentication shield
        
    Examples:
        ```python
        # Basic MFA with TOTP
        @app.get("/protected")
        @multi_factor_auth_shield(
            required_methods=[MFAMethod.TOTP]
        )
        def protected_endpoint():
            return {"message": "MFA verified"}
        ```
    """
    config = MFAConfig(
        required_methods=required_methods or [MFAMethod.TOTP],
        max_attempts=max_attempts,
        session_duration=session_duration,
    )
    
    shield_instance = MFAShield(config)
    return shield_instance.create_shield(name)


def enterprise_mfa_shield(
    required_methods: List[MFAMethod] = None,
    backup_codes_required: bool = True,
    enforce_setup: bool = True,
    lockout_duration: int = 1800,
    name: str = "EnterpriseMFA",
) -> Shield:
    """Create enterprise-grade MFA shield.
    
    Args:
        required_methods: Required MFA methods
        backup_codes_required: Require backup codes setup
        enforce_setup: Enforce MFA setup for all users
        lockout_duration: Account lockout duration in seconds
        name: Shield name
        
    Returns:
        Enterprise MFA authentication shield
        
    Examples:
        ```python
        # Enterprise MFA with multiple methods
        @app.get("/admin")
        @enterprise_mfa_shield(
            required_methods=[MFAMethod.TOTP, MFAMethod.SMS],
            backup_codes_required=True,
            enforce_setup=True
        )
        def admin_endpoint():
            return {"message": "Enterprise MFA verified"}
        ```
    """
    config = MFAConfig(
        required_methods=required_methods or [MFAMethod.TOTP],
        optional_methods=[MFAMethod.SMS, MFAMethod.EMAIL, MFAMethod.BACKUP_CODE],
        max_attempts=3,
        lockout_duration=lockout_duration,
        session_duration=3600,
        require_backup_codes=backup_codes_required,
        enforce_setup=enforce_setup,
        allow_recovery=True,
    )
    
    shield_instance = MFAShield(config)
    return shield_instance.create_shield(name)


def flexible_mfa_shield(
    totp_enabled: bool = True,
    sms_enabled: bool = True,
    email_enabled: bool = True,
    backup_codes_enabled: bool = True,
    name: str = "FlexibleMFA",
) -> Shield:
    """Create flexible MFA shield with configurable methods.
    
    Args:
        totp_enabled: Enable TOTP method
        sms_enabled: Enable SMS method
        email_enabled: Enable email method
        backup_codes_enabled: Enable backup codes
        name: Shield name
        
    Returns:
        Flexible MFA authentication shield
        
    Examples:
        ```python
        # Flexible MFA allowing multiple options
        @app.get("/api/data")
        @flexible_mfa_shield(
            totp_enabled=True,
            sms_enabled=True,
            email_enabled=False
        )
        def api_endpoint():
            return {"data": "sensitive information"}
        ```
    """
    required_methods = []
    optional_methods = []
    
    if totp_enabled:
        required_methods.append(MFAMethod.TOTP)
    if sms_enabled:
        optional_methods.append(MFAMethod.SMS)
    if email_enabled:
        optional_methods.append(MFAMethod.EMAIL)
    if backup_codes_enabled:
        optional_methods.append(MFAMethod.BACKUP_CODE)
    
    if not required_methods and optional_methods:
        required_methods = [optional_methods[0]]  # At least one method required
    
    config = MFAConfig(
        required_methods=required_methods,
        optional_methods=optional_methods,
        enforce_setup=False,
        allow_recovery=True,
    )
    
    shield_instance = MFAShield(config)
    return shield_instance.create_shield(name)