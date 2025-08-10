"""Session management shield for FastAPI Shield.

This module provides secure session management capabilities including session
creation, validation, storage, and security policies. It includes protection
against session fixation, CSRF attacks, and other session-related vulnerabilities.
"""

import asyncio
import hashlib
import hmac
import json
import secrets
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse

from fastapi import Cookie, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator

from fastapi_shield.shield import Shield, shield


class SessionState(str, Enum):
    """Session states."""
    ACTIVE = "active"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"
    RENEWED = "renewed"
    SUSPICIOUS = "suspicious"


class SessionSecurityLevel(str, Enum):
    """Session security levels."""
    LOW = "low"        # Basic session management
    MEDIUM = "medium"  # Standard security with timeouts
    HIGH = "high"      # Strict security with rotation
    PARANOID = "paranoid"  # Maximum security with all protections


class SessionStorageType(str, Enum):
    """Session storage backend types."""
    MEMORY = "memory"
    REDIS = "redis"
    DATABASE = "database"
    FILE = "file"


class CSRFProtection(str, Enum):
    """CSRF protection modes."""
    DISABLED = "disabled"
    TOKEN = "token"
    DOUBLE_SUBMIT = "double_submit"
    SAMEFROM = "samefrom"


class SessionConfig(BaseModel):
    """Configuration for session management."""
    
    # Basic session settings
    session_name: str = "session_id"
    csrf_token_name: str = "csrf_token"
    max_age: int = Field(default=3600, gt=0)  # 1 hour in seconds
    idle_timeout: int = Field(default=1800, gt=0)  # 30 minutes
    absolute_timeout: int = Field(default=86400, gt=0)  # 24 hours
    
    # Security settings
    security_level: SessionSecurityLevel = SessionSecurityLevel.MEDIUM
    secure_cookies: bool = True
    httponly_cookies: bool = True
    samesite_policy: str = "Lax"  # Strict, Lax, None
    
    # Session token settings
    token_length: int = Field(default=32, ge=16, le=128)
    use_secure_random: bool = True
    token_entropy_bits: int = Field(default=256, ge=128)
    
    # Rotation and renewal
    auto_renew: bool = True
    renew_threshold: float = Field(default=0.5, ge=0.1, le=0.9)  # Renew at 50% of max_age
    force_renewal_on_ip_change: bool = True
    force_renewal_on_user_agent_change: bool = False
    
    # Storage settings
    storage_type: SessionStorageType = SessionStorageType.MEMORY
    storage_prefix: str = "session:"
    cleanup_interval: int = Field(default=300, gt=0)  # 5 minutes
    max_sessions_per_user: Optional[int] = None
    
    # CSRF protection
    csrf_protection: CSRFProtection = CSRFProtection.TOKEN
    csrf_token_length: int = Field(default=32, ge=16)
    csrf_header_name: str = "X-CSRF-Token"
    csrf_form_field: str = "csrf_token"
    
    # Security policies
    prevent_session_fixation: bool = True
    track_user_agents: bool = True
    track_ip_addresses: bool = True
    detect_concurrent_sessions: bool = True
    max_concurrent_sessions: int = Field(default=5, gt=0)
    
    # Suspicious activity detection
    max_failed_validations: int = Field(default=3, gt=0)
    lockout_duration: int = Field(default=900, gt=0)  # 15 minutes
    monitor_session_activity: bool = True
    
    # Cookie domain and path
    cookie_domain: Optional[str] = None
    cookie_path: str = "/"
    
    @field_validator('samesite_policy')
    @classmethod
    def validate_samesite(cls, v):
        """Validate SameSite policy."""
        if v not in ['Strict', 'Lax', 'None']:
            raise ValueError("SameSite must be 'Strict', 'Lax', or 'None'")
        return v


class SessionData(BaseModel):
    """Session data model."""
    
    session_id: str
    user_id: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    last_accessed: float = Field(default_factory=time.time)
    expires_at: float
    state: SessionState = SessionState.ACTIVE
    
    # Security tracking
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    fingerprint: Optional[str] = None
    
    # CSRF protection
    csrf_token: Optional[str] = None
    
    # Activity tracking
    request_count: int = 0
    last_renewed: Optional[float] = None
    failed_validations: int = 0
    
    # Custom data
    data: Dict[str, Any] = Field(default_factory=dict)
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if session is expired.
        
        Args:
            current_time: Current timestamp (defaults to now)
            
        Returns:
            True if session is expired
        """
        if current_time is None:
            current_time = time.time()
        
        return current_time >= self.expires_at or self.state in [SessionState.EXPIRED, SessionState.INVALIDATED]
    
    def is_idle_expired(self, idle_timeout: int, current_time: Optional[float] = None) -> bool:
        """Check if session has exceeded idle timeout.
        
        Args:
            idle_timeout: Idle timeout in seconds
            current_time: Current timestamp (defaults to now)
            
        Returns:
            True if idle timeout exceeded
        """
        if current_time is None:
            current_time = time.time()
        
        return (current_time - self.last_accessed) >= idle_timeout
    
    def needs_renewal(self, config: SessionConfig, current_time: Optional[float] = None) -> bool:
        """Check if session needs renewal.
        
        Args:
            config: Session configuration
            current_time: Current timestamp (defaults to now)
            
        Returns:
            True if session needs renewal
        """
        if not config.auto_renew or current_time is None:
            current_time = time.time()
        
        # Calculate renewal time based on threshold
        session_duration = self.expires_at - self.created_at
        renewal_time = self.created_at + (session_duration * config.renew_threshold)
        
        return current_time >= renewal_time
    
    def update_activity(self, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> None:
        """Update session activity.
        
        Args:
            ip_address: Client IP address
            user_agent: Client user agent
        """
        self.last_accessed = time.time()
        self.request_count += 1
        
        if ip_address:
            self.ip_address = ip_address
        if user_agent:
            self.user_agent = user_agent


class SessionStorage(ABC):
    """Abstract base class for session storage backends."""
    
    @abstractmethod
    async def get(self, session_id: str) -> Optional[SessionData]:
        """Get session data by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data or None if not found
        """
        pass
    
    @abstractmethod
    async def set(self, session_id: str, session_data: SessionData) -> bool:
        """Store session data.
        
        Args:
            session_id: Session identifier
            session_data: Session data to store
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    async def delete(self, session_id: str) -> bool:
        """Delete session data.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        pass
    
    @abstractmethod
    async def get_user_sessions(self, user_id: str) -> List[SessionData]:
        """Get all active sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of active sessions
        """
        pass


class MemorySessionStorage(SessionStorage):
    """In-memory session storage implementation."""
    
    def __init__(self, config: SessionConfig):
        """Initialize memory storage.
        
        Args:
            config: Session configuration
        """
        self.config = config
        self.sessions: Dict[str, SessionData] = {}
        self.user_sessions: Dict[str, Set[str]] = {}
        self.last_cleanup = time.time()
    
    async def get(self, session_id: str) -> Optional[SessionData]:
        """Get session data by ID."""
        return self.sessions.get(session_id)
    
    async def set(self, session_id: str, session_data: SessionData) -> bool:
        """Store session data."""
        try:
            self.sessions[session_id] = session_data
            
            # Track user sessions
            if session_data.user_id:
                if session_data.user_id not in self.user_sessions:
                    self.user_sessions[session_data.user_id] = set()
                self.user_sessions[session_data.user_id].add(session_id)
            
            # Cleanup if needed
            await self._periodic_cleanup()
            
            return True
        except Exception:
            return False
    
    async def delete(self, session_id: str) -> bool:
        """Delete session data."""
        try:
            session_data = self.sessions.get(session_id)
            if session_data and session_data.user_id:
                # Remove from user sessions tracking
                if session_data.user_id in self.user_sessions:
                    self.user_sessions[session_data.user_id].discard(session_id)
                    if not self.user_sessions[session_data.user_id]:
                        del self.user_sessions[session_data.user_id]
            
            if session_id in self.sessions:
                del self.sessions[session_id]
                return True
            
            return False
        except Exception:
            return False
    
    async def cleanup_expired(self) -> int:
        """Clean up expired sessions."""
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session_data in self.sessions.items():
            if (session_data.is_expired(current_time) or 
                session_data.is_idle_expired(self.config.idle_timeout, current_time)):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            await self.delete(session_id)
        
        self.last_cleanup = current_time
        return len(expired_sessions)
    
    async def get_user_sessions(self, user_id: str) -> List[SessionData]:
        """Get all active sessions for a user."""
        if user_id not in self.user_sessions:
            return []
        
        sessions = []
        for session_id in list(self.user_sessions[user_id]):
            session_data = self.sessions.get(session_id)
            if session_data and not session_data.is_expired():
                sessions.append(session_data)
            else:
                # Clean up invalid session reference
                self.user_sessions[user_id].discard(session_id)
        
        return sessions
    
    async def _periodic_cleanup(self) -> None:
        """Perform periodic cleanup if needed."""
        current_time = time.time()
        if (current_time - self.last_cleanup) >= self.config.cleanup_interval:
            await self.cleanup_expired()


class SessionManager:
    """Session management engine."""
    
    def __init__(self, config: SessionConfig, storage: Optional[SessionStorage] = None):
        """Initialize session manager.
        
        Args:
            config: Session configuration
            storage: Session storage backend (defaults to memory)
        """
        self.config = config
        self.storage = storage or MemorySessionStorage(config)
    
    def generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID.
        
        Returns:
            Secure session identifier
        """
        if self.config.use_secure_random:
            # Use secrets module for cryptographic randomness
            return secrets.token_urlsafe(self.config.token_length)
        else:
            # Fallback to less secure but faster method
            return hashlib.sha256(
                str(time.time()).encode() + 
                str(secrets.randbits(64)).encode()
            ).hexdigest()[:self.config.token_length]
    
    def generate_csrf_token(self) -> str:
        """Generate CSRF token.
        
        Returns:
            CSRF token
        """
        return secrets.token_urlsafe(self.config.csrf_token_length)
    
    def generate_fingerprint(self, request: Request) -> str:
        """Generate request fingerprint for security tracking.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Request fingerprint
        """
        components = []
        
        # Add User-Agent if available
        user_agent = request.headers.get('user-agent', '')
        components.append(user_agent)
        
        # Add Accept headers for more entropy
        accept = request.headers.get('accept', '')
        accept_language = request.headers.get('accept-language', '')
        accept_encoding = request.headers.get('accept-encoding', '')
        
        components.extend([accept, accept_language, accept_encoding])
        
        # Create fingerprint hash
        fingerprint_data = '|'.join(components).encode()
        return hashlib.sha256(fingerprint_data).hexdigest()[:16]
    
    async def create_session(
        self, 
        request: Request, 
        user_id: Optional[str] = None,
        initial_data: Optional[Dict[str, Any]] = None
    ) -> SessionData:
        """Create a new session.
        
        Args:
            request: FastAPI request object
            user_id: Optional user identifier
            initial_data: Optional initial session data
            
        Returns:
            New session data
        """
        # Generate session ID
        session_id = self.generate_session_id()
        
        # Create session data
        current_time = time.time()
        session_data = SessionData(
            session_id=session_id,
            user_id=user_id,
            created_at=current_time,
            last_accessed=current_time,
            expires_at=current_time + self.config.max_age,
            ip_address=self._get_client_ip(request),
            user_agent=request.headers.get('user-agent'),
            fingerprint=self.generate_fingerprint(request),
            data=initial_data or {},
        )
        
        # Generate CSRF token if enabled
        if self.config.csrf_protection != CSRFProtection.DISABLED:
            session_data.csrf_token = self.generate_csrf_token()
        
        # Handle concurrent session limits
        if user_id and self.config.max_sessions_per_user:
            await self._enforce_session_limits(user_id)
        
        # Store session
        await self.storage.set(session_id, session_data)
        
        return session_data
    
    async def get_session(self, request: Request) -> Optional[SessionData]:
        """Get session from request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Session data if valid, None otherwise
        """
        # Extract session ID from cookie
        session_id = request.cookies.get(self.config.session_name)
        if not session_id:
            return None
        
        # Get session from storage
        session_data = await self.storage.get(session_id)
        if not session_data:
            return None
        
        # Validate session
        current_time = time.time()
        
        # Check if expired
        if session_data.is_expired(current_time):
            await self.invalidate_session(session_id)
            return None
        
        # Check idle timeout
        if session_data.is_idle_expired(self.config.idle_timeout, current_time):
            await self.invalidate_session(session_id)
            return None
        
        # Security validations
        if await self._validate_session_security(request, session_data):
            # Update activity
            session_data.update_activity(
                self._get_client_ip(request),
                request.headers.get('user-agent')
            )
            
            # Store updated session
            await self.storage.set(session_id, session_data)
            
            return session_data
        else:
            # Security validation failed
            session_data.failed_validations += 1
            if session_data.failed_validations >= self.config.max_failed_validations:
                await self.invalidate_session(session_id)
                return None
            
            await self.storage.set(session_id, session_data)
            return None
    
    async def renew_session(self, request: Request, session_data: SessionData) -> SessionData:
        """Renew session with new ID to prevent fixation attacks.
        
        Args:
            request: FastAPI request object
            session_data: Current session data
            
        Returns:
            Renewed session data
        """
        # Generate new session ID
        new_session_id = self.generate_session_id()
        old_session_id = session_data.session_id
        
        # Update session data
        current_time = time.time()
        session_data.session_id = new_session_id
        session_data.last_renewed = current_time
        session_data.expires_at = current_time + self.config.max_age
        session_data.state = SessionState.RENEWED
        
        # Generate new CSRF token
        if self.config.csrf_protection != CSRFProtection.DISABLED:
            session_data.csrf_token = self.generate_csrf_token()
        
        # Store new session and remove old one
        await self.storage.set(new_session_id, session_data)
        await self.storage.delete(old_session_id)
        
        return session_data
    
    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful
        """
        # Get session to update state
        session_data = await self.storage.get(session_id)
        if session_data:
            session_data.state = SessionState.INVALIDATED
            await self.storage.set(session_id, session_data)
        
        # Delete from storage
        return await self.storage.delete(session_id)
    
    async def invalidate_user_sessions(self, user_id: str, except_session_id: Optional[str] = None) -> int:
        """Invalidate all sessions for a user.
        
        Args:
            user_id: User identifier
            except_session_id: Session ID to exclude from invalidation
            
        Returns:
            Number of sessions invalidated
        """
        user_sessions = await self.storage.get_user_sessions(user_id)
        count = 0
        
        for session_data in user_sessions:
            if session_data.session_id != except_session_id:
                if await self.invalidate_session(session_data.session_id):
                    count += 1
        
        return count
    
    async def validate_csrf_token(self, request: Request, session_data: SessionData) -> bool:
        """Validate CSRF token.
        
        Args:
            request: FastAPI request object
            session_data: Session data
            
        Returns:
            True if CSRF token is valid
        """
        if self.config.csrf_protection == CSRFProtection.DISABLED:
            return True
        
        if not session_data.csrf_token:
            return False
        
        # Get token from request
        csrf_token = None
        
        # Check header first
        csrf_token = request.headers.get(self.config.csrf_header_name.lower())
        
        # Check form data if POST request and no header token
        if not csrf_token and request.method == "POST":
            try:
                form = await request.form()
                csrf_token = form.get(self.config.csrf_form_field)
            except Exception:
                pass
        
        if not csrf_token:
            return False
        
        # Compare tokens
        return hmac.compare_digest(session_data.csrf_token, csrf_token)
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Client IP address
        """
        # Check for forwarded headers (in order of preference)
        forwarded_headers = [
            'x-forwarded-for',
            'x-real-ip',
            'cf-connecting-ip',  # Cloudflare
            'x-client-ip',
            'forwarded'
        ]
        
        for header in forwarded_headers:
            if header in request.headers:
                ip = request.headers[header].split(',')[0].strip()
                if ip and ip != 'unknown':
                    return ip
        
        # Fallback to client host
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return 'unknown'
    
    async def _validate_session_security(self, request: Request, session_data: SessionData) -> bool:
        """Validate session security constraints.
        
        Args:
            request: FastAPI request object
            session_data: Session data
            
        Returns:
            True if security validation passes
        """
        current_ip = self._get_client_ip(request)
        current_user_agent = request.headers.get('user-agent')
        
        # IP address validation
        if (self.config.track_ip_addresses and 
            self.config.force_renewal_on_ip_change and 
            session_data.ip_address and 
            session_data.ip_address != current_ip):
            return False
        
        # User-agent validation
        if (self.config.track_user_agents and 
            self.config.force_renewal_on_user_agent_change and 
            session_data.user_agent and 
            session_data.user_agent != current_user_agent):
            return False
        
        return True
    
    async def _enforce_session_limits(self, user_id: str) -> None:
        """Enforce maximum concurrent sessions per user.
        
        Args:
            user_id: User identifier
        """
        if not self.config.max_sessions_per_user:
            return
        
        user_sessions = await self.storage.get_user_sessions(user_id)
        
        if len(user_sessions) >= self.config.max_sessions_per_user:
            # Remove oldest sessions
            user_sessions.sort(key=lambda s: s.last_accessed)
            sessions_to_remove = len(user_sessions) - self.config.max_sessions_per_user + 1
            
            for i in range(sessions_to_remove):
                await self.invalidate_session(user_sessions[i].session_id)


class SessionShield:
    """Session management shield for FastAPI endpoints."""
    
    def __init__(self, config: SessionConfig, storage: Optional[SessionStorage] = None):
        """Initialize session shield.
        
        Args:
            config: Session configuration
            storage: Session storage backend
        """
        self.config = config
        self.manager = SessionManager(config, storage)
    
    def create_shield(self, name: str = "SessionManagement") -> Shield:
        """Create a shield for session management.
        
        Args:
            name: Shield name
            
        Returns:
            Shield instance
        """
        
        async def session_management_shield(request: Request) -> Dict[str, Any]:
            """Session management shield function."""
            
            # Get or create session
            session_data = await self.manager.get_session(request)
            
            if not session_data:
                # Create new session for new requests
                session_data = await self.manager.create_session(request)
            
            # Check if session needs renewal
            if (session_data.needs_renewal(self.config) or 
                self.config.prevent_session_fixation):
                session_data = await self.manager.renew_session(request, session_data)
            
            # CSRF validation for state-changing methods
            if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
                if not await self.manager.validate_csrf_token(request, session_data):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="CSRF token validation failed",
                        headers={"X-CSRF-Error": "invalid_token"}
                    )
            
            # Set session cookies in response (will be handled by FastAPI middleware)
            response_headers = self._get_session_headers(session_data)
            
            # Return session information
            result = {
                "session_management_passed": True,
                "session_id": session_data.session_id,
                "user_id": session_data.user_id,
                "csrf_token": session_data.csrf_token,
                "session_state": session_data.state.value,
                "created_at": session_data.created_at,
                "expires_at": session_data.expires_at,
                "session_data": session_data,
                "response_headers": response_headers,
            }
            
            return result
        
        return shield(
            session_management_shield,
            name=name,
            auto_error=True,
        )
    
    def _get_session_headers(self, session_data: SessionData) -> Dict[str, str]:
        """Get response headers for session cookies.
        
        Args:
            session_data: Session data
            
        Returns:
            Dictionary of response headers
        """
        headers = {}
        
        # Session cookie
        cookie_attributes = []
        cookie_attributes.append(f"Max-Age={self.config.max_age}")
        cookie_attributes.append(f"Path={self.config.cookie_path}")
        
        if self.config.cookie_domain:
            cookie_attributes.append(f"Domain={self.config.cookie_domain}")
        
        if self.config.secure_cookies:
            cookie_attributes.append("Secure")
        
        if self.config.httponly_cookies:
            cookie_attributes.append("HttpOnly")
        
        cookie_attributes.append(f"SameSite={self.config.samesite_policy}")
        
        session_cookie = f"{session_data.session_id}; {'; '.join(cookie_attributes)}"
        headers[f"Set-Cookie"] = f"{self.config.session_name}={session_cookie}"
        
        # CSRF token cookie if needed
        if (self.config.csrf_protection == CSRFProtection.DOUBLE_SUBMIT and 
            session_data.csrf_token):
            csrf_cookie_attrs = cookie_attributes.copy()
            # CSRF token should not be HttpOnly for JavaScript access
            if "HttpOnly" in csrf_cookie_attrs:
                csrf_cookie_attrs.remove("HttpOnly")
            
            csrf_cookie = f"{session_data.csrf_token}; {'; '.join(csrf_cookie_attrs)}"
            headers["Set-Cookie"] += f", {self.config.csrf_token_name}={csrf_cookie}"
        
        return headers


def session_management_shield(
    max_age: int = 3600,
    idle_timeout: int = 1800,
    security_level: SessionSecurityLevel = SessionSecurityLevel.MEDIUM,
    csrf_protection: CSRFProtection = CSRFProtection.TOKEN,
    secure_cookies: bool = True,
    prevent_session_fixation: bool = True,
    name: str = "SessionManagement",
) -> Shield:
    """Create a session management shield.
    
    Args:
        max_age: Maximum session age in seconds
        idle_timeout: Idle timeout in seconds
        security_level: Session security level
        csrf_protection: CSRF protection mode
        secure_cookies: Use secure cookies
        prevent_session_fixation: Enable session fixation prevention
        name: Shield name
        
    Returns:
        Session management shield
        
    Examples:
        ```python
        # Basic session management
        @app.get("/dashboard")
        @session_management_shield()
        def dashboard():
            return {"message": "Protected dashboard"}
        
        # High security sessions
        @app.post("/admin/action")
        @session_management_shield(
            security_level=SessionSecurityLevel.HIGH,
            csrf_protection=CSRFProtection.DOUBLE_SUBMIT,
            max_age=1800  # 30 minutes
        )
        def admin_action():
            return {"status": "executed"}
        
        # API with CSRF protection
        @app.post("/api/update")
        @session_management_shield(
            csrf_protection=CSRFProtection.TOKEN,
            secure_cookies=True
        )
        def update_data():
            return {"updated": True}
        ```
    """
    config = SessionConfig(
        max_age=max_age,
        idle_timeout=idle_timeout,
        security_level=security_level,
        csrf_protection=csrf_protection,
        secure_cookies=secure_cookies,
        prevent_session_fixation=prevent_session_fixation,
    )
    
    shield_instance = SessionShield(config)
    return shield_instance.create_shield(name)


def secure_session_shield(
    name: str = "SecureSession",
) -> Shield:
    """Create a high-security session management shield.
    
    Args:
        name: Shield name
        
    Returns:
        Secure session management shield
        
    Examples:
        ```python
        @app.get("/secure/data")
        @secure_session_shield()
        def secure_data():
            return {"data": "highly protected"}
        ```
    """
    config = SessionConfig(
        max_age=1800,  # 30 minutes
        idle_timeout=900,  # 15 minutes
        security_level=SessionSecurityLevel.HIGH,
        csrf_protection=CSRFProtection.DOUBLE_SUBMIT,
        secure_cookies=True,
        httponly_cookies=True,
        samesite_policy="Strict",
        auto_renew=True,
        renew_threshold=0.3,  # Renew at 30% of lifetime
        prevent_session_fixation=True,
        force_renewal_on_ip_change=True,
        max_concurrent_sessions=3,
        max_failed_validations=2,
    )
    
    shield_instance = SessionShield(config)
    return shield_instance.create_shield(name)


def api_session_shield(
    csrf_protection: CSRFProtection = CSRFProtection.TOKEN,
    max_age: int = 7200,  # 2 hours
    name: str = "APISession",
) -> Shield:
    """Create a session management shield optimized for APIs.
    
    Args:
        csrf_protection: CSRF protection mode
        max_age: Session max age in seconds
        name: Shield name
        
    Returns:
        API session management shield
        
    Examples:
        ```python
        @app.post("/api/v1/data")
        @api_session_shield()
        def api_endpoint():
            return {"result": "success"}
        ```
    """
    config = SessionConfig(
        max_age=max_age,
        idle_timeout=max_age,  # No separate idle timeout for APIs
        security_level=SessionSecurityLevel.MEDIUM,
        csrf_protection=csrf_protection,
        secure_cookies=True,
        httponly_cookies=True,
        samesite_policy="Lax",
        auto_renew=False,  # Manual renewal for APIs
        prevent_session_fixation=False,  # Less critical for APIs
        track_user_agents=False,  # APIs may have varying user agents
        max_concurrent_sessions=10,  # More lenient for API clients
    )
    
    shield_instance = SessionShield(config)
    return shield_instance.create_shield(name)