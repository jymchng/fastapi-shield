"""OAuth2 PKCE (Proof Key for Code Exchange) shield for FastAPI Shield.

This module implements OAuth2 PKCE flow validation according to RFC 7636,
providing secure authentication for mobile and single-page applications.
It includes code challenge/verifier validation, state parameter handling,
token exchange, and integration with popular OAuth2 providers.
"""

import asyncio
import base64
import hashlib
import secrets
import time
import urllib.parse
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlencode, parse_qs, urlparse

import httpx
from fastapi import HTTPException, Request, Response, status

from fastapi_shield.shield import Shield


class CodeChallengeMethod(str, Enum):
    """PKCE code challenge methods as defined in RFC 7636."""
    PLAIN = "plain"
    S256 = "S256"


class TokenType(str, Enum):
    """OAuth2 token types."""
    BEARER = "bearer"
    MAC = "mac"


class GrantType(str, Enum):
    """OAuth2 grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"


class OAuth2Error(str, Enum):
    """OAuth2 error codes as defined in RFC 6749."""
    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_SCOPE = "invalid_scope"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"


@dataclass
class PKCECodePair:
    """PKCE code verifier and challenge pair."""
    verifier: str
    challenge: str
    method: CodeChallengeMethod
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.expires_at is None:
            # PKCE codes typically expire within 10 minutes
            self.expires_at = self.created_at + timedelta(minutes=10)
    
    def is_expired(self) -> bool:
        """Check if the PKCE code pair has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def verify(self, code_verifier: str) -> bool:
        """Verify that the provided code verifier matches this challenge."""
        if self.is_expired():
            return False
        
        if self.method == CodeChallengeMethod.PLAIN:
            return self.challenge == code_verifier
        elif self.method == CodeChallengeMethod.S256:
            # Generate challenge from verifier and compare
            digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
            generated_challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
            return self.challenge == generated_challenge
        
        return False


@dataclass
class OAuth2State:
    """OAuth2 state parameter for CSRF protection."""
    value: str
    redirect_uri: str
    scopes: List[str]
    client_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.expires_at is None:
            # State parameters typically expire within 10 minutes
            self.expires_at = self.created_at + timedelta(minutes=10)
    
    def is_expired(self) -> bool:
        """Check if the state has expired."""
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class OAuth2Token:
    """OAuth2 access token and related information."""
    access_token: str
    token_type: TokenType
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.expires_at is None and self.expires_in is not None:
            self.expires_at = self.created_at + timedelta(seconds=self.expires_in)
    
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary format."""
        token_dict = {
            "access_token": self.access_token,
            "token_type": self.token_type.value,
        }
        
        if self.expires_in is not None:
            token_dict["expires_in"] = self.expires_in
        if self.refresh_token is not None:
            token_dict["refresh_token"] = self.refresh_token
        if self.scope is not None:
            token_dict["scope"] = self.scope
        if self.id_token is not None:
            token_dict["id_token"] = self.id_token
        
        return token_dict


@dataclass
class AuthorizationCode:
    """OAuth2 authorization code."""
    code: str
    client_id: str
    redirect_uri: str
    scopes: List[str]
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[CodeChallengeMethod] = None
    state: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    used: bool = False
    
    def __post_init__(self):
        if self.expires_at is None:
            # Authorization codes typically expire within 10 minutes
            self.expires_at = self.created_at + timedelta(minutes=10)
    
    def is_expired(self) -> bool:
        """Check if the authorization code has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if the authorization code is valid (not expired and not used)."""
        return not self.is_expired() and not self.used
    
    def use(self) -> None:
        """Mark the authorization code as used."""
        self.used = True


class PKCEGenerator:
    """Utility class for generating PKCE code verifiers and challenges."""
    
    # RFC 7636 specifies minimum length of 43 and maximum of 128
    MIN_VERIFIER_LENGTH = 43
    MAX_VERIFIER_LENGTH = 128
    DEFAULT_VERIFIER_LENGTH = 128
    
    @staticmethod
    def generate_code_verifier(length: int = DEFAULT_VERIFIER_LENGTH) -> str:
        """Generate a cryptographically random code verifier.
        
        Args:
            length: Length of the code verifier (43-128 characters)
            
        Returns:
            Base64URL-encoded code verifier
            
        Raises:
            ValueError: If length is outside the valid range
        """
        if not (PKCEGenerator.MIN_VERIFIER_LENGTH <= length <= PKCEGenerator.MAX_VERIFIER_LENGTH):
            raise ValueError(
                f"Code verifier length must be between {PKCEGenerator.MIN_VERIFIER_LENGTH} "
                f"and {PKCEGenerator.MAX_VERIFIER_LENGTH} characters"
            )
        
        # Generate random bytes and encode as base64url
        random_bytes = secrets.token_bytes(length)
        return base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')[:length]
    
    @staticmethod
    def generate_code_challenge(code_verifier: str, method: CodeChallengeMethod = CodeChallengeMethod.S256) -> str:
        """Generate a code challenge from a code verifier.
        
        Args:
            code_verifier: The code verifier string
            method: The challenge method (plain or S256)
            
        Returns:
            The code challenge string
        """
        if method == CodeChallengeMethod.PLAIN:
            return code_verifier
        elif method == CodeChallengeMethod.S256:
            digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
            return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        else:
            raise ValueError(f"Unsupported challenge method: {method}")
    
    @staticmethod
    def generate_pkce_pair(
        method: CodeChallengeMethod = CodeChallengeMethod.S256,
        verifier_length: int = DEFAULT_VERIFIER_LENGTH
    ) -> PKCECodePair:
        """Generate a complete PKCE code verifier/challenge pair.
        
        Args:
            method: The challenge method to use
            verifier_length: Length of the code verifier
            
        Returns:
            PKCECodePair with verifier and challenge
        """
        verifier = PKCEGenerator.generate_code_verifier(verifier_length)
        challenge = PKCEGenerator.generate_code_challenge(verifier, method)
        
        return PKCECodePair(
            verifier=verifier,
            challenge=challenge,
            method=method
        )


class StateGenerator:
    """Utility class for generating OAuth2 state parameters."""
    
    DEFAULT_STATE_LENGTH = 32
    
    @staticmethod
    def generate_state(length: int = DEFAULT_STATE_LENGTH) -> str:
        """Generate a cryptographically random state parameter.
        
        Args:
            length: Length of the state parameter in bytes
            
        Returns:
            Base64URL-encoded state parameter
        """
        random_bytes = secrets.token_bytes(length)
        return base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')


class OAuth2Provider(ABC):
    """Abstract base class for OAuth2 providers."""
    
    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        authorization_endpoint: str = "",
        token_endpoint: str = "",
        userinfo_endpoint: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        timeout: int = 30
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.scopes = scopes or []
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Get the name of the OAuth2 provider."""
        pass
    
    def build_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: str,
        code_challenge_method: CodeChallengeMethod = CodeChallengeMethod.S256,
        scopes: Optional[List[str]] = None,
        additional_params: Optional[Dict[str, str]] = None
    ) -> str:
        """Build the authorization URL for the OAuth2 flow."""
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method.value,
        }
        
        # Add scopes
        scope_list = scopes or self.scopes
        if scope_list:
            params["scope"] = " ".join(scope_list)
        
        # Add additional parameters
        if additional_params:
            params.update(additional_params)
        
        return f"{self.authorization_endpoint}?{urlencode(params)}"
    
    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str
    ) -> OAuth2Token:
        """Exchange authorization code for access token."""
        token_data = {
            "grant_type": GrantType.AUTHORIZATION_CODE.value,
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        
        # Add client secret if available
        if self.client_secret:
            token_data["client_secret"] = self.client_secret
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        
        try:
            response = await self._client.post(
                self.token_endpoint,
                data=token_data,
                headers=headers
            )
            response.raise_for_status()
            
            token_response = response.json()
            
            return OAuth2Token(
                access_token=token_response["access_token"],
                token_type=TokenType(token_response.get("token_type", "bearer").lower()),
                expires_in=token_response.get("expires_in"),
                refresh_token=token_response.get("refresh_token"),
                scope=token_response.get("scope"),
                id_token=token_response.get("id_token")
            )
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                try:
                    error_data = e.response.json()
                    error_code = error_data.get("error", "invalid_grant")
                    error_description = error_data.get("error_description", "Token exchange failed")
                    raise OAuth2ExchangeError(error_code, error_description)
                except (ValueError, KeyError):
                    raise OAuth2ExchangeError("invalid_grant", "Token exchange failed")
            else:
                raise OAuth2ExchangeError("server_error", f"HTTP {e.response.status_code}")
        
        except httpx.RequestError as e:
            raise OAuth2ExchangeError("temporarily_unavailable", f"Network error: {str(e)}")
    
    async def refresh_token(self, refresh_token: str) -> OAuth2Token:
        """Refresh an access token using a refresh token."""
        if not refresh_token:
            raise OAuth2ExchangeError("invalid_request", "Refresh token is required")
        
        token_data = {
            "grant_type": GrantType.REFRESH_TOKEN.value,
            "client_id": self.client_id,
            "refresh_token": refresh_token,
        }
        
        if self.client_secret:
            token_data["client_secret"] = self.client_secret
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        
        try:
            response = await self._client.post(
                self.token_endpoint,
                data=token_data,
                headers=headers
            )
            response.raise_for_status()
            
            token_response = response.json()
            
            return OAuth2Token(
                access_token=token_response["access_token"],
                token_type=TokenType(token_response.get("token_type", "bearer").lower()),
                expires_in=token_response.get("expires_in"),
                refresh_token=token_response.get("refresh_token", refresh_token),
                scope=token_response.get("scope"),
                id_token=token_response.get("id_token")
            )
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                try:
                    error_data = e.response.json()
                    error_code = error_data.get("error", "invalid_grant")
                    error_description = error_data.get("error_description", "Token refresh failed")
                    raise OAuth2ExchangeError(error_code, error_description)
                except (ValueError, KeyError):
                    raise OAuth2ExchangeError("invalid_grant", "Token refresh failed")
            else:
                raise OAuth2ExchangeError("server_error", f"HTTP {e.response.status_code}")
        
        except httpx.RequestError as e:
            raise OAuth2ExchangeError("temporarily_unavailable", f"Network error: {str(e)}")
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information using the access token."""
        if not self.userinfo_endpoint:
            raise ValueError("Userinfo endpoint not configured for this provider")
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        
        try:
            response = await self._client.get(self.userinfo_endpoint, headers=headers)
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise OAuth2ExchangeError("invalid_token", "Invalid or expired access token")
            else:
                raise OAuth2ExchangeError("server_error", f"HTTP {e.response.status_code}")
        
        except httpx.RequestError as e:
            raise OAuth2ExchangeError("temporarily_unavailable", f"Network error: {str(e)}")
    
    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()


class GoogleOAuth2Provider(OAuth2Provider):
    """Google OAuth2 provider implementation."""
    
    def __init__(self, client_id: str, client_secret: Optional[str] = None, **kwargs):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
            token_endpoint="https://oauth2.googleapis.com/token",
            userinfo_endpoint="https://www.googleapis.com/oauth2/v2/userinfo",
            scopes=["openid", "email", "profile"],
            **kwargs
        )
    
    def get_provider_name(self) -> str:
        return "google"


class GitHubOAuth2Provider(OAuth2Provider):
    """GitHub OAuth2 provider implementation."""
    
    def __init__(self, client_id: str, client_secret: Optional[str] = None, **kwargs):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_endpoint="https://github.com/login/oauth/authorize",
            token_endpoint="https://github.com/login/oauth/access_token",
            userinfo_endpoint="https://api.github.com/user",
            scopes=["user:email"],
            **kwargs
        )
    
    def get_provider_name(self) -> str:
        return "github"


class MicrosoftOAuth2Provider(OAuth2Provider):
    """Microsoft OAuth2 provider implementation."""
    
    def __init__(self, client_id: str, client_secret: Optional[str] = None, tenant: str = "common", **kwargs):
        self.tenant = tenant
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_endpoint=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
            token_endpoint=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            userinfo_endpoint="https://graph.microsoft.com/v1.0/me",
            scopes=["openid", "profile", "email"],
            **kwargs
        )
    
    def get_provider_name(self) -> str:
        return "microsoft"


class OAuth2Storage(ABC):
    """Abstract base class for OAuth2 data storage."""
    
    @abstractmethod
    async def store_pkce_pair(self, session_id: str, pkce_pair: PKCECodePair) -> None:
        """Store PKCE code pair."""
        pass
    
    @abstractmethod
    async def get_pkce_pair(self, session_id: str) -> Optional[PKCECodePair]:
        """Retrieve PKCE code pair."""
        pass
    
    @abstractmethod
    async def delete_pkce_pair(self, session_id: str) -> None:
        """Delete PKCE code pair."""
        pass
    
    @abstractmethod
    async def store_state(self, state_value: str, state: OAuth2State) -> None:
        """Store OAuth2 state."""
        pass
    
    @abstractmethod
    async def get_state(self, state_value: str) -> Optional[OAuth2State]:
        """Retrieve OAuth2 state."""
        pass
    
    @abstractmethod
    async def delete_state(self, state_value: str) -> None:
        """Delete OAuth2 state."""
        pass
    
    @abstractmethod
    async def store_authorization_code(self, code: str, auth_code: AuthorizationCode) -> None:
        """Store authorization code."""
        pass
    
    @abstractmethod
    async def get_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        """Retrieve authorization code."""
        pass
    
    @abstractmethod
    async def delete_authorization_code(self, code: str) -> None:
        """Delete authorization code."""
        pass
    
    @abstractmethod
    async def store_token(self, token_key: str, token: OAuth2Token) -> None:
        """Store OAuth2 token."""
        pass
    
    @abstractmethod
    async def get_token(self, token_key: str) -> Optional[OAuth2Token]:
        """Retrieve OAuth2 token."""
        pass
    
    @abstractmethod
    async def delete_token(self, token_key: str) -> None:
        """Delete OAuth2 token."""
        pass
    
    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Clean up expired entries and return the count of cleaned items."""
        pass


class MemoryOAuth2Storage(OAuth2Storage):
    """In-memory storage for OAuth2 data (for development/testing)."""
    
    def __init__(self):
        self.pkce_pairs: Dict[str, PKCECodePair] = {}
        self.states: Dict[str, OAuth2State] = {}
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.tokens: Dict[str, OAuth2Token] = {}
        self._lock = asyncio.Lock()
    
    async def store_pkce_pair(self, session_id: str, pkce_pair: PKCECodePair) -> None:
        async with self._lock:
            self.pkce_pairs[session_id] = pkce_pair
    
    async def get_pkce_pair(self, session_id: str) -> Optional[PKCECodePair]:
        async with self._lock:
            pkce_pair = self.pkce_pairs.get(session_id)
            if pkce_pair and pkce_pair.is_expired():
                del self.pkce_pairs[session_id]
                return None
            return pkce_pair
    
    async def delete_pkce_pair(self, session_id: str) -> None:
        async with self._lock:
            self.pkce_pairs.pop(session_id, None)
    
    async def store_state(self, state_value: str, state: OAuth2State) -> None:
        async with self._lock:
            self.states[state_value] = state
    
    async def get_state(self, state_value: str) -> Optional[OAuth2State]:
        async with self._lock:
            state = self.states.get(state_value)
            if state and state.is_expired():
                del self.states[state_value]
                return None
            return state
    
    async def delete_state(self, state_value: str) -> None:
        async with self._lock:
            self.states.pop(state_value, None)
    
    async def store_authorization_code(self, code: str, auth_code: AuthorizationCode) -> None:
        async with self._lock:
            self.authorization_codes[code] = auth_code
    
    async def get_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        async with self._lock:
            auth_code = self.authorization_codes.get(code)
            if auth_code and auth_code.is_expired():
                del self.authorization_codes[code]
                return None
            return auth_code
    
    async def delete_authorization_code(self, code: str) -> None:
        async with self._lock:
            self.authorization_codes.pop(code, None)
    
    async def store_token(self, token_key: str, token: OAuth2Token) -> None:
        async with self._lock:
            self.tokens[token_key] = token
    
    async def get_token(self, token_key: str) -> Optional[OAuth2Token]:
        async with self._lock:
            token = self.tokens.get(token_key)
            if token and token.is_expired():
                del self.tokens[token_key]
                return None
            return token
    
    async def delete_token(self, token_key: str) -> None:
        async with self._lock:
            self.tokens.pop(token_key, None)
    
    async def cleanup_expired(self) -> int:
        async with self._lock:
            cleaned_count = 0
            
            # Clean up expired PKCE pairs
            expired_pkce = [k for k, v in self.pkce_pairs.items() if v.is_expired()]
            for key in expired_pkce:
                del self.pkce_pairs[key]
                cleaned_count += 1
            
            # Clean up expired states
            expired_states = [k for k, v in self.states.items() if v.is_expired()]
            for key in expired_states:
                del self.states[key]
                cleaned_count += 1
            
            # Clean up expired authorization codes
            expired_codes = [k for k, v in self.authorization_codes.items() if v.is_expired()]
            for key in expired_codes:
                del self.authorization_codes[key]
                cleaned_count += 1
            
            # Clean up expired tokens
            expired_tokens = [k for k, v in self.tokens.items() if v.is_expired()]
            for key in expired_tokens:
                del self.tokens[key]
                cleaned_count += 1
            
            return cleaned_count


class OAuth2ExchangeError(Exception):
    """Exception raised during OAuth2 token exchange."""
    
    def __init__(self, error_code: str, error_description: str):
        self.error_code = error_code
        self.error_description = error_description
        super().__init__(f"{error_code}: {error_description}")


@dataclass
class OAuth2PKCEConfig:
    """Configuration for OAuth2 PKCE shield."""
    
    provider: OAuth2Provider
    storage: OAuth2Storage
    redirect_uri: str
    scopes: Optional[List[str]] = None
    require_pkce: bool = True
    require_state: bool = True
    state_length: int = 32
    code_challenge_method: CodeChallengeMethod = CodeChallengeMethod.S256
    session_cookie_name: str = "oauth2_session"
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = True
    session_cookie_samesite: str = "lax"
    authorization_code_expiry_minutes: int = 10
    access_token_expiry_minutes: Optional[int] = None
    allow_localhost_redirect: bool = False
    validate_redirect_uri: bool = True
    cleanup_interval_minutes: int = 60
    on_success_callback: Optional[Callable[[OAuth2Token, Dict[str, Any]], None]] = None
    on_error_callback: Optional[Callable[[Exception], None]] = None


class OAuth2PKCEShield(Shield):
    """OAuth2 PKCE shield for secure authentication flow."""
    
    def __init__(self, config: OAuth2PKCEConfig):
        self.config = config
        self._last_cleanup = time.time()
        
        super().__init__(self._shield_function)
    
    async def _shield_function(self, request: Request) -> Optional[Dict[str, Any]]:
        """Main shield function for OAuth2 PKCE flow."""
        # Run periodic cleanup
        await self._periodic_cleanup()
        
        # Handle different OAuth2 flow endpoints
        path = request.url.path
        method = request.method
        
        if method == "GET" and path.endswith("/authorize"):
            return await self._handle_authorization_request(request)
        elif method == "GET" and path.endswith("/callback"):
            return await self._handle_callback_request(request)
        elif method == "POST" and path.endswith("/token"):
            return await self._handle_token_request(request)
        elif method == "POST" and path.endswith("/refresh"):
            return await self._handle_refresh_request(request)
        elif method == "GET" and path.endswith("/userinfo"):
            return await self._handle_userinfo_request(request)
        elif method == "POST" and path.endswith("/logout"):
            return await self._handle_logout_request(request)
        
        # For other requests, validate bearer token if present
        return await self._validate_bearer_token(request)
    
    async def _handle_authorization_request(self, request: Request) -> Dict[str, Any]:
        """Handle OAuth2 authorization request (initiate flow)."""
        try:
            # Generate session ID
            session_id = secrets.token_urlsafe(32)
            
            # Generate PKCE pair
            pkce_pair = PKCEGenerator.generate_pkce_pair(
                method=self.config.code_challenge_method
            )
            
            # Generate state parameter
            state_value = StateGenerator.generate_state(self.config.state_length)
            
            # Get scopes from request or use defaults
            scopes = self._get_scopes_from_request(request)
            
            # Create state object
            state = OAuth2State(
                value=state_value,
                redirect_uri=self.config.redirect_uri,
                scopes=scopes,
                client_id=self.config.provider.client_id
            )
            
            # Store PKCE pair and state
            await self.config.storage.store_pkce_pair(session_id, pkce_pair)
            await self.config.storage.store_state(state_value, state)
            
            # Build authorization URL
            auth_url = self.config.provider.build_authorization_url(
                redirect_uri=self.config.redirect_uri,
                state=state_value,
                code_challenge=pkce_pair.challenge,
                code_challenge_method=pkce_pair.method,
                scopes=scopes
            )
            
            return {
                "oauth2_authorization": {
                    "authorization_url": auth_url,
                    "session_id": session_id,
                    "state": state_value,
                    "code_challenge": pkce_pair.challenge,
                    "code_challenge_method": pkce_pair.method.value,
                    "scopes": scopes
                }
            }
            
        except Exception as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": OAuth2Error.SERVER_ERROR.value,
                    "error_description": "Failed to initiate OAuth2 flow"
                }
            )
    
    async def _handle_callback_request(self, request: Request) -> Dict[str, Any]:
        """Handle OAuth2 callback request (complete authorization)."""
        try:
            query_params = dict(request.query_params)
            
            # Check for error response
            if "error" in query_params:
                error_code = query_params["error"]
                error_description = query_params.get("error_description", "Authorization failed")
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": error_code,
                        "error_description": error_description
                    }
                )
            
            # Validate required parameters
            if "code" not in query_params:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": OAuth2Error.INVALID_REQUEST.value,
                        "error_description": "Missing authorization code"
                    }
                )
            
            if self.config.require_state and "state" not in query_params:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": OAuth2Error.INVALID_REQUEST.value,
                        "error_description": "Missing state parameter"
                    }
                )
            
            # Validate state parameter
            state_value = query_params.get("state")
            if state_value:
                state = await self.config.storage.get_state(state_value)
                if not state:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail={
                            "error": OAuth2Error.INVALID_REQUEST.value,
                            "error_description": "Invalid or expired state parameter"
                        }
                    )
                
                # Clean up state after use
                await self.config.storage.delete_state(state_value)
            
            # Get session ID from cookie
            session_id = request.cookies.get(self.config.session_cookie_name)
            if not session_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": OAuth2Error.INVALID_REQUEST.value,
                        "error_description": "Missing session information"
                    }
                )
            
            # Get PKCE pair
            pkce_pair = await self.config.storage.get_pkce_pair(session_id)
            if not pkce_pair:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": OAuth2Error.INVALID_REQUEST.value,
                        "error_description": "Invalid or expired PKCE session"
                    }
                )
            
            # Exchange authorization code for token
            auth_code = query_params["code"]
            token = await self.config.provider.exchange_code_for_token(
                code=auth_code,
                redirect_uri=self.config.redirect_uri,
                code_verifier=pkce_pair.verifier
            )
            
            # Store token
            token_key = f"user_{session_id}"
            await self.config.storage.store_token(token_key, token)
            
            # Clean up PKCE pair
            await self.config.storage.delete_pkce_pair(session_id)
            
            # Get user info if possible
            user_info = {}
            if self.config.provider.userinfo_endpoint:
                try:
                    user_info = await self.config.provider.get_user_info(token.access_token)
                except Exception:
                    # Non-fatal error, user info is optional
                    pass
            
            # Call success callback if configured
            if self.config.on_success_callback:
                self.config.on_success_callback(token, user_info)
            
            return {
                "oauth2_token": {
                    "access_token": token.access_token,
                    "token_type": token.token_type.value,
                    "expires_in": token.expires_in,
                    "scope": token.scope,
                    "user_info": user_info,
                    "session_id": session_id
                }
            }
            
        except HTTPException:
            raise
        except OAuth2ExchangeError as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": e.error_code,
                    "error_description": e.error_description
                }
            )
        except Exception as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": OAuth2Error.SERVER_ERROR.value,
                    "error_description": "Token exchange failed"
                }
            )
    
    async def _handle_token_request(self, request: Request) -> Dict[str, Any]:
        """Handle direct token request (for confidential clients)."""
        try:
            # This is typically for server-to-server flows
            # Parse form data
            form_data = await request.form()
            
            grant_type = form_data.get("grant_type")
            if grant_type != GrantType.AUTHORIZATION_CODE.value:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": OAuth2Error.UNSUPPORTED_GRANT_TYPE.value,
                        "error_description": "Only authorization_code grant type is supported"
                    }
                )
            
            # Validate required parameters
            required_params = ["code", "redirect_uri", "code_verifier"]
            for param in required_params:
                if param not in form_data:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail={
                            "error": OAuth2Error.INVALID_REQUEST.value,
                            "error_description": f"Missing required parameter: {param}"
                        }
                    )
            
            # Exchange code for token using provider
            token = await self.config.provider.exchange_code_for_token(
                code=form_data["code"],
                redirect_uri=form_data["redirect_uri"],
                code_verifier=form_data["code_verifier"]
            )
            
            return {"oauth2_token": token.to_dict()}
            
        except HTTPException:
            raise
        except OAuth2ExchangeError as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": e.error_code,
                    "error_description": e.error_description
                }
            )
        except Exception as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": OAuth2Error.SERVER_ERROR.value,
                    "error_description": "Token request failed"
                }
            )
    
    async def _handle_refresh_request(self, request: Request) -> Dict[str, Any]:
        """Handle token refresh request."""
        try:
            form_data = await request.form()
            
            refresh_token = form_data.get("refresh_token")
            if not refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": OAuth2Error.INVALID_REQUEST.value,
                        "error_description": "Missing refresh_token parameter"
                    }
                )
            
            # Refresh token using provider
            new_token = await self.config.provider.refresh_token(refresh_token)
            
            return {"oauth2_token": new_token.to_dict()}
            
        except HTTPException:
            raise
        except OAuth2ExchangeError as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": e.error_code,
                    "error_description": e.error_description
                }
            )
        except Exception as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": OAuth2Error.SERVER_ERROR.value,
                    "error_description": "Token refresh failed"
                }
            )
    
    async def _handle_userinfo_request(self, request: Request) -> Dict[str, Any]:
        """Handle user info request."""
        try:
            # Extract access token from Authorization header
            access_token = self._extract_bearer_token(request)
            if not access_token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "error": "invalid_token",
                        "error_description": "Missing or invalid access token"
                    }
                )
            
            # Get user info from provider
            user_info = await self.config.provider.get_user_info(access_token)
            
            return {"user_info": user_info}
            
        except HTTPException:
            raise
        except OAuth2ExchangeError as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": e.error_code,
                    "error_description": e.error_description
                }
            )
        except Exception as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": OAuth2Error.SERVER_ERROR.value,
                    "error_description": "Failed to get user info"
                }
            )
    
    async def _handle_logout_request(self, request: Request) -> Dict[str, Any]:
        """Handle logout request."""
        try:
            # Get session ID from cookie
            session_id = request.cookies.get(self.config.session_cookie_name)
            if session_id:
                # Clean up stored token
                token_key = f"user_{session_id}"
                await self.config.storage.delete_token(token_key)
                
                # Clean up any remaining PKCE data
                await self.config.storage.delete_pkce_pair(session_id)
            
            return {
                "oauth2_logout": {
                    "success": True,
                    "message": "Successfully logged out"
                }
            }
            
        except Exception as e:
            if self.config.on_error_callback:
                self.config.on_error_callback(e)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": OAuth2Error.SERVER_ERROR.value,
                    "error_description": "Logout failed"
                }
            )
    
    async def _validate_bearer_token(self, request: Request) -> Optional[Dict[str, Any]]:
        """Validate bearer token for protected resources."""
        # Extract token from Authorization header
        access_token = self._extract_bearer_token(request)
        
        if not access_token:
            # No token provided - let the application decide if this is required
            return None
        
        # For a full implementation, you would validate the token
        # This could involve JWT validation, database lookup, or provider verification
        # For now, we'll return basic token info
        return {
            "oauth2_validation": {
                "access_token_present": True,
                "token_type": "bearer"
            }
        }
    
    def _extract_bearer_token(self, request: Request) -> Optional[str]:
        """Extract bearer token from Authorization header."""
        authorization = request.headers.get("Authorization")
        if not authorization:
            return None
        
        try:
            scheme, token = authorization.split(" ", 1)
            if scheme.lower() != "bearer":
                return None
            return token
        except ValueError:
            return None
    
    def _get_scopes_from_request(self, request: Request) -> List[str]:
        """Get scopes from request or use defaults."""
        scope_param = request.query_params.get("scope")
        if scope_param:
            return scope_param.split()
        return self.config.scopes or self.config.provider.scopes
    
    async def _periodic_cleanup(self) -> None:
        """Run periodic cleanup of expired data."""
        current_time = time.time()
        cleanup_interval = self.config.cleanup_interval_minutes * 60
        
        if current_time - self._last_cleanup > cleanup_interval:
            await self.config.storage.cleanup_expired()
            self._last_cleanup = current_time


# Convenience functions for creating OAuth2 PKCE shields

def google_oauth2_pkce_shield(
    client_id: str,
    client_secret: Optional[str] = None,
    redirect_uri: str = "",
    scopes: Optional[List[str]] = None,
    storage: Optional[OAuth2Storage] = None
) -> OAuth2PKCEShield:
    """Create OAuth2 PKCE shield for Google authentication.
    
    Args:
        client_id: Google OAuth2 client ID
        client_secret: Google OAuth2 client secret (optional for public clients)
        redirect_uri: Authorized redirect URI
        scopes: OAuth2 scopes to request
        storage: Storage backend (defaults to MemoryOAuth2Storage)
    
    Returns:
        OAuth2PKCEShield configured for Google
    """
    provider = GoogleOAuth2Provider(client_id=client_id, client_secret=client_secret)
    
    config = OAuth2PKCEConfig(
        provider=provider,
        storage=storage or MemoryOAuth2Storage(),
        redirect_uri=redirect_uri,
        scopes=scopes or ["openid", "email", "profile"]
    )
    
    return OAuth2PKCEShield(config)


def github_oauth2_pkce_shield(
    client_id: str,
    client_secret: Optional[str] = None,
    redirect_uri: str = "",
    scopes: Optional[List[str]] = None,
    storage: Optional[OAuth2Storage] = None
) -> OAuth2PKCEShield:
    """Create OAuth2 PKCE shield for GitHub authentication.
    
    Args:
        client_id: GitHub OAuth2 client ID
        client_secret: GitHub OAuth2 client secret (optional for public clients)
        redirect_uri: Authorized redirect URI
        scopes: OAuth2 scopes to request
        storage: Storage backend (defaults to MemoryOAuth2Storage)
    
    Returns:
        OAuth2PKCEShield configured for GitHub
    """
    provider = GitHubOAuth2Provider(client_id=client_id, client_secret=client_secret)
    
    config = OAuth2PKCEConfig(
        provider=provider,
        storage=storage or MemoryOAuth2Storage(),
        redirect_uri=redirect_uri,
        scopes=scopes or ["user:email"]
    )
    
    return OAuth2PKCEShield(config)


def microsoft_oauth2_pkce_shield(
    client_id: str,
    client_secret: Optional[str] = None,
    redirect_uri: str = "",
    tenant: str = "common",
    scopes: Optional[List[str]] = None,
    storage: Optional[OAuth2Storage] = None
) -> OAuth2PKCEShield:
    """Create OAuth2 PKCE shield for Microsoft authentication.
    
    Args:
        client_id: Microsoft OAuth2 client ID
        client_secret: Microsoft OAuth2 client secret (optional for public clients)
        redirect_uri: Authorized redirect URI
        tenant: Microsoft tenant ID or 'common' for multi-tenant
        scopes: OAuth2 scopes to request
        storage: Storage backend (defaults to MemoryOAuth2Storage)
    
    Returns:
        OAuth2PKCEShield configured for Microsoft
    """
    provider = MicrosoftOAuth2Provider(
        client_id=client_id,
        client_secret=client_secret,
        tenant=tenant
    )
    
    config = OAuth2PKCEConfig(
        provider=provider,
        storage=storage or MemoryOAuth2Storage(),
        redirect_uri=redirect_uri,
        scopes=scopes or ["openid", "profile", "email"]
    )
    
    return OAuth2PKCEShield(config)


def custom_oauth2_pkce_shield(
    provider: OAuth2Provider,
    redirect_uri: str,
    scopes: Optional[List[str]] = None,
    storage: Optional[OAuth2Storage] = None,
    require_pkce: bool = True,
    require_state: bool = True
) -> OAuth2PKCEShield:
    """Create OAuth2 PKCE shield with custom provider.
    
    Args:
        provider: Custom OAuth2 provider implementation
        redirect_uri: Authorized redirect URI
        scopes: OAuth2 scopes to request
        storage: Storage backend (defaults to MemoryOAuth2Storage)
        require_pkce: Whether to require PKCE (recommended)
        require_state: Whether to require state parameter (recommended)
    
    Returns:
        OAuth2PKCEShield configured with custom provider
    """
    config = OAuth2PKCEConfig(
        provider=provider,
        storage=storage or MemoryOAuth2Storage(),
        redirect_uri=redirect_uri,
        scopes=scopes,
        require_pkce=require_pkce,
        require_state=require_state
    )
    
    return OAuth2PKCEShield(config)