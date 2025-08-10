"""Mock classes and utilities for OAuth2 PKCE shield testing."""

import asyncio
import base64
import hashlib
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Union, Callable
from unittest.mock import Mock, AsyncMock

from fastapi_shield.oauth2_pkce import (
    OAuth2Provider,
    OAuth2Storage,
    OAuth2Token,
    OAuth2State,
    PKCECodePair,
    AuthorizationCode,
    CodeChallengeMethod,
    TokenType,
    GrantType,
    OAuth2ExchangeError
)


class MockOAuth2Provider(OAuth2Provider):
    """Mock OAuth2 provider for testing."""
    
    def __init__(
        self,
        client_id: str = "test_client_id",
        client_secret: Optional[str] = "test_client_secret",
        should_fail_token_exchange: bool = False,
        should_fail_refresh: bool = False,
        should_fail_userinfo: bool = False,
        **kwargs
    ):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            userinfo_endpoint="https://auth.example.com/userinfo",
            scopes=["openid", "profile", "email"],
            **kwargs
        )
        
        self.should_fail_token_exchange = should_fail_token_exchange
        self.should_fail_refresh = should_fail_refresh
        self.should_fail_userinfo = should_fail_userinfo
        
        # Tracking
        self.token_exchange_calls: List[Dict[str, Any]] = []
        self.refresh_calls: List[Dict[str, Any]] = []
        self.userinfo_calls: List[Dict[str, Any]] = []
        
        # Mock responses
        self.mock_token_response = {
            "access_token": "mock_access_token",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token",
            "scope": "openid profile email"
        }
        
        self.mock_user_info = {
            "sub": "123456789",
            "name": "Test User",
            "email": "test@example.com",
            "picture": "https://example.com/avatar.jpg"
        }
    
    def get_provider_name(self) -> str:
        return "mock_provider"
    
    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str
    ) -> OAuth2Token:
        """Mock token exchange."""
        self.token_exchange_calls.append({
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "timestamp": time.time()
        })
        
        if self.should_fail_token_exchange:
            raise OAuth2ExchangeError("invalid_grant", "Mock token exchange failure")
        
        return OAuth2Token(
            access_token=self.mock_token_response["access_token"],
            token_type=TokenType.BEARER,
            expires_in=self.mock_token_response["expires_in"],
            refresh_token=self.mock_token_response["refresh_token"],
            scope=self.mock_token_response["scope"]
        )
    
    async def refresh_token(self, refresh_token: str) -> OAuth2Token:
        """Mock token refresh."""
        self.refresh_calls.append({
            "refresh_token": refresh_token,
            "timestamp": time.time()
        })
        
        if self.should_fail_refresh:
            raise OAuth2ExchangeError("invalid_grant", "Mock token refresh failure")
        
        return OAuth2Token(
            access_token="new_access_token",
            token_type=TokenType.BEARER,
            expires_in=3600,
            refresh_token=refresh_token,  # Keep same refresh token
            scope="openid profile email"
        )
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Mock user info retrieval."""
        self.userinfo_calls.append({
            "access_token": access_token,
            "timestamp": time.time()
        })
        
        if self.should_fail_userinfo:
            raise OAuth2ExchangeError("invalid_token", "Mock userinfo failure")
        
        return self.mock_user_info.copy()
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.token_exchange_calls = []
        self.refresh_calls = []
        self.userinfo_calls = []


class MockOAuth2Storage(OAuth2Storage):
    """Mock OAuth2 storage for testing."""
    
    def __init__(self):
        self.pkce_pairs: Dict[str, PKCECodePair] = {}
        self.states: Dict[str, OAuth2State] = {}
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.tokens: Dict[str, OAuth2Token] = {}
        
        # Tracking
        self.store_calls: Dict[str, List[Dict[str, Any]]] = {
            "pkce_pairs": [],
            "states": [],
            "authorization_codes": [],
            "tokens": []
        }
        self.get_calls: Dict[str, List[Dict[str, Any]]] = {
            "pkce_pairs": [],
            "states": [],
            "authorization_codes": [],
            "tokens": []
        }
        self.delete_calls: Dict[str, List[Dict[str, Any]]] = {
            "pkce_pairs": [],
            "states": [],
            "authorization_codes": [],
            "tokens": []
        }
        self.cleanup_calls: List[float] = []
    
    async def store_pkce_pair(self, session_id: str, pkce_pair: PKCECodePair) -> None:
        """Mock store PKCE pair."""
        self.store_calls["pkce_pairs"].append({
            "session_id": session_id,
            "pkce_pair": pkce_pair,
            "timestamp": time.time()
        })
        self.pkce_pairs[session_id] = pkce_pair
    
    async def get_pkce_pair(self, session_id: str) -> Optional[PKCECodePair]:
        """Mock get PKCE pair."""
        self.get_calls["pkce_pairs"].append({
            "session_id": session_id,
            "timestamp": time.time()
        })
        
        pkce_pair = self.pkce_pairs.get(session_id)
        if pkce_pair and pkce_pair.is_expired():
            del self.pkce_pairs[session_id]
            return None
        return pkce_pair
    
    async def delete_pkce_pair(self, session_id: str) -> None:
        """Mock delete PKCE pair."""
        self.delete_calls["pkce_pairs"].append({
            "session_id": session_id,
            "timestamp": time.time()
        })
        self.pkce_pairs.pop(session_id, None)
    
    async def store_state(self, state_value: str, state: OAuth2State) -> None:
        """Mock store state."""
        self.store_calls["states"].append({
            "state_value": state_value,
            "state": state,
            "timestamp": time.time()
        })
        self.states[state_value] = state
    
    async def get_state(self, state_value: str) -> Optional[OAuth2State]:
        """Mock get state."""
        self.get_calls["states"].append({
            "state_value": state_value,
            "timestamp": time.time()
        })
        
        state = self.states.get(state_value)
        if state and state.is_expired():
            del self.states[state_value]
            return None
        return state
    
    async def delete_state(self, state_value: str) -> None:
        """Mock delete state."""
        self.delete_calls["states"].append({
            "state_value": state_value,
            "timestamp": time.time()
        })
        self.states.pop(state_value, None)
    
    async def store_authorization_code(self, code: str, auth_code: AuthorizationCode) -> None:
        """Mock store authorization code."""
        self.store_calls["authorization_codes"].append({
            "code": code,
            "auth_code": auth_code,
            "timestamp": time.time()
        })
        self.authorization_codes[code] = auth_code
    
    async def get_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        """Mock get authorization code."""
        self.get_calls["authorization_codes"].append({
            "code": code,
            "timestamp": time.time()
        })
        
        auth_code = self.authorization_codes.get(code)
        if auth_code and auth_code.is_expired():
            del self.authorization_codes[code]
            return None
        return auth_code
    
    async def delete_authorization_code(self, code: str) -> None:
        """Mock delete authorization code."""
        self.delete_calls["authorization_codes"].append({
            "code": code,
            "timestamp": time.time()
        })
        self.authorization_codes.pop(code, None)
    
    async def store_token(self, token_key: str, token: OAuth2Token) -> None:
        """Mock store token."""
        self.store_calls["tokens"].append({
            "token_key": token_key,
            "token": token,
            "timestamp": time.time()
        })
        self.tokens[token_key] = token
    
    async def get_token(self, token_key: str) -> Optional[OAuth2Token]:
        """Mock get token."""
        self.get_calls["tokens"].append({
            "token_key": token_key,
            "timestamp": time.time()
        })
        
        token = self.tokens.get(token_key)
        if token and token.is_expired():
            del self.tokens[token_key]
            return None
        return token
    
    async def delete_token(self, token_key: str) -> None:
        """Mock delete token."""
        self.delete_calls["tokens"].append({
            "token_key": token_key,
            "timestamp": time.time()
        })
        self.tokens.pop(token_key, None)
    
    async def cleanup_expired(self) -> int:
        """Mock cleanup expired entries."""
        self.cleanup_calls.append(time.time())
        
        cleaned_count = 0
        current_time = datetime.now(timezone.utc)
        
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
    
    def reset_tracking(self):
        """Reset call tracking."""
        for key in self.store_calls:
            self.store_calls[key] = []
        for key in self.get_calls:
            self.get_calls[key] = []
        for key in self.delete_calls:
            self.delete_calls[key] = []
        self.cleanup_calls = []


def create_mock_pkce_pair(
    method: CodeChallengeMethod = CodeChallengeMethod.S256,
    expired: bool = False
) -> PKCECodePair:
    """Create a mock PKCE code pair for testing."""
    verifier = "test_code_verifier_" + secrets.token_urlsafe(32)
    
    if method == CodeChallengeMethod.PLAIN:
        challenge = verifier
    else:  # S256
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
    
    created_at = datetime.now(timezone.utc)
    if expired:
        created_at = created_at - timedelta(minutes=15)  # Make it expired
    
    return PKCECodePair(
        verifier=verifier,
        challenge=challenge,
        method=method,
        created_at=created_at
    )


def create_mock_oauth2_state(
    client_id: str = "test_client_id",
    redirect_uri: str = "https://app.example.com/callback",
    scopes: Optional[List[str]] = None,
    expired: bool = False
) -> OAuth2State:
    """Create a mock OAuth2 state for testing."""
    state_value = "test_state_" + secrets.token_urlsafe(16)
    created_at = datetime.now(timezone.utc)
    
    if expired:
        created_at = created_at - timedelta(minutes=15)  # Make it expired
    
    return OAuth2State(
        value=state_value,
        redirect_uri=redirect_uri,
        scopes=scopes or ["openid", "profile", "email"],
        client_id=client_id,
        created_at=created_at
    )


def create_mock_oauth2_token(
    access_token: str = "mock_access_token",
    expires_in: Optional[int] = 3600,
    refresh_token: Optional[str] = "mock_refresh_token",
    expired: bool = False
) -> OAuth2Token:
    """Create a mock OAuth2 token for testing."""
    created_at = datetime.now(timezone.utc)
    
    if expired and expires_in:
        created_at = created_at - timedelta(seconds=expires_in + 60)  # Make it expired
    
    return OAuth2Token(
        access_token=access_token,
        token_type=TokenType.BEARER,
        expires_in=expires_in,
        refresh_token=refresh_token,
        scope="openid profile email",
        created_at=created_at
    )


def create_mock_authorization_code(
    code: str = "test_auth_code",
    client_id: str = "test_client_id",
    redirect_uri: str = "https://app.example.com/callback",
    scopes: Optional[List[str]] = None,
    code_challenge: Optional[str] = None,
    expired: bool = False,
    used: bool = False
) -> AuthorizationCode:
    """Create a mock authorization code for testing."""
    created_at = datetime.now(timezone.utc)
    
    if expired:
        created_at = created_at - timedelta(minutes=15)  # Make it expired
    
    return AuthorizationCode(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scopes=scopes or ["openid", "profile", "email"],
        code_challenge=code_challenge,
        code_challenge_method=CodeChallengeMethod.S256 if code_challenge else None,
        created_at=created_at,
        used=used
    )


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(
        self,
        method: str = "GET",
        path: str = "/oauth2/authorize",
        query_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        form_data: Optional[Dict[str, str]] = None
    ):
        self.method = method
        self.url = Mock()
        self.url.path = path
        self.query_params = query_params or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self._form_data = form_data or {}
    
    async def form(self):
        """Mock form data."""
        return self._form_data
    
    async def body(self):
        """Mock request body."""
        return b""


class OAuth2FlowSimulator:
    """Helper class for simulating OAuth2 PKCE flows in tests."""
    
    def __init__(self, provider: MockOAuth2Provider, storage: MockOAuth2Storage):
        self.provider = provider
        self.storage = storage
        self.session_data: Dict[str, Any] = {}
    
    async def start_authorization_flow(
        self,
        client_id: Optional[str] = None,
        redirect_uri: str = "https://app.example.com/callback",
        scopes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Simulate starting an authorization flow."""
        from fastapi_shield.oauth2_pkce import PKCEGenerator, StateGenerator
        
        # Generate session ID and PKCE pair
        session_id = secrets.token_urlsafe(32)
        pkce_pair = PKCEGenerator.generate_pkce_pair()
        state_value = StateGenerator.generate_state()
        
        # Create state object
        state = OAuth2State(
            value=state_value,
            redirect_uri=redirect_uri,
            scopes=scopes or ["openid", "profile", "email"],
            client_id=client_id or self.provider.client_id
        )
        
        # Store data
        await self.storage.store_pkce_pair(session_id, pkce_pair)
        await self.storage.store_state(state_value, state)
        
        # Build authorization URL
        auth_url = self.provider.build_authorization_url(
            redirect_uri=redirect_uri,
            state=state_value,
            code_challenge=pkce_pair.challenge,
            code_challenge_method=pkce_pair.method,
            scopes=scopes or ["openid", "profile", "email"]
        )
        
        # Store session data for later use
        self.session_data[session_id] = {
            "pkce_pair": pkce_pair,
            "state": state,
            "auth_url": auth_url
        }
        
        return {
            "session_id": session_id,
            "state": state_value,
            "code_challenge": pkce_pair.challenge,
            "code_verifier": pkce_pair.verifier,
            "authorization_url": auth_url
        }
    
    async def simulate_callback(
        self,
        session_id: str,
        authorization_code: str = "test_auth_code",
        include_error: Optional[str] = None
    ) -> Dict[str, Any]:
        """Simulate OAuth2 callback with authorization code."""
        if include_error:
            return {
                "error": include_error,
                "error_description": f"Mock {include_error} error"
            }
        
        session_data = self.session_data.get(session_id)
        if not session_data:
            raise ValueError("Session not found")
        
        # Exchange code for token
        token = await self.provider.exchange_code_for_token(
            code=authorization_code,
            redirect_uri=session_data["state"].redirect_uri,
            code_verifier=session_data["pkce_pair"].verifier
        )
        
        # Store token
        token_key = f"user_{session_id}"
        await self.storage.store_token(token_key, token)
        
        # Clean up PKCE pair and state
        await self.storage.delete_pkce_pair(session_id)
        await self.storage.delete_state(session_data["state"].value)
        
        return {
            "access_token": token.access_token,
            "token_type": token.token_type.value,
            "expires_in": token.expires_in,
            "refresh_token": token.refresh_token,
            "scope": token.scope,
            "session_id": session_id
        }
    
    def reset_session_data(self):
        """Reset session data."""
        self.session_data = {}


class PKCETestHelper:
    """Helper class for PKCE-specific testing utilities."""
    
    @staticmethod
    def create_valid_verifier_challenge_pair() -> Dict[str, str]:
        """Create a valid PKCE verifier/challenge pair."""
        from fastapi_shield.oauth2_pkce import PKCEGenerator
        
        pair = PKCEGenerator.generate_pkce_pair(CodeChallengeMethod.S256)
        return {
            "verifier": pair.verifier,
            "challenge": pair.challenge,
            "method": pair.method.value
        }
    
    @staticmethod
    def create_invalid_verifier_challenge_pair() -> Dict[str, str]:
        """Create an invalid PKCE verifier/challenge pair."""
        return {
            "verifier": "invalid_verifier",
            "challenge": "invalid_challenge",
            "method": CodeChallengeMethod.S256.value
        }
    
    @staticmethod
    def verify_pkce_challenge(verifier: str, challenge: str, method: CodeChallengeMethod) -> bool:
        """Verify a PKCE challenge against a verifier."""
        if method == CodeChallengeMethod.PLAIN:
            return verifier == challenge
        elif method == CodeChallengeMethod.S256:
            digest = hashlib.sha256(verifier.encode('utf-8')).digest()
            expected_challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
            return challenge == expected_challenge
        return False


class SecurityTestHelper:
    """Helper class for security-related testing."""
    
    @staticmethod
    def test_state_entropy(state_values: List[str]) -> Dict[str, Any]:
        """Test the entropy of generated state values."""
        if not state_values:
            return {"entropy": 0, "unique_count": 0, "duplicates": []}
        
        unique_values = set(state_values)
        duplicate_count = len(state_values) - len(unique_values)
        
        # Simple entropy calculation based on unique character distribution
        all_chars = ''.join(state_values)
        char_counts = {}
        for char in all_chars:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        total_chars = len(all_chars)
        entropy = 0
        for count in char_counts.values():
            probability = count / total_chars
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)
        
        return {
            "entropy": entropy,
            "unique_count": len(unique_values),
            "total_count": len(state_values),
            "duplicate_count": duplicate_count,
            "uniqueness_ratio": len(unique_values) / len(state_values)
        }
    
    @staticmethod
    def test_timing_attack_resistance(operations: List[Callable], iterations: int = 100) -> Dict[str, float]:
        """Test operations for timing attack resistance."""
        timings = {f"operation_{i}": [] for i in range(len(operations))}
        
        for _ in range(iterations):
            for i, operation in enumerate(operations):
                start_time = time.perf_counter()
                try:
                    operation()
                except Exception:
                    pass  # Ignore errors, we're measuring timing
                end_time = time.perf_counter()
                timings[f"operation_{i}"].append(end_time - start_time)
        
        # Calculate statistics
        stats = {}
        for operation_name, times in timings.items():
            avg_time = sum(times) / len(times)
            variance = sum((t - avg_time) ** 2 for t in times) / len(times)
            std_dev = variance ** 0.5
            
            stats[operation_name] = {
                "average": avg_time,
                "variance": variance,
                "std_deviation": std_dev,
                "min": min(times),
                "max": max(times)
            }
        
        return stats


class TokenValidationHelper:
    """Helper for token validation testing."""
    
    @staticmethod
    def create_jwt_like_token(payload: Dict[str, Any], expired: bool = False) -> str:
        """Create a JWT-like token for testing (not a real JWT)."""
        import json
        
        if expired:
            payload["exp"] = int(time.time()) - 3600  # Expired 1 hour ago
        else:
            payload["exp"] = int(time.time()) + 3600  # Expires in 1 hour
        
        # Simple base64 encoding (not a real JWT)
        header = {"alg": "HS256", "typ": "JWT"}
        encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        return f"{encoded_header}.{encoded_payload}.mock_signature"
    
    @staticmethod
    def extract_payload_from_mock_jwt(token: str) -> Dict[str, Any]:
        """Extract payload from mock JWT token."""
        import json
        
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {}
            
            # Decode payload
            payload_b64 = parts[1]
            # Add padding if needed
            payload_b64 += '=' * (4 - len(payload_b64) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_bytes.decode())
        except Exception:
            return {}
    
    @staticmethod
    def is_mock_token_expired(token: str) -> bool:
        """Check if mock JWT token is expired."""
        payload = TokenValidationHelper.extract_payload_from_mock_jwt(token)
        exp = payload.get("exp")
        if exp is None:
            return False
        return int(time.time()) > exp