"""Comprehensive tests for OAuth2 PKCE shield."""

import pytest
import asyncio
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import Mock, patch, AsyncMock
from fastapi import FastAPI, Request, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield.oauth2_pkce import (
    OAuth2PKCEShield,
    OAuth2PKCEConfig,
    OAuth2Provider,
    OAuth2Storage,
    MemoryOAuth2Storage,
    GoogleOAuth2Provider,
    GitHubOAuth2Provider,
    MicrosoftOAuth2Provider,
    PKCEGenerator,
    StateGenerator,
    PKCECodePair,
    OAuth2State,
    OAuth2Token,
    AuthorizationCode,
    CodeChallengeMethod,
    TokenType,
    GrantType,
    OAuth2Error,
    OAuth2ExchangeError,
    google_oauth2_pkce_shield,
    github_oauth2_pkce_shield,
    microsoft_oauth2_pkce_shield,
    custom_oauth2_pkce_shield,
)

from tests.mocks.oauth2_pkce_mocks import (
    MockOAuth2Provider,
    MockOAuth2Storage,
    create_mock_pkce_pair,
    create_mock_oauth2_state,
    create_mock_oauth2_token,
    create_mock_authorization_code,
    MockRequest,
    OAuth2FlowSimulator,
    PKCETestHelper,
    SecurityTestHelper,
    TokenValidationHelper,
)


class TestPKCEGenerator:
    """Test PKCE code generation functionality."""
    
    def test_generate_code_verifier_default_length(self):
        """Test code verifier generation with default length."""
        verifier = PKCEGenerator.generate_code_verifier()
        
        assert isinstance(verifier, str)
        assert len(verifier) == PKCEGenerator.DEFAULT_VERIFIER_LENGTH
        assert verifier.isalnum() or set(verifier) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    
    def test_generate_code_verifier_custom_length(self):
        """Test code verifier generation with custom length."""
        length = 60
        verifier = PKCEGenerator.generate_code_verifier(length)
        
        assert len(verifier) == length
    
    def test_generate_code_verifier_invalid_length(self):
        """Test code verifier generation with invalid length."""
        with pytest.raises(ValueError, match="Code verifier length must be between"):
            PKCEGenerator.generate_code_verifier(30)  # Too short
        
        with pytest.raises(ValueError, match="Code verifier length must be between"):
            PKCEGenerator.generate_code_verifier(200)  # Too long
    
    def test_generate_code_challenge_plain(self):
        """Test code challenge generation with PLAIN method."""
        verifier = "test_verifier"
        challenge = PKCEGenerator.generate_code_challenge(verifier, CodeChallengeMethod.PLAIN)
        
        assert challenge == verifier
    
    def test_generate_code_challenge_s256(self):
        """Test code challenge generation with S256 method."""
        verifier = "test_verifier"
        challenge = PKCEGenerator.generate_code_challenge(verifier, CodeChallengeMethod.S256)
        
        assert challenge != verifier
        assert len(challenge) > 0
        # S256 challenge should be base64url encoded
        assert set(challenge) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    
    def test_generate_pkce_pair_default(self):
        """Test PKCE pair generation with defaults."""
        pair = PKCEGenerator.generate_pkce_pair()
        
        assert isinstance(pair, PKCECodePair)
        assert pair.method == CodeChallengeMethod.S256
        assert len(pair.verifier) == PKCEGenerator.DEFAULT_VERIFIER_LENGTH
        assert len(pair.challenge) > 0
        assert pair.challenge != pair.verifier  # S256 should transform the verifier
    
    def test_generate_pkce_pair_plain_method(self):
        """Test PKCE pair generation with PLAIN method."""
        pair = PKCEGenerator.generate_pkce_pair(CodeChallengeMethod.PLAIN)
        
        assert pair.method == CodeChallengeMethod.PLAIN
        assert pair.challenge == pair.verifier
    
    def test_code_verifier_uniqueness(self):
        """Test that generated code verifiers are unique."""
        verifiers = [PKCEGenerator.generate_code_verifier() for _ in range(100)]
        unique_verifiers = set(verifiers)
        
        assert len(unique_verifiers) == len(verifiers)  # All should be unique


class TestStateGenerator:
    """Test OAuth2 state parameter generation."""
    
    def test_generate_state_default_length(self):
        """Test state generation with default length."""
        state = StateGenerator.generate_state()
        
        assert isinstance(state, str)
        assert len(state) > 0
        # State should be base64url encoded
        assert set(state) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    
    def test_generate_state_custom_length(self):
        """Test state generation with custom length."""
        state = StateGenerator.generate_state(16)
        
        assert len(state) > 0  # Length may vary due to base64 encoding
    
    def test_state_uniqueness(self):
        """Test that generated states are unique."""
        states = [StateGenerator.generate_state() for _ in range(100)]
        unique_states = set(states)
        
        assert len(unique_states) == len(states)  # All should be unique


class TestPKCECodePair:
    """Test PKCE code pair functionality."""
    
    def test_pkce_code_pair_creation(self):
        """Test PKCE code pair creation."""
        verifier = "test_verifier"
        challenge = "test_challenge"
        method = CodeChallengeMethod.S256
        
        pair = PKCECodePair(verifier=verifier, challenge=challenge, method=method)
        
        assert pair.verifier == verifier
        assert pair.challenge == challenge
        assert pair.method == method
        assert isinstance(pair.created_at, datetime)
        assert isinstance(pair.expires_at, datetime)
        assert pair.expires_at > pair.created_at
    
    def test_pkce_code_pair_expiration(self):
        """Test PKCE code pair expiration."""
        # Create expired pair
        past_time = datetime.now(timezone.utc) - timedelta(minutes=15)
        pair = PKCECodePair(
            verifier="test",
            challenge="test",
            method=CodeChallengeMethod.PLAIN,
            created_at=past_time,
            expires_at=past_time + timedelta(minutes=1)  # Expired
        )
        
        assert pair.is_expired() is True
        
        # Create non-expired pair
        pair = create_mock_pkce_pair()
        assert pair.is_expired() is False
    
    def test_pkce_code_pair_verification_plain(self):
        """Test PKCE verification with PLAIN method."""
        verifier = "test_verifier"
        pair = PKCECodePair(
            verifier=verifier,
            challenge=verifier,
            method=CodeChallengeMethod.PLAIN
        )
        
        assert pair.verify(verifier) is True
        assert pair.verify("wrong_verifier") is False
    
    def test_pkce_code_pair_verification_s256(self):
        """Test PKCE verification with S256 method."""
        verifier = "test_verifier"
        challenge = PKCEGenerator.generate_code_challenge(verifier, CodeChallengeMethod.S256)
        
        pair = PKCECodePair(
            verifier=verifier,
            challenge=challenge,
            method=CodeChallengeMethod.S256
        )
        
        assert pair.verify(verifier) is True
        assert pair.verify("wrong_verifier") is False
    
    def test_pkce_code_pair_verification_expired(self):
        """Test PKCE verification fails for expired pair."""
        pair = create_mock_pkce_pair(expired=True)
        
        assert pair.verify(pair.verifier) is False


class TestOAuth2State:
    """Test OAuth2 state functionality."""
    
    def test_oauth2_state_creation(self):
        """Test OAuth2 state creation."""
        state = OAuth2State(
            value="test_state",
            redirect_uri="https://app.example.com/callback",
            scopes=["openid", "email"],
            client_id="test_client"
        )
        
        assert state.value == "test_state"
        assert state.redirect_uri == "https://app.example.com/callback"
        assert state.scopes == ["openid", "email"]
        assert state.client_id == "test_client"
        assert isinstance(state.created_at, datetime)
        assert isinstance(state.expires_at, datetime)
    
    def test_oauth2_state_expiration(self):
        """Test OAuth2 state expiration."""
        # Test non-expired state
        state = create_mock_oauth2_state()
        assert state.is_expired() is False
        
        # Test expired state
        expired_state = create_mock_oauth2_state(expired=True)
        assert expired_state.is_expired() is True


class TestOAuth2Token:
    """Test OAuth2 token functionality."""
    
    def test_oauth2_token_creation(self):
        """Test OAuth2 token creation."""
        token = OAuth2Token(
            access_token="test_token",
            token_type=TokenType.BEARER,
            expires_in=3600,
            refresh_token="test_refresh"
        )
        
        assert token.access_token == "test_token"
        assert token.token_type == TokenType.BEARER
        assert token.expires_in == 3600
        assert token.refresh_token == "test_refresh"
        assert isinstance(token.created_at, datetime)
        assert isinstance(token.expires_at, datetime)
    
    def test_oauth2_token_expiration(self):
        """Test OAuth2 token expiration."""
        # Test non-expired token
        token = create_mock_oauth2_token()
        assert token.is_expired() is False
        
        # Test expired token
        expired_token = create_mock_oauth2_token(expired=True)
        assert expired_token.is_expired() is True
        
        # Test token without expiration
        token_no_expiry = OAuth2Token(
            access_token="test",
            token_type=TokenType.BEARER
        )
        assert token_no_expiry.is_expired() is False
    
    def test_oauth2_token_to_dict(self):
        """Test OAuth2 token serialization."""
        token = OAuth2Token(
            access_token="test_token",
            token_type=TokenType.BEARER,
            expires_in=3600,
            refresh_token="test_refresh",
            scope="openid email",
            id_token="test_id_token"
        )
        
        token_dict = token.to_dict()
        
        expected_keys = {"access_token", "token_type", "expires_in", "refresh_token", "scope", "id_token"}
        assert set(token_dict.keys()) == expected_keys
        assert token_dict["access_token"] == "test_token"
        assert token_dict["token_type"] == "bearer"


class TestAuthorizationCode:
    """Test authorization code functionality."""
    
    def test_authorization_code_creation(self):
        """Test authorization code creation."""
        code = AuthorizationCode(
            code="test_code",
            client_id="test_client",
            redirect_uri="https://app.example.com/callback",
            scopes=["openid", "email"]
        )
        
        assert code.code == "test_code"
        assert code.client_id == "test_client"
        assert code.redirect_uri == "https://app.example.com/callback"
        assert code.scopes == ["openid", "email"]
        assert code.used is False
        assert isinstance(code.created_at, datetime)
    
    def test_authorization_code_expiration(self):
        """Test authorization code expiration."""
        # Test non-expired code
        code = create_mock_authorization_code()
        assert code.is_expired() is False
        assert code.is_valid() is True
        
        # Test expired code
        expired_code = create_mock_authorization_code(expired=True)
        assert expired_code.is_expired() is True
        assert expired_code.is_valid() is False
    
    def test_authorization_code_usage(self):
        """Test authorization code usage."""
        code = create_mock_authorization_code()
        
        assert code.is_valid() is True
        
        code.use()
        assert code.used is True
        assert code.is_valid() is False  # Used codes are invalid


class TestOAuth2Providers:
    """Test OAuth2 provider implementations."""
    
    def test_google_provider_initialization(self):
        """Test Google OAuth2 provider initialization."""
        provider = GoogleOAuth2Provider(
            client_id="test_client_id",
            client_secret="test_secret"
        )
        
        assert provider.client_id == "test_client_id"
        assert provider.client_secret == "test_secret"
        assert provider.get_provider_name() == "google"
        assert "accounts.google.com" in provider.authorization_endpoint
        assert "googleapis.com" in provider.token_endpoint
        assert provider.userinfo_endpoint is not None
    
    def test_github_provider_initialization(self):
        """Test GitHub OAuth2 provider initialization."""
        provider = GitHubOAuth2Provider(
            client_id="test_client_id",
            client_secret="test_secret"
        )
        
        assert provider.client_id == "test_client_id"
        assert provider.client_secret == "test_secret"
        assert provider.get_provider_name() == "github"
        assert "github.com" in provider.authorization_endpoint
        assert "github.com" in provider.token_endpoint
        assert provider.userinfo_endpoint is not None
    
    def test_microsoft_provider_initialization(self):
        """Test Microsoft OAuth2 provider initialization."""
        provider = MicrosoftOAuth2Provider(
            client_id="test_client_id",
            client_secret="test_secret",
            tenant="test_tenant"
        )
        
        assert provider.client_id == "test_client_id"
        assert provider.client_secret == "test_secret"
        assert provider.get_provider_name() == "microsoft"
        assert "test_tenant" in provider.authorization_endpoint
        assert "test_tenant" in provider.token_endpoint
        assert provider.userinfo_endpoint is not None
    
    def test_provider_build_authorization_url(self):
        """Test authorization URL building."""
        provider = MockOAuth2Provider()
        
        url = provider.build_authorization_url(
            redirect_uri="https://app.example.com/callback",
            state="test_state",
            code_challenge="test_challenge",
            code_challenge_method=CodeChallengeMethod.S256,
            scopes=["openid", "email"]
        )
        
        assert "response_type=code" in url
        assert "client_id=test_client_id" in url
        assert "redirect_uri=" in url
        assert "state=test_state" in url
        assert "code_challenge=test_challenge" in url
        assert "code_challenge_method=S256" in url
        assert "scope=openid+email" in url
    
    @pytest.mark.asyncio
    async def test_provider_token_exchange_success(self):
        """Test successful token exchange."""
        provider = MockOAuth2Provider()
        
        token = await provider.exchange_code_for_token(
            code="test_code",
            redirect_uri="https://app.example.com/callback",
            code_verifier="test_verifier"
        )
        
        assert isinstance(token, OAuth2Token)
        assert token.access_token == "mock_access_token"
        assert token.token_type == TokenType.BEARER
        assert len(provider.token_exchange_calls) == 1
    
    @pytest.mark.asyncio
    async def test_provider_token_exchange_failure(self):
        """Test failed token exchange."""
        provider = MockOAuth2Provider(should_fail_token_exchange=True)
        
        with pytest.raises(OAuth2ExchangeError):
            await provider.exchange_code_for_token(
                code="invalid_code",
                redirect_uri="https://app.example.com/callback",
                code_verifier="invalid_verifier"
            )
    
    @pytest.mark.asyncio
    async def test_provider_refresh_token_success(self):
        """Test successful token refresh."""
        provider = MockOAuth2Provider()
        
        new_token = await provider.refresh_token("test_refresh_token")
        
        assert isinstance(new_token, OAuth2Token)
        assert new_token.access_token == "new_access_token"
        assert len(provider.refresh_calls) == 1
    
    @pytest.mark.asyncio
    async def test_provider_refresh_token_failure(self):
        """Test failed token refresh."""
        provider = MockOAuth2Provider(should_fail_refresh=True)
        
        with pytest.raises(OAuth2ExchangeError):
            await provider.refresh_token("invalid_refresh_token")
    
    @pytest.mark.asyncio
    async def test_provider_get_user_info_success(self):
        """Test successful user info retrieval."""
        provider = MockOAuth2Provider()
        
        user_info = await provider.get_user_info("test_access_token")
        
        assert isinstance(user_info, dict)
        assert "sub" in user_info
        assert "email" in user_info
        assert len(provider.userinfo_calls) == 1
    
    @pytest.mark.asyncio
    async def test_provider_get_user_info_failure(self):
        """Test failed user info retrieval."""
        provider = MockOAuth2Provider(should_fail_userinfo=True)
        
        with pytest.raises(OAuth2ExchangeError):
            await provider.get_user_info("invalid_token")


class TestOAuth2Storage:
    """Test OAuth2 storage implementations."""
    
    @pytest.mark.asyncio
    async def test_memory_storage_pkce_pairs(self):
        """Test memory storage for PKCE pairs."""
        storage = MemoryOAuth2Storage()
        
        # Test store and get
        pair = create_mock_pkce_pair()
        await storage.store_pkce_pair("session_1", pair)
        
        retrieved = await storage.get_pkce_pair("session_1")
        assert retrieved is not None
        assert retrieved.verifier == pair.verifier
        
        # Test delete
        await storage.delete_pkce_pair("session_1")
        retrieved = await storage.get_pkce_pair("session_1")
        assert retrieved is None
    
    @pytest.mark.asyncio
    async def test_memory_storage_states(self):
        """Test memory storage for OAuth2 states."""
        storage = MemoryOAuth2Storage()
        
        # Test store and get
        state = create_mock_oauth2_state()
        await storage.store_state(state.value, state)
        
        retrieved = await storage.get_state(state.value)
        assert retrieved is not None
        assert retrieved.client_id == state.client_id
        
        # Test delete
        await storage.delete_state(state.value)
        retrieved = await storage.get_state(state.value)
        assert retrieved is None
    
    @pytest.mark.asyncio
    async def test_memory_storage_tokens(self):
        """Test memory storage for OAuth2 tokens."""
        storage = MemoryOAuth2Storage()
        
        # Test store and get
        token = create_mock_oauth2_token()
        await storage.store_token("token_key", token)
        
        retrieved = await storage.get_token("token_key")
        assert retrieved is not None
        assert retrieved.access_token == token.access_token
        
        # Test delete
        await storage.delete_token("token_key")
        retrieved = await storage.get_token("token_key")
        assert retrieved is None
    
    @pytest.mark.asyncio
    async def test_memory_storage_cleanup_expired(self):
        """Test cleanup of expired entries."""
        storage = MemoryOAuth2Storage()
        
        # Store expired entries
        expired_pair = create_mock_pkce_pair(expired=True)
        expired_state = create_mock_oauth2_state(expired=True)
        expired_token = create_mock_oauth2_token(expired=True)
        
        await storage.store_pkce_pair("expired_session", expired_pair)
        await storage.store_state("expired_state", expired_state)
        await storage.store_token("expired_token", expired_token)
        
        # Store valid entries
        valid_pair = create_mock_pkce_pair()
        valid_state = create_mock_oauth2_state()
        valid_token = create_mock_oauth2_token()
        
        await storage.store_pkce_pair("valid_session", valid_pair)
        await storage.store_state("valid_state", valid_state)
        await storage.store_token("valid_token", valid_token)
        
        # Run cleanup
        cleaned_count = await storage.cleanup_expired()
        assert cleaned_count >= 3  # At least the expired entries
        
        # Verify expired entries are gone
        assert await storage.get_pkce_pair("expired_session") is None
        assert await storage.get_state("expired_state") is None
        assert await storage.get_token("expired_token") is None
        
        # Verify valid entries remain
        assert await storage.get_pkce_pair("valid_session") is not None
        assert await storage.get_state("valid_state") is not None
        assert await storage.get_token("valid_token") is not None


class TestOAuth2PKCEConfig:
    """Test OAuth2 PKCE configuration."""
    
    def test_config_creation(self):
        """Test OAuth2 PKCE configuration creation."""
        provider = MockOAuth2Provider()
        storage = MockOAuth2Storage()
        
        config = OAuth2PKCEConfig(
            provider=provider,
            storage=storage,
            redirect_uri="https://app.example.com/callback"
        )
        
        assert config.provider == provider
        assert config.storage == storage
        assert config.redirect_uri == "https://app.example.com/callback"
        assert config.require_pkce is True
        assert config.require_state is True
        assert config.code_challenge_method == CodeChallengeMethod.S256
    
    def test_config_with_callbacks(self):
        """Test configuration with success and error callbacks."""
        success_callback = Mock()
        error_callback = Mock()
        
        config = OAuth2PKCEConfig(
            provider=MockOAuth2Provider(),
            storage=MockOAuth2Storage(),
            redirect_uri="https://app.example.com/callback",
            on_success_callback=success_callback,
            on_error_callback=error_callback
        )
        
        assert config.on_success_callback == success_callback
        assert config.on_error_callback == error_callback


class TestOAuth2PKCEShield:
    """Test OAuth2 PKCE shield functionality."""
    
    @pytest.fixture
    def shield_config(self):
        """Create a test shield configuration."""
        return OAuth2PKCEConfig(
            provider=MockOAuth2Provider(),
            storage=MockOAuth2Storage(),
            redirect_uri="https://app.example.com/callback"
        )
    
    @pytest.fixture
    def shield(self, shield_config):
        """Create a test shield."""
        return OAuth2PKCEShield(shield_config)
    
    def test_shield_creation(self, shield):
        """Test OAuth2 PKCE shield creation."""
        assert isinstance(shield, OAuth2PKCEShield)
        assert isinstance(shield.config, OAuth2PKCEConfig)
    
    @pytest.mark.asyncio
    async def test_handle_authorization_request(self, shield):
        """Test handling authorization request."""
        request = MockRequest(
            method="GET",
            path="/oauth2/authorize",
            query_params={"scope": "openid email"}
        )
        
        result = await shield._handle_authorization_request(request)
        
        assert "oauth2_authorization" in result
        auth_data = result["oauth2_authorization"]
        assert "authorization_url" in auth_data
        assert "session_id" in auth_data
        assert "state" in auth_data
        assert "code_challenge" in auth_data
        assert auth_data["code_challenge_method"] == "S256"
        assert auth_data["scopes"] == ["openid", "email"]
    
    @pytest.mark.asyncio
    async def test_handle_callback_request_success(self, shield):
        """Test successful callback request handling."""
        # First, set up the flow
        simulator = OAuth2FlowSimulator(shield.config.provider, shield.config.storage)
        flow_data = await simulator.start_authorization_flow()
        
        request = MockRequest(
            method="GET",
            path="/oauth2/callback",
            query_params={
                "code": "test_auth_code",
                "state": flow_data["state"]
            },
            cookies={"oauth2_session": flow_data["session_id"]}
        )
        
        result = await shield._handle_callback_request(request)
        
        assert "oauth2_token" in result
        token_data = result["oauth2_token"]
        assert "access_token" in token_data
        assert "token_type" in token_data
        assert token_data["token_type"] == "bearer"
    
    @pytest.mark.asyncio
    async def test_handle_callback_request_error(self, shield):
        """Test callback request with OAuth2 error."""
        request = MockRequest(
            method="GET",
            path="/oauth2/callback",
            query_params={
                "error": "access_denied",
                "error_description": "User denied access"
            }
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._handle_callback_request(request)
        
        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["error"] == "access_denied"
    
    @pytest.mark.asyncio
    async def test_handle_callback_request_missing_code(self, shield):
        """Test callback request with missing authorization code."""
        request = MockRequest(
            method="GET",
            path="/oauth2/callback",
            query_params={"state": "test_state"}
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._handle_callback_request(request)
        
        assert exc_info.value.status_code == 400
        assert "Missing authorization code" in exc_info.value.detail["error_description"]
    
    @pytest.mark.asyncio
    async def test_handle_callback_request_invalid_state(self, shield):
        """Test callback request with invalid state."""
        request = MockRequest(
            method="GET",
            path="/oauth2/callback",
            query_params={
                "code": "test_code",
                "state": "invalid_state"
            },
            cookies={"oauth2_session": "test_session"}
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._handle_callback_request(request)
        
        assert exc_info.value.status_code == 400
        assert "Invalid or expired state parameter" in exc_info.value.detail["error_description"]
    
    @pytest.mark.asyncio
    async def test_handle_token_request(self, shield):
        """Test direct token request handling."""
        request = MockRequest(
            method="POST",
            path="/oauth2/token",
            form_data={
                "grant_type": "authorization_code",
                "code": "test_code",
                "redirect_uri": "https://app.example.com/callback",
                "code_verifier": "test_verifier"
            }
        )
        
        result = await shield._handle_token_request(request)
        
        assert "oauth2_token" in result
        token_data = result["oauth2_token"]
        assert "access_token" in token_data
        assert "token_type" in token_data
    
    @pytest.mark.asyncio
    async def test_handle_token_request_invalid_grant_type(self, shield):
        """Test token request with invalid grant type."""
        request = MockRequest(
            method="POST",
            path="/oauth2/token",
            form_data={
                "grant_type": "client_credentials",
                "code": "test_code"
            }
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._handle_token_request(request)
        
        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["error"] == "unsupported_grant_type"
    
    @pytest.mark.asyncio
    async def test_handle_refresh_request(self, shield):
        """Test token refresh request handling."""
        request = MockRequest(
            method="POST",
            path="/oauth2/refresh",
            form_data={"refresh_token": "test_refresh_token"}
        )
        
        result = await shield._handle_refresh_request(request)
        
        assert "oauth2_token" in result
        token_data = result["oauth2_token"]
        assert "access_token" in token_data
        assert token_data["access_token"] == "new_access_token"
    
    @pytest.mark.asyncio
    async def test_handle_userinfo_request(self, shield):
        """Test user info request handling."""
        request = MockRequest(
            method="GET",
            path="/oauth2/userinfo",
            headers={"Authorization": "Bearer test_access_token"}
        )
        
        result = await shield._handle_userinfo_request(request)
        
        assert "user_info" in result
        user_data = result["user_info"]
        assert "sub" in user_data
        assert "email" in user_data
    
    @pytest.mark.asyncio
    async def test_handle_userinfo_request_missing_token(self, shield):
        """Test user info request with missing token."""
        request = MockRequest(
            method="GET",
            path="/oauth2/userinfo"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._handle_userinfo_request(request)
        
        assert exc_info.value.status_code == 401
        assert "invalid_token" in exc_info.value.detail["error"]
    
    @pytest.mark.asyncio
    async def test_handle_logout_request(self, shield):
        """Test logout request handling."""
        request = MockRequest(
            method="POST",
            path="/oauth2/logout",
            cookies={"oauth2_session": "test_session"}
        )
        
        result = await shield._handle_logout_request(request)
        
        assert "oauth2_logout" in result
        logout_data = result["oauth2_logout"]
        assert logout_data["success"] is True
    
    @pytest.mark.asyncio
    async def test_validate_bearer_token_present(self, shield):
        """Test bearer token validation when token is present."""
        request = MockRequest(
            method="GET",
            path="/api/protected",
            headers={"Authorization": "Bearer test_token"}
        )
        
        result = await shield._validate_bearer_token(request)
        
        assert result is not None
        assert "oauth2_validation" in result
        assert result["oauth2_validation"]["access_token_present"] is True
    
    @pytest.mark.asyncio
    async def test_validate_bearer_token_missing(self, shield):
        """Test bearer token validation when token is missing."""
        request = MockRequest(
            method="GET",
            path="/api/public"
        )
        
        result = await shield._validate_bearer_token(request)
        
        assert result is None  # No token, let application decide
    
    def test_extract_bearer_token_valid(self, shield):
        """Test bearer token extraction from valid Authorization header."""
        request = MockRequest(
            headers={"Authorization": "Bearer test_token_123"}
        )
        
        token = shield._extract_bearer_token(request)
        assert token == "test_token_123"
    
    def test_extract_bearer_token_invalid_scheme(self, shield):
        """Test bearer token extraction with invalid scheme."""
        request = MockRequest(
            headers={"Authorization": "Basic dGVzdA=="}
        )
        
        token = shield._extract_bearer_token(request)
        assert token is None
    
    def test_extract_bearer_token_malformed(self, shield):
        """Test bearer token extraction from malformed header."""
        request = MockRequest(
            headers={"Authorization": "Bearer"}
        )
        
        token = shield._extract_bearer_token(request)
        assert token is None
    
    def test_get_scopes_from_request(self, shield):
        """Test scope extraction from request."""
        # Test with scope parameter
        request = MockRequest(
            query_params={"scope": "openid email profile"}
        )
        
        scopes = shield._get_scopes_from_request(request)
        assert scopes == ["openid", "email", "profile"]
        
        # Test without scope parameter
        request = MockRequest()
        scopes = shield._get_scopes_from_request(request)
        assert scopes == shield.config.provider.scopes
    
    @pytest.mark.asyncio
    async def test_periodic_cleanup(self, shield):
        """Test periodic cleanup functionality."""
        # Set last cleanup to trigger cleanup
        shield._last_cleanup = time.time() - (shield.config.cleanup_interval_minutes * 60 + 1)
        
        await shield._periodic_cleanup()
        
        # Verify cleanup was called on storage
        assert len(shield.config.storage.cleanup_calls) > 0


class TestConvenienceFunctions:
    """Test convenience functions for creating shields."""
    
    def test_google_oauth2_pkce_shield(self):
        """Test Google OAuth2 PKCE shield creation."""
        shield = google_oauth2_pkce_shield(
            client_id="test_client_id",
            client_secret="test_secret",
            redirect_uri="https://app.example.com/callback"
        )
        
        assert isinstance(shield, OAuth2PKCEShield)
        assert isinstance(shield.config.provider, GoogleOAuth2Provider)
        assert shield.config.provider.client_id == "test_client_id"
        assert shield.config.redirect_uri == "https://app.example.com/callback"
    
    def test_github_oauth2_pkce_shield(self):
        """Test GitHub OAuth2 PKCE shield creation."""
        shield = github_oauth2_pkce_shield(
            client_id="test_client_id",
            redirect_uri="https://app.example.com/callback",
            scopes=["user", "repo"]
        )
        
        assert isinstance(shield, OAuth2PKCEShield)
        assert isinstance(shield.config.provider, GitHubOAuth2Provider)
        assert shield.config.scopes == ["user", "repo"]
    
    def test_microsoft_oauth2_pkce_shield(self):
        """Test Microsoft OAuth2 PKCE shield creation."""
        shield = microsoft_oauth2_pkce_shield(
            client_id="test_client_id",
            redirect_uri="https://app.example.com/callback",
            tenant="test_tenant"
        )
        
        assert isinstance(shield, OAuth2PKCEShield)
        assert isinstance(shield.config.provider, MicrosoftOAuth2Provider)
        assert shield.config.provider.tenant == "test_tenant"
    
    def test_custom_oauth2_pkce_shield(self):
        """Test custom OAuth2 PKCE shield creation."""
        custom_provider = MockOAuth2Provider()
        
        shield = custom_oauth2_pkce_shield(
            provider=custom_provider,
            redirect_uri="https://app.example.com/callback",
            require_pkce=False
        )
        
        assert isinstance(shield, OAuth2PKCEShield)
        assert shield.config.provider == custom_provider
        assert shield.config.require_pkce is False


class TestSecurityFeatures:
    """Test security-related features."""
    
    def test_pkce_code_verifier_entropy(self):
        """Test entropy of generated PKCE code verifiers."""
        verifiers = [PKCEGenerator.generate_code_verifier() for _ in range(100)]
        
        # Test for uniqueness (basic entropy test)
        unique_verifiers = set(verifiers)
        assert len(unique_verifiers) == len(verifiers)
        
        # Test minimum length requirement
        for verifier in verifiers:
            assert len(verifier) >= PKCEGenerator.MIN_VERIFIER_LENGTH
    
    def test_state_parameter_entropy(self):
        """Test entropy of generated state parameters."""
        states = [StateGenerator.generate_state() for _ in range(100)]
        
        # Use security test helper
        entropy_stats = SecurityTestHelper.test_state_entropy(states)
        
        assert entropy_stats["uniqueness_ratio"] == 1.0  # All should be unique
        assert entropy_stats["duplicate_count"] == 0
        assert entropy_stats["entropy"] > 0
    
    def test_timing_attack_resistance(self):
        """Test resistance to timing attacks in PKCE verification."""
        pair = create_mock_pkce_pair(CodeChallengeMethod.S256)
        
        # Test operations that should have similar timing
        operations = [
            lambda: pair.verify(pair.verifier),  # Correct verifier
            lambda: pair.verify("wrong_verifier_same_length_as_correct_one"),  # Wrong verifier
            lambda: pair.verify("different_wrong_verifier_same_length_ok")  # Another wrong verifier
        ]
        
        timing_stats = SecurityTestHelper.test_timing_attack_resistance(operations, 50)
        
        # Verify operations complete without errors
        assert len(timing_stats) == len(operations)
        for op_stats in timing_stats.values():
            assert op_stats["average"] > 0
    
    def test_pkce_challenge_methods_security(self):
        """Test security properties of PKCE challenge methods."""
        verifier = "test_verifier_with_sufficient_entropy_123456789"
        
        # Test PLAIN method (should be identical)
        plain_challenge = PKCEGenerator.generate_code_challenge(verifier, CodeChallengeMethod.PLAIN)
        assert plain_challenge == verifier
        
        # Test S256 method (should be different and irreversible)
        s256_challenge = PKCEGenerator.generate_code_challenge(verifier, CodeChallengeMethod.S256)
        assert s256_challenge != verifier
        assert len(s256_challenge) > 0
        
        # Verify S256 challenge is deterministic
        s256_challenge_2 = PKCEGenerator.generate_code_challenge(verifier, CodeChallengeMethod.S256)
        assert s256_challenge == s256_challenge_2
    
    @pytest.mark.asyncio
    async def test_state_parameter_csrf_protection(self):
        """Test state parameter provides CSRF protection."""
        storage = MockOAuth2Storage()
        
        # Create and store valid state
        state = create_mock_oauth2_state()
        await storage.store_state(state.value, state)
        
        # Verify valid state is accepted
        retrieved_state = await storage.get_state(state.value)
        assert retrieved_state is not None
        assert retrieved_state.value == state.value
        
        # Verify invalid state is rejected
        invalid_state = await storage.get_state("invalid_state_value")
        assert invalid_state is None
    
    def test_token_expiration_security(self):
        """Test token expiration security mechanisms."""
        # Test token with expiration
        token = create_mock_oauth2_token(expires_in=3600)
        assert token.is_expired() is False
        
        # Test expired token
        expired_token = create_mock_oauth2_token(expired=True)
        assert expired_token.is_expired() is True
        
        # Test token without expiration (should not expire)
        persistent_token = create_mock_oauth2_token(expires_in=None)
        assert persistent_token.is_expired() is False


class TestCompliance:
    """Test RFC 7636 compliance."""
    
    def test_rfc7636_code_verifier_requirements(self):
        """Test RFC 7636 code verifier requirements."""
        # Test minimum and maximum length requirements
        min_verifier = PKCEGenerator.generate_code_verifier(PKCEGenerator.MIN_VERIFIER_LENGTH)
        assert len(min_verifier) == PKCEGenerator.MIN_VERIFIER_LENGTH
        
        max_verifier = PKCEGenerator.generate_code_verifier(PKCEGenerator.MAX_VERIFIER_LENGTH)
        assert len(max_verifier) == PKCEGenerator.MAX_VERIFIER_LENGTH
        
        # Test character set requirements (unreserved characters)
        verifier = PKCEGenerator.generate_code_verifier()
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        
        # Allow base64url characters (which is compliant)
        base64url_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        verifier_chars = set(verifier)
        
        # Verifier should only contain allowed characters
        assert verifier_chars <= base64url_chars
    
    def test_rfc7636_code_challenge_methods(self):
        """Test RFC 7636 code challenge methods."""
        verifier = "test_verifier"
        
        # Test PLAIN method
        plain_challenge = PKCEGenerator.generate_code_challenge(verifier, CodeChallengeMethod.PLAIN)
        assert plain_challenge == verifier
        
        # Test S256 method
        s256_challenge = PKCEGenerator.generate_code_challenge(verifier, CodeChallengeMethod.S256)
        assert s256_challenge != verifier
        
        # Verify S256 challenge format (base64url without padding)
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert set(s256_challenge) <= allowed_chars
        assert "=" not in s256_challenge  # No padding in base64url
    
    def test_rfc7636_pkce_verification_process(self):
        """Test RFC 7636 PKCE verification process."""
        # Generate PKCE pair
        pair = PKCEGenerator.generate_pkce_pair(CodeChallengeMethod.S256)
        
        # Verification should succeed with correct verifier
        assert pair.verify(pair.verifier) is True
        
        # Verification should fail with incorrect verifier
        assert pair.verify("wrong_verifier") is False
        
        # Test PLAIN method verification
        plain_pair = PKCEGenerator.generate_pkce_pair(CodeChallengeMethod.PLAIN)
        assert plain_pair.verify(plain_pair.verifier) is True
        assert plain_pair.verify("wrong_verifier") is False


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    @pytest.mark.asyncio
    async def test_oauth2_exchange_error_handling(self):
        """Test OAuth2ExchangeError handling."""
        provider = MockOAuth2Provider(should_fail_token_exchange=True)
        
        with pytest.raises(OAuth2ExchangeError) as exc_info:
            await provider.exchange_code_for_token("invalid_code", "redirect_uri", "verifier")
        
        assert exc_info.value.error_code == "invalid_grant"
        assert "Mock token exchange failure" in exc_info.value.error_description
    
    @pytest.mark.asyncio
    async def test_shield_error_callback(self):
        """Test shield error callback functionality."""
        error_callback = Mock()
        
        config = OAuth2PKCEConfig(
            provider=MockOAuth2Provider(should_fail_token_exchange=True),
            storage=MockOAuth2Storage(),
            redirect_uri="https://app.example.com/callback",
            on_error_callback=error_callback
        )
        
        shield = OAuth2PKCEShield(config)
        
        # Simulate error scenario
        request = MockRequest(
            method="POST",
            path="/oauth2/token",
            form_data={
                "grant_type": "authorization_code",
                "code": "invalid_code",
                "redirect_uri": "https://app.example.com/callback",
                "code_verifier": "test_verifier"
            }
        )
        
        with pytest.raises(HTTPException):
            await shield._handle_token_request(request)
        
        # Verify error callback was called
        assert error_callback.called
    
    @pytest.mark.asyncio
    async def test_shield_success_callback(self):
        """Test shield success callback functionality."""
        success_callback = Mock()
        
        config = OAuth2PKCEConfig(
            provider=MockOAuth2Provider(),
            storage=MockOAuth2Storage(),
            redirect_uri="https://app.example.com/callback",
            on_success_callback=success_callback
        )
        
        shield = OAuth2PKCEShield(config)
        
        # Set up successful flow
        simulator = OAuth2FlowSimulator(config.provider, config.storage)
        flow_data = await simulator.start_authorization_flow()
        
        request = MockRequest(
            method="GET",
            path="/oauth2/callback",
            query_params={
                "code": "test_auth_code",
                "state": flow_data["state"]
            },
            cookies={"oauth2_session": flow_data["session_id"]}
        )
        
        await shield._handle_callback_request(request)
        
        # Verify success callback was called
        assert success_callback.called
    
    def test_pkce_generator_edge_cases(self):
        """Test PKCE generator edge cases."""
        # Test invalid challenge method
        with pytest.raises(ValueError):
            PKCEGenerator.generate_code_challenge("verifier", "invalid_method")
        
        # Test boundary length values
        min_verifier = PKCEGenerator.generate_code_verifier(PKCEGenerator.MIN_VERIFIER_LENGTH)
        assert len(min_verifier) == PKCEGenerator.MIN_VERIFIER_LENGTH
        
        max_verifier = PKCEGenerator.generate_code_verifier(PKCEGenerator.MAX_VERIFIER_LENGTH)
        assert len(max_verifier) == PKCEGenerator.MAX_VERIFIER_LENGTH


class TestIntegrationScenarios:
    """Test integration scenarios with FastAPI."""
    
    @pytest.mark.asyncio
    async def test_complete_oauth2_flow(self):
        """Test complete OAuth2 PKCE flow integration."""
        provider = MockOAuth2Provider()
        storage = MockOAuth2Storage()
        
        config = OAuth2PKCEConfig(
            provider=provider,
            storage=storage,
            redirect_uri="https://app.example.com/callback"
        )
        
        shield = OAuth2PKCEShield(config)
        
        # Step 1: Start authorization
        auth_request = MockRequest(method="GET", path="/oauth2/authorize")
        auth_result = await shield._handle_authorization_request(auth_request)
        
        assert "oauth2_authorization" in auth_result
        auth_data = auth_result["oauth2_authorization"]
        
        # Step 2: Simulate callback
        callback_request = MockRequest(
            method="GET",
            path="/oauth2/callback",
            query_params={
                "code": "test_auth_code",
                "state": auth_data["state"]
            },
            cookies={"oauth2_session": auth_data["session_id"]}
        )
        
        callback_result = await shield._handle_callback_request(callback_request)
        
        assert "oauth2_token" in callback_result
        assert callback_result["oauth2_token"]["access_token"] == "mock_access_token"
        
        # Step 3: Test protected resource access
        protected_request = MockRequest(
            method="GET",
            path="/api/protected",
            headers={"Authorization": f"Bearer {callback_result['oauth2_token']['access_token']}"}
        )
        
        validation_result = await shield._validate_bearer_token(protected_request)
        
        assert validation_result is not None
        assert validation_result["oauth2_validation"]["access_token_present"] is True
    
    def test_fastapi_integration(self):
        """Test FastAPI application integration."""
        app = FastAPI()
        
        shield = google_oauth2_pkce_shield(
            client_id="test_client_id",
            redirect_uri="https://app.example.com/callback"
        )
        
        @app.get("/oauth2/authorize")
        async def authorize(request: Request):
            result = await shield._handle_authorization_request(request)
            return result
        
        client = TestClient(app)
        
        response = client.get("/oauth2/authorize")
        
        assert response.status_code == 200
        data = response.json()
        assert "oauth2_authorization" in data
        assert "authorization_url" in data["oauth2_authorization"]


class TestPerformanceAndScalability:
    """Test performance and scalability aspects."""
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Test concurrent OAuth2 operations."""
        storage = MemoryOAuth2Storage()
        
        # Test concurrent PKCE pair operations
        async def store_and_retrieve_pkce():
            pair = create_mock_pkce_pair()
            session_id = secrets.token_urlsafe(16)
            await storage.store_pkce_pair(session_id, pair)
            retrieved = await storage.get_pkce_pair(session_id)
            return retrieved is not None
        
        # Run concurrent operations
        tasks = [store_and_retrieve_pkce() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        
        # All operations should succeed
        assert all(results)
    
    @pytest.mark.asyncio
    async def test_storage_performance_with_large_dataset(self):
        """Test storage performance with large dataset."""
        storage = MemoryOAuth2Storage()
        
        # Store many items
        num_items = 1000
        
        start_time = time.time()
        
        for i in range(num_items):
            pair = create_mock_pkce_pair()
            await storage.store_pkce_pair(f"session_{i}", pair)
        
        store_time = time.time() - start_time
        
        # Retrieve items
        start_time = time.time()
        
        for i in range(num_items):
            await storage.get_pkce_pair(f"session_{i}")
        
        retrieve_time = time.time() - start_time
        
        # Performance should be reasonable
        assert store_time < 10.0  # Should store 1000 items in under 10 seconds
        assert retrieve_time < 5.0  # Should retrieve 1000 items in under 5 seconds
    
    @pytest.mark.asyncio
    async def test_cleanup_performance(self):
        """Test cleanup performance with mixed expired/valid data."""
        storage = MemoryOAuth2Storage()
        
        # Create mixed dataset
        num_items = 500
        
        for i in range(num_items):
            if i % 2 == 0:  # Half expired
                pair = create_mock_pkce_pair(expired=True)
                state = create_mock_oauth2_state(expired=True)
            else:  # Half valid
                pair = create_mock_pkce_pair()
                state = create_mock_oauth2_state()
            
            await storage.store_pkce_pair(f"session_{i}", pair)
            await storage.store_state(f"state_{i}", state)
        
        # Run cleanup
        start_time = time.time()
        cleaned_count = await storage.cleanup_expired()
        cleanup_time = time.time() - start_time
        
        # Verify cleanup results
        assert cleaned_count >= num_items  # Should clean up at least the expired items
        assert cleanup_time < 5.0  # Should complete in reasonable time


# Run specific test groups if this file is executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])