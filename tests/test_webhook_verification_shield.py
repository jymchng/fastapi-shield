"""Tests for webhook verification shield functionality."""

import hashlib
import hmac
import time
from datetime import datetime, timezone
from typing import Dict
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_shield.webhook_verification import (
    WebhookVerificationShield,
    WebhookConfig,
    WebhookVerificationResult,
    SignatureAlgorithm,
    WebhookProvider,
    ReplayProtection,
    MemoryReplayProtection,
    SignatureValidator,
    HMACSignatureValidator,
    GitHubSignatureValidator,
    StripeSignatureValidator,
    PayPalSignatureValidator,
    SlackSignatureValidator,
    github_webhook_shield,
    stripe_webhook_shield,
    paypal_webhook_shield,
    slack_webhook_shield,
    custom_webhook_shield,
)


class MockReplayProtection(ReplayProtection):
    """Mock replay protection for testing."""
    
    def __init__(self):
        self.seen_requests = set()
        self.cleanup_count = 0
    
    async def is_request_seen(self, signature: str, timestamp: int) -> bool:
        """Check if request has been seen."""
        return signature in self.seen_requests
    
    async def record_request(self, signature: str, timestamp: int) -> None:
        """Record request."""
        self.seen_requests.add(signature)
    
    async def cleanup_expired(self) -> int:
        """Mock cleanup."""
        self.cleanup_count += 1
        return 0


class TestWebhookConfig:
    """Test webhook configuration."""
    
    def test_webhook_config_defaults(self):
        """Test default webhook configuration."""
        config = WebhookConfig(secret="test-secret")
        
        assert config.provider == WebhookProvider.CUSTOM
        assert config.secret == "test-secret"
        assert config.signature_header == "X-Hub-Signature-256"
        assert config.signature_algorithm == SignatureAlgorithm.SHA256
        assert config.signature_prefix == "sha256="
        assert config.enable_timestamp_validation is True
        assert config.enable_replay_protection is True
    
    def test_webhook_config_custom(self):
        """Test custom webhook configuration."""
        config = WebhookConfig(
            secret="custom-secret",
            provider=WebhookProvider.GITHUB,
            signature_header="X-Custom-Signature",
            signature_algorithm=SignatureAlgorithm.SHA1,
            signature_prefix="sha1=",
            enable_timestamp_validation=False,
            enable_replay_protection=False,
        )
        
        assert config.provider == WebhookProvider.GITHUB
        assert config.signature_algorithm == SignatureAlgorithm.SHA1
        assert config.signature_prefix == "sha1="
        assert config.enable_timestamp_validation is False
        assert config.enable_replay_protection is False


class TestMemoryReplayProtection:
    """Test memory-based replay protection."""
    
    @pytest.mark.asyncio
    async def test_replay_protection_basic(self):
        """Test basic replay protection functionality."""
        protection = MemoryReplayProtection(max_size=2, ttl=1)
        
        # First request should not be seen
        assert await protection.is_request_seen("sig1", 1000) is False
        
        # Record the request
        await protection.record_request("sig1", 1000)
        
        # Now it should be seen
        assert await protection.is_request_seen("sig1", 1000) is True
        
        # Different signature should not be seen
        assert await protection.is_request_seen("sig2", 1001) is False
    
    @pytest.mark.asyncio
    async def test_replay_protection_cleanup(self):
        """Test replay protection cleanup."""
        protection = MemoryReplayProtection(max_size=10, ttl=1)
        
        # Record old request
        old_time = int(time.time()) - 10
        await protection.record_request("old_sig", old_time)
        
        # Should be seen initially
        assert await protection.is_request_seen("old_sig", old_time) is True
        
        # Wait and cleanup (simulate time passing)
        with patch('time.time', return_value=time.time() + 10):
            cleaned = await protection.cleanup_expired()
            assert cleaned == 1
            
            # Should no longer be seen
            assert await protection.is_request_seen("old_sig", old_time) is False
    
    @pytest.mark.asyncio
    async def test_replay_protection_max_size(self):
        """Test replay protection max size limit."""
        protection = MemoryReplayProtection(max_size=2, ttl=3600)
        
        # Use current time to avoid cleanup issues
        current_time = int(time.time())
        
        # Add maximum number of requests
        await protection.record_request("sig1", current_time)
        await protection.record_request("sig2", current_time + 1)
        
        # Add one more - should evict oldest
        await protection.record_request("sig3", current_time + 2)
        
        # sig1 should be evicted, sig2 and sig3 should remain
        assert await protection.is_request_seen("sig1", current_time) is False
        assert await protection.is_request_seen("sig2", current_time + 1) is True
        assert await protection.is_request_seen("sig3", current_time + 2) is True


class TestSignatureValidators:
    """Test signature validators."""
    
    def test_hmac_signature_validator(self):
        """Test HMAC signature validator."""
        validator = HMACSignatureValidator(SignatureAlgorithm.SHA256)
        
        secret = "test-secret"
        body = b"test-body"
        
        # Generate signature
        expected_sig = validator.generate_signature(body, secret)
        
        # Should validate correctly
        assert validator.validate_signature(body, expected_sig, secret) is True
        
        # Should fail with wrong signature
        assert validator.validate_signature(body, "wrong-sig", secret) is False
        
        # Should fail with wrong secret
        assert validator.validate_signature(body, expected_sig, "wrong-secret") is False
    
    def test_github_signature_validator(self):
        """Test GitHub signature validator."""
        validator = GitHubSignatureValidator(SignatureAlgorithm.SHA256)
        
        secret = "github-secret"
        body = b'{"action": "opened"}'
        
        # Generate signature
        expected_sig = validator.generate_signature(body, secret)
        assert expected_sig.startswith("sha256=")
        
        # Should validate correctly
        assert validator.validate_signature(body, expected_sig, secret) is True
        
        # Should fail with wrong signature
        assert validator.validate_signature(body, "sha256=wrong", secret) is False
    
    def test_stripe_signature_validator(self):
        """Test Stripe signature validator."""
        validator = StripeSignatureValidator()
        
        secret = "stripe-secret"
        body = b'{"id": "evt_test"}'
        timestamp = "1609459200"  # 2021-01-01
        
        # Generate expected signature
        expected_sig = validator.generate_signature(body, secret, timestamp)
        
        # Create Stripe signature format
        stripe_sig = f"t={timestamp},v1={expected_sig},v1=another_signature"
        
        # Should validate correctly
        assert validator.validate_signature(body, stripe_sig, secret, timestamp) is True
        
        # Should fail without timestamp
        assert validator.validate_signature(body, stripe_sig, secret) is False
        
        # Should fail with wrong signature
        wrong_sig = f"t={timestamp},v1=wrong_signature"
        assert validator.validate_signature(body, wrong_sig, secret, timestamp) is False
    
    def test_paypal_signature_validator(self):
        """Test PayPal signature validator."""
        validator = PayPalSignatureValidator()
        
        secret = "paypal-secret"
        body = b'{"event_type": "PAYMENT.CAPTURE.COMPLETED"}'
        
        # Generate signature
        expected_sig = validator.generate_signature(body, secret)
        
        # Should validate correctly
        assert validator.validate_signature(body, expected_sig, secret) is True
        
        # Should fail with wrong signature
        assert validator.validate_signature(body, "wrong-sig", secret) is False
    
    def test_slack_signature_validator(self):
        """Test Slack signature validator."""
        validator = SlackSignatureValidator()
        
        secret = "slack-secret"
        body = b"token=xoxp-test&team_id=T1234567890"
        timestamp = "1609459200"  # 2021-01-01
        
        # Generate signature
        expected_sig = validator.generate_signature(body, secret, timestamp)
        assert expected_sig.startswith("v0=")
        
        # Should validate correctly
        assert validator.validate_signature(body, expected_sig, secret, timestamp) is True
        
        # Should fail without timestamp
        with pytest.raises(ValueError):
            validator.generate_signature(body, secret)


class TestWebhookVerificationShield:
    """Test the webhook verification shield class."""
    
    @pytest.fixture
    def basic_config(self):
        """Create basic webhook configuration for testing."""
        return WebhookConfig(
            secret="test-secret",
            signature_header="X-Test-Signature",
            signature_prefix="sha256=",
            enable_timestamp_validation=False,
            enable_replay_protection=False,
        )
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request for testing."""
        request = Mock(spec=Request)
        request.headers = {}
        request._body = b'{"test": "data"}'
        
        async def mock_body():
            return request._body
        
        request.body = mock_body
        return request
    
    def test_shield_initialization(self, basic_config):
        """Test shield initialization."""
        shield = WebhookVerificationShield(config=basic_config)
        
        assert shield.config == basic_config
        assert shield.signature_validator is not None
        assert isinstance(shield.signature_validator, HMACSignatureValidator)
    
    def test_shield_initialization_with_replay_protection(self, basic_config):
        """Test shield initialization with replay protection."""
        basic_config.enable_replay_protection = True
        shield = WebhookVerificationShield(config=basic_config)
        
        assert shield.replay_protection is not None
        assert isinstance(shield.replay_protection, MemoryReplayProtection)
    
    def test_get_header_value_case_sensitive(self, basic_config, mock_request):
        """Test header value extraction with case sensitivity."""
        basic_config.case_sensitive_headers = True
        shield = WebhookVerificationShield(config=basic_config)
        
        mock_request.headers = {"X-Test-Signature": "value1", "x-test-signature": "value2"}
        
        # Should get exact case match
        value = shield._get_header_value(mock_request, "X-Test-Signature")
        assert value == "value1"
        
        # Should not match different case
        value = shield._get_header_value(mock_request, "x-test-signature")
        assert value == "value2"
    
    def test_get_header_value_case_insensitive(self, basic_config, mock_request):
        """Test header value extraction with case insensitivity."""
        basic_config.case_sensitive_headers = False
        shield = WebhookVerificationShield(config=basic_config)
        
        mock_request.headers = {"X-Test-Signature": "value1"}
        
        # Should match regardless of case
        value = shield._get_header_value(mock_request, "x-test-signature")
        assert value == "value1"
        
        value = shield._get_header_value(mock_request, "X-TEST-SIGNATURE")
        assert value == "value1"
    
    def test_extract_signature(self, basic_config):
        """Test signature extraction from header."""
        shield = WebhookVerificationShield(config=basic_config)
        
        # With prefix
        sig = shield._extract_signature("sha256=abc123")
        assert sig == "abc123"
        
        # Without prefix (should return as-is)
        basic_config.signature_prefix = ""
        shield = WebhookVerificationShield(config=basic_config)
        sig = shield._extract_signature("abc123")
        assert sig == "abc123"
    
    def test_validate_timestamp(self, basic_config):
        """Test timestamp validation."""
        basic_config.enable_timestamp_validation = True
        basic_config.timestamp_tolerance = 300  # 5 minutes
        shield = WebhookVerificationShield(config=basic_config)
        
        current_time = int(time.time())
        
        # Valid timestamp (current time)
        valid, dt = shield._validate_timestamp(str(current_time))
        assert valid is True
        assert dt is not None
        
        # Valid timestamp (within tolerance)
        valid, dt = shield._validate_timestamp(str(current_time - 200))
        assert valid is True
        
        # Invalid timestamp (outside tolerance)
        valid, dt = shield._validate_timestamp(str(current_time - 400))
        assert valid is False
        assert dt is None
        
        # Invalid timestamp format
        valid, dt = shield._validate_timestamp("invalid")
        assert valid is False
        assert dt is None
    
    @pytest.mark.asyncio
    async def test_verify_webhook_success(self, basic_config, mock_request):
        """Test successful webhook verification."""
        shield = WebhookVerificationShield(config=basic_config)
        
        # Generate valid signature
        body = mock_request._body
        signature = hmac.new(
            basic_config.secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        mock_request.headers = {
            "X-Test-Signature": f"sha256={signature}",
            "Content-Length": str(len(body))
        }
        
        result = await shield.verify_webhook(mock_request)
        
        assert result.verified is True
        assert result.signature_valid is True
        assert result.timestamp_valid is True
        assert result.replay_check_passed is True
        assert result.error_message is None
    
    @pytest.mark.asyncio
    async def test_verify_webhook_missing_signature(self, basic_config, mock_request):
        """Test webhook verification with missing signature."""
        shield = WebhookVerificationShield(config=basic_config)
        
        mock_request.headers = {}
        
        result = await shield.verify_webhook(mock_request)
        
        assert result.verified is False
        assert result.signature_valid is False
        assert "Missing signature header" in result.error_message
    
    @pytest.mark.asyncio
    async def test_verify_webhook_invalid_signature(self, basic_config, mock_request):
        """Test webhook verification with invalid signature."""
        shield = WebhookVerificationShield(config=basic_config)
        
        mock_request.headers = {
            "X-Test-Signature": "sha256=invalid_signature"
        }
        
        result = await shield.verify_webhook(mock_request)
        
        assert result.verified is False
        assert result.signature_valid is False
        assert "Invalid signature" in result.error_message
    
    @pytest.mark.asyncio
    async def test_verify_webhook_content_length_mismatch(self, basic_config, mock_request):
        """Test webhook verification with content length mismatch."""
        basic_config.verify_content_length = True
        shield = WebhookVerificationShield(config=basic_config)
        
        body = mock_request._body
        signature = hmac.new(
            basic_config.secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        mock_request.headers = {
            "X-Test-Signature": f"sha256={signature}",
            "Content-Length": "999"  # Wrong length
        }
        
        result = await shield.verify_webhook(mock_request)
        
        assert result.verified is False
        assert "Content length mismatch" in result.error_message
    
    @pytest.mark.asyncio
    async def test_verify_webhook_with_timestamp(self, basic_config, mock_request):
        """Test webhook verification with timestamp validation."""
        basic_config.enable_timestamp_validation = True
        basic_config.timestamp_header = "X-Test-Timestamp"
        shield = WebhookVerificationShield(config=basic_config)
        
        body = mock_request._body
        signature = hmac.new(
            basic_config.secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        current_time = int(time.time())
        mock_request.headers = {
            "X-Test-Signature": f"sha256={signature}",
            "X-Test-Timestamp": str(current_time)
        }
        
        result = await shield.verify_webhook(mock_request)
        
        assert result.verified is True
        assert result.timestamp_valid is True
        assert result.timestamp is not None
    
    @pytest.mark.asyncio
    async def test_verify_webhook_invalid_timestamp(self, basic_config, mock_request):
        """Test webhook verification with invalid timestamp."""
        basic_config.enable_timestamp_validation = True
        basic_config.timestamp_header = "X-Test-Timestamp"
        basic_config.timestamp_tolerance = 300
        shield = WebhookVerificationShield(config=basic_config)
        
        body = mock_request._body
        signature = hmac.new(
            basic_config.secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        old_time = int(time.time()) - 500  # Outside tolerance
        mock_request.headers = {
            "X-Test-Signature": f"sha256={signature}",
            "X-Test-Timestamp": str(old_time)
        }
        
        result = await shield.verify_webhook(mock_request)
        
        assert result.verified is False
        assert result.timestamp_valid is False
        assert "Invalid or expired timestamp" in result.error_message
    
    @pytest.mark.asyncio
    async def test_verify_webhook_replay_attack(self, basic_config, mock_request):
        """Test webhook verification with replay attack."""
        mock_replay = MockReplayProtection()
        shield = WebhookVerificationShield(
            config=basic_config, 
            replay_protection=mock_replay
        )
        
        body = mock_request._body
        signature = hmac.new(
            basic_config.secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        mock_request.headers = {
            "X-Test-Signature": f"sha256={signature}"
        }
        
        # First request should succeed
        result = await shield.verify_webhook(mock_request)
        assert result.verified is True
        
        # Second request (replay) should fail
        result = await shield.verify_webhook(mock_request)
        assert result.verified is False
        assert result.replay_check_passed is False
        assert "Replay attack detected" in result.error_message


class TestWebhookIntegration:
    """Integration tests with FastAPI."""
    
    @pytest.fixture
    def app_with_webhook(self):
        """Create FastAPI app with webhook endpoint."""
        app = FastAPI()
        
        @app.post("/webhooks/test")
        @custom_webhook_shield(
            secret="test-secret",
            enable_timestamp_validation=False,
            enable_replay_protection=False
        )
        def test_webhook():
            return {"status": "received"}
        
        return app
    
    def test_webhook_verification_success(self, app_with_webhook):
        """Test successful webhook verification."""
        client = TestClient(app_with_webhook)
        
        body = b'{"test": "data"}'
        signature = hmac.new(
            b"test-secret",
            body,
            hashlib.sha256
        ).hexdigest()
        
        response = client.post(
            "/webhooks/test",
            content=body,
            headers={
                "X-Hub-Signature-256": f"sha256={signature}",
                "Content-Type": "application/json"
            }
        )
        
        assert response.status_code == 200
        assert response.json() == {"status": "received"}
    
    def test_webhook_verification_failure(self, app_with_webhook):
        """Test failed webhook verification."""
        client = TestClient(app_with_webhook)
        
        body = b'{"test": "data"}'
        
        response = client.post(
            "/webhooks/test",
            content=body,
            headers={
                "X-Hub-Signature-256": "sha256=invalid_signature",
                "Content-Type": "application/json"
            }
        )
        
        assert response.status_code == 401
        assert "Invalid signature" in response.json()["detail"]
    
    def test_github_webhook_integration(self):
        """Test GitHub webhook integration."""
        app = FastAPI()
        
        @app.post("/webhooks/github")
        @github_webhook_shield(secret="github-secret")
        def github_webhook():
            return {"status": "processed"}
        
        client = TestClient(app)
        
        body = b'{"action": "opened", "number": 1}'
        signature = hmac.new(
            b"github-secret",
            body,
            hashlib.sha256
        ).hexdigest()
        
        response = client.post(
            "/webhooks/github",
            content=body,
            headers={
                "X-Hub-Signature-256": f"sha256={signature}",
                "Content-Type": "application/json"
            }
        )
        
        assert response.status_code == 200
        assert response.json() == {"status": "processed"}
    
    def test_stripe_webhook_integration(self):
        """Test Stripe webhook integration."""
        app = FastAPI()
        
        @app.post("/webhooks/stripe")
        @stripe_webhook_shield(secret="stripe-secret")
        def stripe_webhook():
            return {"status": "received"}
        
        client = TestClient(app)
        
        body = b'{"id": "evt_test", "type": "payment_intent.succeeded"}'
        timestamp = str(int(time.time()))
        
        # Generate Stripe signature
        payload = f"{timestamp}.".encode() + body
        signature = hmac.new(
            b"stripe-secret",
            payload,
            hashlib.sha256
        ).hexdigest()
        
        stripe_signature = f"t={timestamp},v1={signature}"
        
        response = client.post(
            "/webhooks/stripe",
            content=body,
            headers={
                "Stripe-Signature": stripe_signature,
                "Content-Type": "application/json"
            }
        )
        
        assert response.status_code == 200
        assert response.json() == {"status": "received"}


class TestConvenienceFunctions:
    """Test convenience functions for webhook verification."""
    
    def test_github_webhook_shield_factory(self):
        """Test GitHub webhook shield factory function."""
        shield = github_webhook_shield(
            secret="github-secret",
            algorithm=SignatureAlgorithm.SHA1
        )
        assert isinstance(shield, type(github_webhook_shield("test")))
    
    def test_stripe_webhook_shield_factory(self):
        """Test Stripe webhook shield factory function."""
        shield = stripe_webhook_shield(
            secret="stripe-secret",
            timestamp_tolerance=600
        )
        assert isinstance(shield, type(stripe_webhook_shield("test")))
    
    def test_paypal_webhook_shield_factory(self):
        """Test PayPal webhook shield factory function."""
        shield = paypal_webhook_shield(secret="paypal-secret")
        assert isinstance(shield, type(paypal_webhook_shield("test")))
    
    def test_slack_webhook_shield_factory(self):
        """Test Slack webhook shield factory function."""
        shield = slack_webhook_shield(
            secret="slack-secret",
            timestamp_tolerance=600
        )
        assert isinstance(shield, type(slack_webhook_shield("test")))
    
    def test_custom_webhook_shield_factory(self):
        """Test custom webhook shield factory function."""
        shield = custom_webhook_shield(
            secret="custom-secret",
            signature_header="X-Custom-Sig",
            enable_timestamp_validation=True
        )
        assert isinstance(shield, type(custom_webhook_shield("test")))


class TestRealWorldScenarios:
    """Test real-world webhook scenarios."""
    
    def test_github_push_webhook(self):
        """Test GitHub push webhook scenario."""
        # Real GitHub push webhook payload (simplified)
        payload = {
            "ref": "refs/heads/main",
            "commits": [
                {
                    "id": "abc123",
                    "message": "Update README",
                    "author": {"name": "John Doe", "email": "john@example.com"}
                }
            ]
        }
        
        import json
        body = json.dumps(payload).encode()
        secret = "my-github-secret"
        
        # Generate GitHub signature
        signature = hmac.new(
            secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        github_sig = f"sha256={signature}"
        
        app = FastAPI()
        
        @app.post("/webhooks/github-push")
        @github_webhook_shield(secret=secret)
        def handle_push():
            return {"status": "push processed"}
        
        client = TestClient(app)
        
        response = client.post(
            "/webhooks/github-push",
            content=body,
            headers={
                "X-Hub-Signature-256": github_sig,
                "X-GitHub-Event": "push",
                "Content-Type": "application/json"
            }
        )
        
        assert response.status_code == 200
        assert response.json() == {"status": "push processed"}
    
    def test_stripe_payment_webhook(self):
        """Test Stripe payment webhook scenario."""
        # Real Stripe payment webhook payload (simplified)
        payload = {
            "id": "evt_1234567890",
            "object": "event",
            "type": "payment_intent.succeeded",
            "data": {
                "object": {
                    "id": "pi_1234567890",
                    "amount": 2000,
                    "currency": "usd",
                    "status": "succeeded"
                }
            }
        }
        
        import json
        body = json.dumps(payload).encode()
        secret = "whsec_my_stripe_secret"
        timestamp = str(int(time.time()))
        
        # Generate Stripe signature
        payload_to_sign = f"{timestamp}.".encode() + body
        signature = hmac.new(
            secret.encode(),
            payload_to_sign,
            hashlib.sha256
        ).hexdigest()
        stripe_sig = f"t={timestamp},v1={signature}"
        
        app = FastAPI()
        
        @app.post("/webhooks/stripe-payment")
        @stripe_webhook_shield(secret=secret)
        def handle_payment():
            return {"status": "payment processed"}
        
        client = TestClient(app)
        
        response = client.post(
            "/webhooks/stripe-payment",
            content=body,
            headers={
                "Stripe-Signature": stripe_sig,
                "Content-Type": "application/json"
            }
        )
        
        assert response.status_code == 200
        assert response.json() == {"status": "payment processed"}


class TestErrorHandling:
    """Test error handling scenarios."""
    
    def test_invalid_algorithm(self):
        """Test invalid signature algorithm."""
        with pytest.raises(AttributeError):
            HMACSignatureValidator("invalid_algorithm")
    
    @pytest.mark.asyncio
    async def test_body_read_error(self):
        """Test error handling when body cannot be read."""
        config = WebhookConfig(secret="test")
        shield = WebhookVerificationShield(config=config)
        
        # Mock request that throws exception when reading body
        mock_request = Mock(spec=Request)
        mock_request.headers = {"X-Hub-Signature-256": "sha256=test"}
        
        async def failing_body():
            raise Exception("Cannot read body")
        
        mock_request.body = failing_body
        
        result = await shield.verify_webhook(mock_request)
        
        # Should handle gracefully and use empty body
        assert result.verified is False
        assert result.signature_valid is False
    
    @pytest.mark.asyncio
    async def test_replay_protection_error(self):
        """Test error handling in replay protection."""
        class FailingReplayProtection(ReplayProtection):
            async def is_request_seen(self, signature: str, timestamp: int) -> bool:
                raise Exception("Replay check failed")
            
            async def record_request(self, signature: str, timestamp: int) -> None:
                pass
            
            async def cleanup_expired(self) -> int:
                return 0
        
        config = WebhookConfig(
            secret="test", 
            enable_replay_protection=True,
            enable_timestamp_validation=False  # Disable timestamp validation for this test
        )
        failing_replay = FailingReplayProtection()
        shield = WebhookVerificationShield(
            config=config, 
            replay_protection=failing_replay
        )
        
        mock_request = Mock(spec=Request)
        body = b"test"
        mock_request._body = body
        
        # Generate valid signature
        import hashlib
        import hmac
        signature = hmac.new(
            b"test",
            body,
            hashlib.sha256
        ).hexdigest()
        
        mock_request.headers = {"X-Hub-Signature-256": f"sha256={signature}"}
        
        async def mock_body():
            return mock_request._body
        
        mock_request.body = mock_body
        
        result = await shield.verify_webhook(mock_request)
        
        assert result.verified is False
        assert "Replay protection error" in result.error_message
    
    def test_stripe_signature_without_timestamp(self):
        """Test Stripe signature validation without timestamp."""
        validator = StripeSignatureValidator()
        
        with pytest.raises(ValueError, match="Timestamp is required"):
            validator.generate_signature(b"test", "secret")
    
    def test_slack_signature_without_timestamp(self):
        """Test Slack signature validation without timestamp."""
        validator = SlackSignatureValidator()
        
        with pytest.raises(ValueError, match="Timestamp is required"):
            validator.generate_signature(b"test", "secret")


class TestPerformanceOptimizations:
    """Test performance optimization features."""
    
    @pytest.mark.asyncio
    async def test_body_caching(self):
        """Test that request body is cached for reuse."""
        config = WebhookConfig(secret="test", enable_replay_protection=False)
        shield = WebhookVerificationShield(config=config)
        
        mock_request = Mock(spec=Request)
        body_call_count = 0
        
        async def mock_body():
            nonlocal body_call_count
            body_call_count += 1
            return b'{"test": "data"}'
        
        mock_request.body = mock_body
        mock_request.headers = {}
        
        # Call get_raw_body twice
        body1 = await shield._get_raw_body(mock_request)
        body2 = await shield._get_raw_body(mock_request)
        
        # Body should be the same
        assert body1 == body2
        
        # Body method should only be called once due to caching
        assert body_call_count == 1
        assert hasattr(mock_request, '_body')
    
    @pytest.mark.asyncio
    async def test_memory_replay_protection_efficiency(self):
        """Test memory efficiency of replay protection."""
        protection = MemoryReplayProtection(max_size=3, ttl=3600)  # Use longer TTL
        
        # Use current time to avoid cleanup issues
        current_time = int(time.time())
        
        # Add more than max_size entries
        await protection.record_request("sig1", current_time)
        await protection.record_request("sig2", current_time + 1)
        await protection.record_request("sig3", current_time + 2)
        await protection.record_request("sig4", current_time + 3)  # Should evict sig1
        await protection.record_request("sig5", current_time + 4)  # Should evict sig2
        
        # Check that size is maintained
        assert len(protection.seen_requests) <= 3
        
        # Check that oldest entries were evicted
        assert await protection.is_request_seen("sig1", current_time) is False
        assert await protection.is_request_seen("sig2", current_time + 1) is False
        assert await protection.is_request_seen("sig3", current_time + 2) is True
        assert await protection.is_request_seen("sig4", current_time + 3) is True
        assert await protection.is_request_seen("sig5", current_time + 4) is True


if __name__ == "__main__":
    pytest.main([__file__])