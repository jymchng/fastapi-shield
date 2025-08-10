"""Webhook verification shield for FastAPI Shield.

This module provides comprehensive webhook signature verification with support
for multiple providers (GitHub, Stripe, PayPal, etc.), replay attack prevention,
and configurable signature algorithms. It ensures webhook endpoints only process
legitimate requests that haven't been tampered with.
"""

import hashlib
import hmac
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union
from urllib.parse import parse_qs

from fastapi import HTTPException, Request, status
from pydantic import BaseModel

from fastapi_shield.shield import Shield, shield


class SignatureAlgorithm(str, Enum):
    """Supported signature algorithms."""
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"


class WebhookProvider(str, Enum):
    """Supported webhook providers."""
    GITHUB = "github"
    STRIPE = "stripe"
    PAYPAL = "paypal"
    SLACK = "slack"
    DISCORD = "discord"
    CUSTOM = "custom"


class WebhookConfig(BaseModel):
    """Configuration for webhook verification."""
    
    # Provider settings
    provider: WebhookProvider = WebhookProvider.CUSTOM
    secret: str  # Webhook secret key
    
    # Signature settings
    signature_header: str = "X-Hub-Signature-256"
    signature_algorithm: SignatureAlgorithm = SignatureAlgorithm.SHA256
    signature_prefix: str = "sha256="  # Prefix before the signature
    
    # Timestamp settings for replay protection
    enable_timestamp_validation: bool = True
    timestamp_header: str = "X-Hub-Timestamp"
    timestamp_tolerance: int = 300  # seconds (5 minutes)
    
    # Body settings
    require_raw_body: bool = True
    encoding: str = "utf-8"
    
    # Security settings
    enable_replay_protection: bool = True
    replay_cache_size: int = 1000
    replay_cache_ttl: int = 600  # seconds (10 minutes)
    
    # Validation settings
    case_sensitive_headers: bool = False
    allow_missing_timestamp: bool = False
    verify_content_length: bool = True
    
    model_config = {"arbitrary_types_allowed": True}


class WebhookVerificationResult(BaseModel):
    """Result of webhook verification."""
    
    verified: bool
    provider: WebhookProvider
    signature_valid: bool
    timestamp_valid: bool
    replay_check_passed: bool
    error_message: Optional[str] = None
    timestamp: Optional[datetime] = None
    content_length: Optional[int] = None
    
    model_config = {"arbitrary_types_allowed": True}


class ReplayProtection(ABC):
    """Abstract base class for replay attack protection."""
    
    @abstractmethod
    async def is_request_seen(self, signature: str, timestamp: int) -> bool:
        """Check if this request signature/timestamp combination has been seen."""
        pass
    
    @abstractmethod
    async def record_request(self, signature: str, timestamp: int) -> None:
        """Record this request to prevent replay attacks."""
        pass
    
    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Clean up expired entries and return count cleaned."""
        pass


class MemoryReplayProtection(ReplayProtection):
    """In-memory replay protection for development and testing."""
    
    def __init__(self, max_size: int = 1000, ttl: int = 600):
        self.max_size = max_size
        self.ttl = ttl
        self.seen_requests: Dict[str, int] = {}  # signature -> timestamp
    
    async def is_request_seen(self, signature: str, timestamp: int) -> bool:
        """Check if this request signature/timestamp combination has been seen."""
        # Only cleanup periodically, not on every check
        return signature in self.seen_requests
    
    async def record_request(self, signature: str, timestamp: int) -> None:
        """Record this request to prevent replay attacks."""
        await self.cleanup_expired()
        
        # If cache is full, remove oldest entries
        while len(self.seen_requests) >= self.max_size:
            oldest_sig = min(self.seen_requests.keys(), key=lambda k: self.seen_requests[k])
            del self.seen_requests[oldest_sig]
        
        self.seen_requests[signature] = timestamp
    
    async def cleanup_expired(self) -> int:
        """Clean up expired entries and return count cleaned."""
        current_time = int(time.time())
        expired_signatures = [
            sig for sig, ts in self.seen_requests.items()
            if current_time - ts > self.ttl
        ]
        
        for sig in expired_signatures:
            del self.seen_requests[sig]
        
        return len(expired_signatures)


class SignatureValidator(ABC):
    """Abstract base class for signature validators."""
    
    @abstractmethod
    def validate_signature(
        self,
        body: bytes,
        signature: str,
        secret: str,
        timestamp: Optional[str] = None
    ) -> bool:
        """Validate webhook signature."""
        pass
    
    @abstractmethod
    def generate_signature(
        self,
        body: bytes,
        secret: str,
        timestamp: Optional[str] = None
    ) -> str:
        """Generate expected signature for comparison."""
        pass


class HMACSignatureValidator(SignatureValidator):
    """HMAC-based signature validator."""
    
    def __init__(self, algorithm: SignatureAlgorithm = SignatureAlgorithm.SHA256):
        self.algorithm = algorithm
        self.hash_func = getattr(hashlib, algorithm.value)
    
    def validate_signature(
        self,
        body: bytes,
        signature: str,
        secret: str,
        timestamp: Optional[str] = None
    ) -> bool:
        """Validate HMAC signature."""
        expected_sig = self.generate_signature(body, secret, timestamp)
        return hmac.compare_digest(signature, expected_sig)
    
    def generate_signature(
        self,
        body: bytes,
        secret: str,
        timestamp: Optional[str] = None
    ) -> str:
        """Generate HMAC signature."""
        # For basic HMAC, we just sign the body
        signature = hmac.new(
            secret.encode('utf-8'),
            body,
            self.hash_func
        ).hexdigest()
        return signature


class GitHubSignatureValidator(SignatureValidator):
    """GitHub webhook signature validator."""
    
    def __init__(self, algorithm: SignatureAlgorithm = SignatureAlgorithm.SHA256):
        self.algorithm = algorithm
        self.hash_func = getattr(hashlib, algorithm.value)
    
    def validate_signature(
        self,
        body: bytes,
        signature: str,
        secret: str,
        timestamp: Optional[str] = None
    ) -> bool:
        """Validate GitHub webhook signature."""
        expected_sig = self.generate_signature(body, secret, timestamp)
        return hmac.compare_digest(signature, expected_sig)
    
    def generate_signature(
        self,
        body: bytes,
        secret: str,
        timestamp: Optional[str] = None
    ) -> str:
        """Generate GitHub webhook signature."""
        signature = hmac.new(
            secret.encode('utf-8'),
            body,
            self.hash_func
        ).hexdigest()
        return f"{self.algorithm.value}={signature}"


class StripeSignatureValidator(SignatureValidator):
    """Stripe webhook signature validator."""
    
    def validate_signature(
        self,
        body: bytes,
        signature: str,
        secret: str,
        timestamp: Optional[str] = None
    ) -> bool:
        """Validate Stripe webhook signature."""
        if not timestamp:
            return False
        
        expected_sig = self.generate_signature(body, secret, timestamp)
        
        # Stripe signature format: t=timestamp,v1=signature,v1=signature2
        sig_parts = {}
        for part in signature.split(','):
            if '=' in part:
                key, value = part.split('=', 1)
                if key == 'v1':
                    if hmac.compare_digest(value, expected_sig):
                        return True
        
        return False
    
    def generate_signature(
        self,
        body: bytes,
        secret: str,
        timestamp: Optional[str] = None
    ) -> str:
        """Generate Stripe webhook signature."""
        if not timestamp:
            raise ValueError("Timestamp is required for Stripe signatures")
        
        # Stripe signature payload: timestamp.body
        payload = f"{timestamp}.".encode('utf-8') + body
        
        signature = hmac.new(
            secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return signature


class PayPalSignatureValidator(SignatureValidator):
    """PayPal webhook signature validator."""
    
    def validate_signature(
        self,
        body: bytes,
        signature: str,
        secret: str,
        timestamp: Optional[str] = None
    ) -> bool:
        """Validate PayPal webhook signature."""
        expected_sig = self.generate_signature(body, secret, timestamp)
        return hmac.compare_digest(signature, expected_sig)
    
    def generate_signature(
        self,
        body: bytes,
        secret: str,
        timestamp: Optional[str] = None
    ) -> str:
        """Generate PayPal webhook signature."""
        signature = hmac.new(
            secret.encode('utf-8'),
            body,
            hashlib.sha256
        ).hexdigest()
        return signature


class SlackSignatureValidator(SignatureValidator):
    """Slack webhook signature validator."""
    
    def validate_signature(
        self,
        body: bytes,
        signature: str,
        secret: str,
        timestamp: Optional[str] = None
    ) -> bool:
        """Validate Slack webhook signature."""
        if not timestamp:
            return False
        
        expected_sig = self.generate_signature(body, secret, timestamp)
        return hmac.compare_digest(signature, expected_sig)
    
    def generate_signature(
        self,
        body: bytes,
        secret: str,
        timestamp: Optional[str] = None
    ) -> str:
        """Generate Slack webhook signature."""
        if not timestamp:
            raise ValueError("Timestamp is required for Slack signatures")
        
        # Slack signature format: version:timestamp:body
        version = "v0"
        base_string = f"{version}:{timestamp}:".encode('utf-8') + body
        
        signature = hmac.new(
            secret.encode('utf-8'),
            base_string,
            hashlib.sha256
        ).hexdigest()
        
        return f"{version}={signature}"


class WebhookVerificationShield:
    """Webhook verification shield with multi-provider support."""
    
    def __init__(
        self,
        config: WebhookConfig,
        replay_protection: Optional[ReplayProtection] = None,
        signature_validator: Optional[SignatureValidator] = None,
    ):
        """Initialize webhook verification shield.
        
        Args:
            config: Webhook verification configuration
            replay_protection: Optional replay protection implementation
            signature_validator: Optional custom signature validator
        """
        self.config = config
        
        # Set up replay protection
        if replay_protection:
            self.replay_protection = replay_protection
        elif config.enable_replay_protection:
            self.replay_protection = MemoryReplayProtection(
                max_size=config.replay_cache_size,
                ttl=config.replay_cache_ttl
            )
        else:
            self.replay_protection = None
        
        # Set up signature validator
        if signature_validator:
            self.signature_validator = signature_validator
        else:
            self.signature_validator = self._get_default_validator()
    
    def _get_default_validator(self) -> SignatureValidator:
        """Get default signature validator based on provider."""
        if self.config.provider == WebhookProvider.GITHUB:
            return GitHubSignatureValidator(self.config.signature_algorithm)
        elif self.config.provider == WebhookProvider.STRIPE:
            return StripeSignatureValidator()
        elif self.config.provider == WebhookProvider.PAYPAL:
            return PayPalSignatureValidator()
        elif self.config.provider == WebhookProvider.SLACK:
            return SlackSignatureValidator()
        else:
            # Default HMAC validator
            return HMACSignatureValidator(self.config.signature_algorithm)
    
    def _get_header_value(self, request: Request, header_name: str) -> Optional[str]:
        """Get header value with optional case-insensitive lookup."""
        if self.config.case_sensitive_headers:
            return request.headers.get(header_name)
        else:
            # Case-insensitive lookup
            for key, value in request.headers.items():
                if key.lower() == header_name.lower():
                    return value
            return None
    
    def _extract_signature(self, signature_header: str) -> str:
        """Extract signature from header, removing prefix if needed."""
        # For GitHub, we don't strip the prefix since the validator expects it
        if self.config.provider == WebhookProvider.GITHUB:
            return signature_header
        
        if self.config.signature_prefix and signature_header.startswith(self.config.signature_prefix):
            return signature_header[len(self.config.signature_prefix):]
        return signature_header
    
    def _validate_timestamp(self, timestamp_str: str) -> tuple[bool, Optional[datetime]]:
        """Validate timestamp for replay protection."""
        if not self.config.enable_timestamp_validation:
            return True, None
        
        try:
            timestamp = int(timestamp_str)
            current_time = int(time.time())
            
            # Check if timestamp is within tolerance
            if abs(current_time - timestamp) > self.config.timestamp_tolerance:
                return False, None
            
            return True, datetime.fromtimestamp(timestamp, tz=timezone.utc)
        
        except (ValueError, OverflowError):
            return False, None
    
    async def _get_raw_body(self, request: Request) -> bytes:
        """Get raw request body for signature verification."""
        try:
            if hasattr(request, '_body'):
                # Body already read
                body = request._body
            else:
                # Read body
                body = await request.body()
                # Store for potential reuse
                request._body = body
            
            return body
        except Exception:
            return b""
    
    async def verify_webhook(self, request: Request) -> WebhookVerificationResult:
        """Verify webhook request signature and prevent replay attacks."""
        result = WebhookVerificationResult(
            verified=False,
            provider=self.config.provider,
            signature_valid=False,
            timestamp_valid=True,  # Default to True if not using timestamp validation
            replay_check_passed=True,  # Default to True if not using replay protection
        )
        
        try:
            # Get signature from headers
            signature_header = self._get_header_value(request, self.config.signature_header)
            if not signature_header:
                result.error_message = f"Missing signature header: {self.config.signature_header}"
                return result
            
            # Extract signature
            signature = self._extract_signature(signature_header)
            
            # Get timestamp if required
            timestamp_str = None
            if self.config.enable_timestamp_validation or self.config.provider in [
                WebhookProvider.STRIPE, WebhookProvider.SLACK
            ]:
                if self.config.provider == WebhookProvider.STRIPE:
                    # For Stripe, timestamp is embedded in the signature header
                    if signature_header and 't=' in signature_header:
                        timestamp_part = [part for part in signature_header.split(',') if part.startswith('t=')]
                        if timestamp_part:
                            timestamp_str = timestamp_part[0].split('=', 1)[1]
                else:
                    timestamp_str = self._get_header_value(request, self.config.timestamp_header)
                
                if not timestamp_str and not self.config.allow_missing_timestamp:
                    result.error_message = f"Missing timestamp header: {self.config.timestamp_header}"
                    return result
                
                # Validate timestamp
                if timestamp_str:
                    timestamp_valid, timestamp_dt = self._validate_timestamp(timestamp_str)
                    result.timestamp_valid = timestamp_valid
                    result.timestamp = timestamp_dt
                    
                    if not timestamp_valid:
                        result.error_message = "Invalid or expired timestamp"
                        return result
            
            # Get raw body
            body = await self._get_raw_body(request)
            
            # Verify content length if required
            if self.config.verify_content_length:
                content_length_header = self._get_header_value(request, 'content-length')
                if content_length_header:
                    try:
                        expected_length = int(content_length_header)
                        actual_length = len(body)
                        result.content_length = actual_length
                        
                        if expected_length != actual_length:
                            result.error_message = f"Content length mismatch: expected {expected_length}, got {actual_length}"
                            return result
                    except ValueError:
                        result.error_message = "Invalid content-length header"
                        return result
            
            # Validate signature
            try:
                signature_valid = self.signature_validator.validate_signature(
                    body=body,
                    signature=signature,
                    secret=self.config.secret,
                    timestamp=timestamp_str
                )
                result.signature_valid = signature_valid
                
                if not signature_valid:
                    result.error_message = "Invalid signature"
                    return result
            
            except Exception as e:
                result.error_message = f"Signature validation error: {str(e)}"
                return result
            
            # Check for replay attacks
            if self.replay_protection:
                try:
                    timestamp_int = int(timestamp_str) if timestamp_str else int(time.time())
                    
                    if await self.replay_protection.is_request_seen(signature, timestamp_int):
                        result.replay_check_passed = False
                        result.error_message = "Replay attack detected"
                        return result
                    
                    # Record this request
                    await self.replay_protection.record_request(signature, timestamp_int)
                
                except Exception as e:
                    result.error_message = f"Replay protection error: {str(e)}"
                    return result
            
            # All checks passed
            result.verified = True
            return result
        
        except Exception as e:
            result.error_message = f"Verification error: {str(e)}"
            return result
    
    def create_shield(
        self,
        name: str = "WebhookVerification"
    ) -> Shield:
        """Create a shield for webhook verification.
        
        Args:
            name: Shield name
            
        Returns:
            Shield instance
        """
        
        async def webhook_verification_shield(request: Request) -> Dict[str, Any]:
            """Webhook verification shield function."""
            result = await self.verify_webhook(request)
            
            if not result.verified:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=result.error_message or "Webhook verification failed"
                )
            
            return {
                "webhook_verified": True,
                "provider": result.provider,
                "timestamp": result.timestamp,
                "signature_algorithm": self.config.signature_algorithm,
                "verification_result": result,
            }
        
        return shield(
            webhook_verification_shield,
            name=name,
            auto_error=True,
        )


# Convenience functions for popular webhook providers
def github_webhook_shield(
    secret: str,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.SHA256,
    enable_timestamp_validation: bool = False,
    name: str = "GitHubWebhook",
) -> Shield:
    """Create a webhook verification shield for GitHub webhooks.
    
    Args:
        secret: GitHub webhook secret
        algorithm: Signature algorithm (sha1 or sha256)
        enable_timestamp_validation: Whether to validate timestamps
        name: Shield name
        
    Returns:
        Shield: GitHub webhook verification shield
        
    Examples:
        ```python
        # Basic GitHub webhook
        @app.post("/webhooks/github")
        @github_webhook_shield(secret="your-github-secret")
        def github_webhook(payload: dict):
            return {"status": "processed"}
        
        # GitHub webhook with SHA1 (legacy)
        @app.post("/webhooks/github-legacy")
        @github_webhook_shield(
            secret="your-secret",
            algorithm=SignatureAlgorithm.SHA1
        )
        def github_webhook_legacy(payload: dict):
            return {"status": "processed"}
        ```
    """
    signature_header = "X-Hub-Signature-256"
    signature_prefix = f"{algorithm.value}="
    
    if algorithm == SignatureAlgorithm.SHA1:
        signature_header = "X-Hub-Signature"
    
    config = WebhookConfig(
        provider=WebhookProvider.GITHUB,
        secret=secret,
        signature_header=signature_header,
        signature_algorithm=algorithm,
        signature_prefix=signature_prefix,
        enable_timestamp_validation=enable_timestamp_validation,
        timestamp_header="X-Hub-Timestamp",
    )
    
    shield_instance = WebhookVerificationShield(config=config)
    return shield_instance.create_shield(name=name)


def stripe_webhook_shield(
    secret: str,
    timestamp_tolerance: int = 300,
    name: str = "StripeWebhook",
) -> Shield:
    """Create a webhook verification shield for Stripe webhooks.
    
    Args:
        secret: Stripe webhook signing secret
        timestamp_tolerance: Timestamp tolerance in seconds
        name: Shield name
        
    Returns:
        Shield: Stripe webhook verification shield
        
    Examples:
        ```python
        # Stripe webhook
        @app.post("/webhooks/stripe")
        @stripe_webhook_shield(secret="whsec_your_stripe_secret")
        def stripe_webhook(event: dict):
            return {"status": "received"}
        
        # Stripe webhook with custom tolerance
        @app.post("/webhooks/stripe-custom")
        @stripe_webhook_shield(
            secret="whsec_your_secret",
            timestamp_tolerance=600  # 10 minutes
        )
        def stripe_webhook_custom(event: dict):
            return {"status": "received"}
        ```
    """
    config = WebhookConfig(
        provider=WebhookProvider.STRIPE,
        secret=secret,
        signature_header="Stripe-Signature",
        signature_algorithm=SignatureAlgorithm.SHA256,
        signature_prefix="",  # Stripe has its own format
        enable_timestamp_validation=True,
        timestamp_header="Stripe-Signature",  # Timestamp is in the same header
        timestamp_tolerance=timestamp_tolerance,
    )
    
    shield_instance = WebhookVerificationShield(config=config)
    return shield_instance.create_shield(name=name)


def paypal_webhook_shield(
    secret: str,
    name: str = "PayPalWebhook",
) -> Shield:
    """Create a webhook verification shield for PayPal webhooks.
    
    Args:
        secret: PayPal webhook secret
        name: Shield name
        
    Returns:
        Shield: PayPal webhook verification shield
        
    Examples:
        ```python
        # PayPal webhook
        @app.post("/webhooks/paypal")
        @paypal_webhook_shield(secret="your-paypal-secret")
        def paypal_webhook(event: dict):
            return {"status": "processed"}
        ```
    """
    config = WebhookConfig(
        provider=WebhookProvider.PAYPAL,
        secret=secret,
        signature_header="PAYPAL-TRANSMISSION-SIG",
        signature_algorithm=SignatureAlgorithm.SHA256,
        signature_prefix="",
        enable_timestamp_validation=False,  # PayPal doesn't use timestamps
    )
    
    shield_instance = WebhookVerificationShield(config=config)
    return shield_instance.create_shield(name=name)


def slack_webhook_shield(
    secret: str,
    timestamp_tolerance: int = 300,
    name: str = "SlackWebhook",
) -> Shield:
    """Create a webhook verification shield for Slack webhooks.
    
    Args:
        secret: Slack signing secret
        timestamp_tolerance: Timestamp tolerance in seconds
        name: Shield name
        
    Returns:
        Shield: Slack webhook verification shield
        
    Examples:
        ```python
        # Slack webhook
        @app.post("/webhooks/slack")
        @slack_webhook_shield(secret="your-slack-signing-secret")
        def slack_webhook(payload: dict):
            return {"status": "ok"}
        
        # Slack webhook with custom tolerance
        @app.post("/webhooks/slack-custom")
        @slack_webhook_shield(
            secret="your-secret",
            timestamp_tolerance=600  # 10 minutes
        )
        def slack_webhook_custom(payload: dict):
            return {"status": "ok"}
        ```
    """
    config = WebhookConfig(
        provider=WebhookProvider.SLACK,
        secret=secret,
        signature_header="X-Slack-Signature",
        signature_algorithm=SignatureAlgorithm.SHA256,
        signature_prefix="v0=",
        enable_timestamp_validation=True,
        timestamp_header="X-Slack-Request-Timestamp",
        timestamp_tolerance=timestamp_tolerance,
    )
    
    shield_instance = WebhookVerificationShield(config=config)
    return shield_instance.create_shield(name=name)


def custom_webhook_shield(
    secret: str,
    signature_header: str = "X-Hub-Signature-256",
    signature_algorithm: SignatureAlgorithm = SignatureAlgorithm.SHA256,
    signature_prefix: str = "sha256=",
    enable_timestamp_validation: bool = False,
    timestamp_header: str = "X-Hub-Timestamp",
    timestamp_tolerance: int = 300,
    enable_replay_protection: bool = True,
    name: str = "CustomWebhook",
) -> Shield:
    """Create a custom webhook verification shield.
    
    Args:
        secret: Webhook secret
        signature_header: Header containing the signature
        signature_algorithm: Algorithm used for signature
        signature_prefix: Prefix before the signature
        enable_timestamp_validation: Whether to validate timestamps
        timestamp_header: Header containing the timestamp
        timestamp_tolerance: Timestamp tolerance in seconds
        enable_replay_protection: Whether to enable replay protection
        name: Shield name
        
    Returns:
        Shield: Custom webhook verification shield
        
    Examples:
        ```python
        # Custom webhook with timestamp validation
        @app.post("/webhooks/custom")
        @custom_webhook_shield(
            secret="your-secret",
            signature_header="X-Custom-Signature",
            enable_timestamp_validation=True
        )
        def custom_webhook(payload: dict):
            return {"status": "processed"}
        
        # Simple HMAC verification
        @app.post("/webhooks/simple")
        @custom_webhook_shield(
            secret="your-secret",
            signature_prefix="",
            enable_timestamp_validation=False
        )
        def simple_webhook(payload: dict):
            return {"status": "ok"}
        ```
    """
    config = WebhookConfig(
        provider=WebhookProvider.CUSTOM,
        secret=secret,
        signature_header=signature_header,
        signature_algorithm=signature_algorithm,
        signature_prefix=signature_prefix,
        enable_timestamp_validation=enable_timestamp_validation,
        timestamp_header=timestamp_header,
        timestamp_tolerance=timestamp_tolerance,
        enable_replay_protection=enable_replay_protection,
    )
    
    shield_instance = WebhookVerificationShield(config=config)
    return shield_instance.create_shield(name=name)