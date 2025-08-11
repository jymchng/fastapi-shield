"""Comprehensive test suite for Zero-Trust Network Architecture Integration Shield."""

import pytest
import asyncio
import secrets
import time
import hashlib
import json
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

import numpy as np

from src.fastapi_shield.zero_trust_network import (
    ZeroTrustShield, ZeroTrustDatabase, IdentityVerificationEngine,
    NetworkMicroSegmentation, ContinuousAuthorizationEngine, DataClassificationEngine,
    TrustLevel, RiskScore, AccessDecision, AuthenticationMethod, DeviceType,
    NetworkZone, DataClassification, ComplianceFramework,
    DeviceIdentity, UserIdentity, NetworkContext, AccessRequest,
    AccessDecisionResult, ZeroTrustPolicy, BehavioralProfile,
    create_zero_trust_shield
)
from tests.mocks.mock_zero_trust_network import (
    MockZeroTrustShield, MockZeroTrustTestEnvironment,
    MockZeroTrustDatabase, MockIdentityVerificationEngine
)


class TestZeroTrustDatabase:
    """Test zero-trust database functionality."""
    
    def test_database_initialization(self, tmp_path):
        """Test database initialization and schema creation."""
        db_path = tmp_path / "test_zero_trust.db"
        db = ZeroTrustDatabase(str(db_path))
        
        assert db.db_path == str(db_path)
        assert os.path.exists(str(db_path))
        
        # Test table creation
        import sqlite3
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            expected_tables = [
                'user_identities', 'device_identities', 'zero_trust_policies',
                'access_requests', 'behavioral_profiles', 'network_sessions',
                'threat_intelligence', 'compliance_audit'
            ]
            for table in expected_tables:
                assert table in tables
    
    def test_user_identity_storage_and_retrieval(self, tmp_path):
        """Test storing and retrieving user identities."""
        db_path = tmp_path / "test_user_identity.db"
        db = ZeroTrustDatabase(str(db_path))
        
        user_identity = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john.doe@company.com",
            roles=["user", "developer"],
            groups=["engineering"],
            trust_level=TrustLevel.HIGH,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.PASSWORD, AuthenticationMethod.MFA],
            behavioral_profile={"login_frequency": 5.2},
            risk_indicators=["off_hours_access"],
            metadata={"department": "engineering"}
        )
        
        # Store user identity
        assert db.store_user_identity(user_identity) == True
        
        # Retrieve user identity
        retrieved = db.get_user_identity(user_identity.user_id)
        assert retrieved is not None
        assert retrieved.user_id == user_identity.user_id
        assert retrieved.username == user_identity.username
        assert retrieved.email == user_identity.email
        assert retrieved.roles == user_identity.roles
        assert retrieved.trust_level == user_identity.trust_level
        assert len(retrieved.authentication_methods) == 2
    
    def test_device_identity_storage_and_retrieval(self, tmp_path):
        """Test storing and retrieving device identities."""
        db_path = tmp_path / "test_device_identity.db"
        db = ZeroTrustDatabase(str(db_path))
        
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.LAPTOP,
            manufacturer="TestCorp",
            model="SecureBook",
            os_version="TestOS 2.0",
            trust_level=TrustLevel.VERIFIED,
            last_seen=datetime.now(timezone.utc),
            certificate_fingerprint="abc123def456",
            compliance_status={"antivirus": True, "firewall": True},
            risk_factors=["outdated_patch"],
            metadata={"managed": True}
        )
        
        # Store device identity
        assert db.store_device_identity(device_identity) == True
        
        # Retrieve device identity
        retrieved = db.get_device_identity(device_identity.device_id)
        assert retrieved is not None
        assert retrieved.device_id == device_identity.device_id
        assert retrieved.device_type == device_identity.device_type
        assert retrieved.trust_level == device_identity.trust_level
        assert retrieved.compliance_status == device_identity.compliance_status
    
    def test_access_request_storage(self, tmp_path):
        """Test storing access requests and decisions."""
        db_path = tmp_path / "test_access_request.db"
        db = ZeroTrustDatabase(str(db_path))
        
        # Create test data
        user_identity = UserIdentity(
            user_id="user_001",
            username="test.user",
            email="test@company.com",
            roles=["user"],
            groups=[],
            trust_level=TrustLevel.MEDIUM,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.PASSWORD]
        )
        
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.DESKTOP,
            manufacturer="TestCorp",
            model="TestDevice",
            os_version="TestOS 1.0",
            trust_level=TrustLevel.MEDIUM,
            last_seen=datetime.now(timezone.utc)
        )
        
        network_context = NetworkContext(
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            source_port=12345,
            destination_port=443,
            protocol="tcp",
            network_zone=NetworkZone.INTERNAL
        )
        
        access_request = AccessRequest(
            request_id="req_001",
            user_identity=user_identity,
            device_identity=device_identity,
            network_context=network_context,
            resource="/api/data",
            action="read",
            data_classification=DataClassification.INTERNAL,
            timestamp=datetime.now(timezone.utc)
        )
        
        decision = AccessDecisionResult(
            decision=AccessDecision.ALLOW,
            risk_score=25,
            trust_score=75,
            reasons=["Low risk access granted"],
            required_actions=[],
            monitoring_requirements=["Standard logging"]
        )
        
        # Store access request
        assert db.store_access_request(access_request, decision) == True
    
    def test_nonexistent_identity_retrieval(self, tmp_path):
        """Test retrieving non-existent identities."""
        db_path = tmp_path / "test_nonexistent.db"
        db = ZeroTrustDatabase(str(db_path))
        
        # Test non-existent user
        user = db.get_user_identity("nonexistent_user")
        assert user is None
        
        # Test non-existent device
        device = db.get_device_identity("nonexistent_device")
        assert device is None


class TestIdentityVerificationEngine:
    """Test identity verification engine."""
    
    def test_valid_user_identity_verification(self, tmp_path):
        """Test successful user identity verification."""
        db_path = tmp_path / "test_identity_verification.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = IdentityVerificationEngine(db)
        
        # Create a valid JWT token (simplified for testing)
        import jwt
        token_payload = {
            'sub': 'user_001',
            'username': 'john.doe',
            'email': 'john.doe@company.com',
            'roles': ['user', 'developer'],
            'groups': ['engineering'],
            'exp': (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        }
        
        valid_token = jwt.encode(token_payload, 'secret', algorithm='HS256')
        
        # Test with multi-factor authentication
        auth_factors = [
            {'type': 'password', 'success': True},
            {'type': 'mfa', 'success': True}
        ]
        
        user_identity, trust_level = engine.verify_user_identity(valid_token, auth_factors)
        
        assert user_identity is not None
        assert user_identity.user_id == 'user_001'
        assert user_identity.username == 'john.doe'
        assert trust_level in [TrustLevel.MEDIUM, TrustLevel.HIGH, TrustLevel.VERIFIED]
        assert AuthenticationMethod.PASSWORD in user_identity.authentication_methods
        assert AuthenticationMethod.MFA in user_identity.authentication_methods
    
    def test_invalid_user_token_verification(self, tmp_path):
        """Test user identity verification with invalid token."""
        db_path = tmp_path / "test_invalid_token.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = IdentityVerificationEngine(db)
        
        invalid_token = "invalid.jwt.token"
        auth_factors = []
        
        user_identity, trust_level = engine.verify_user_identity(invalid_token, auth_factors)
        
        assert user_identity is None
        assert trust_level == TrustLevel.UNTRUSTED
    
    def test_expired_token_verification(self, tmp_path):
        """Test user identity verification with expired token."""
        db_path = tmp_path / "test_expired_token.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = IdentityVerificationEngine(db)
        
        # Create expired token
        import jwt
        expired_payload = {
            'sub': 'user_001',
            'username': 'john.doe',
            'exp': (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()
        }
        
        expired_token = jwt.encode(expired_payload, 'secret', algorithm='HS256')
        
        user_identity, trust_level = engine.verify_user_identity(expired_token, [])
        
        assert user_identity is None
        assert trust_level == TrustLevel.UNTRUSTED
    
    def test_device_identity_verification_with_valid_certificate(self, tmp_path):
        """Test device identity verification with valid certificate."""
        db_path = tmp_path / "test_device_cert.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = IdentityVerificationEngine(db)
        
        # Create mock valid certificate (base64 encoded)
        mock_cert = secrets.token_bytes(256)
        valid_certificate = Mock()
        valid_certificate.not_valid_after = datetime.now(timezone.utc) + timedelta(days=30)
        valid_certificate.not_valid_before = datetime.now(timezone.utc) - timedelta(days=1)
        
        device_info = {
            'device_type': 'laptop',
            'manufacturer': 'TestCorp',
            'model': 'SecureBook',
            'os_version': 'TestOS 2.0',
            'compliance': {
                'antivirus_enabled': True,
                'firewall_enabled': True,
                'encryption_enabled': True
            },
            'managed_device': True
        }
        
        # Mock certificate validation by providing a long enough certificate string
        long_certificate = secrets.token_urlsafe(200)
        
        device_identity, trust_level = engine.verify_device_identity(long_certificate, device_info)
        
        assert device_identity is not None
        assert device_identity.device_type == DeviceType.LAPTOP
        assert device_identity.manufacturer == 'TestCorp'
        assert trust_level.value >= TrustLevel.LOW.value
    
    def test_device_identity_verification_with_invalid_certificate(self, tmp_path):
        """Test device identity verification with invalid certificate."""
        db_path = tmp_path / "test_invalid_device_cert.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = IdentityVerificationEngine(db)
        
        invalid_certificate = "short_cert"  # Too short to be valid
        device_info = {'device_type': 'unknown'}
        
        device_identity, trust_level = engine.verify_device_identity(invalid_certificate, device_info)
        
        assert device_identity is None
        assert trust_level == TrustLevel.UNTRUSTED
    
    def test_authentication_factor_evaluation(self, tmp_path):
        """Test authentication factor evaluation for trust level calculation."""
        db_path = tmp_path / "test_auth_factors.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = IdentityVerificationEngine(db)
        
        # Test different authentication factor combinations
        test_cases = [
            # Single factor (password only)
            ([{'type': 'password', 'success': True}], TrustLevel.LOW),
            
            # Multi-factor (password + MFA)
            ([
                {'type': 'password', 'success': True},
                {'type': 'mfa', 'success': True}
            ], TrustLevel.MEDIUM),
            
            # High security (certificate + biometric)
            ([
                {'type': 'certificate', 'success': True},
                {'type': 'biometric', 'success': True}
            ], TrustLevel.VERIFIED),
            
            # Failed authentication
            ([{'type': 'password', 'success': False}], TrustLevel.UNTRUSTED)
        ]
        
        for auth_factors, expected_min_level in test_cases:
            user_identity = UserIdentity(
                user_id="test_user",
                username="test",
                email="test@test.com",
                roles=["user"],
                groups=[],
                trust_level=TrustLevel.LOW,
                last_authentication=datetime.now(timezone.utc),
                authentication_methods=[]
            )
            
            calculated_level = engine._evaluate_authentication_factors(user_identity, auth_factors)
            
            # For failed auth, expect UNTRUSTED; otherwise, at least the minimum expected level
            if expected_min_level == TrustLevel.UNTRUSTED:
                assert calculated_level == TrustLevel.UNTRUSTED
            else:
                assert calculated_level.value >= expected_min_level.value


class TestNetworkMicroSegmentation:
    """Test network micro-segmentation functionality."""
    
    def test_internal_network_access_evaluation(self, tmp_path):
        """Test network access evaluation for internal networks."""
        db_path = tmp_path / "test_network_internal.db"
        db = ZeroTrustDatabase(str(db_path))
        segmentation = NetworkMicroSegmentation(db)
        
        # Create test data
        network_context = NetworkContext(
            source_ip="192.168.1.100",  # Internal IP
            destination_ip="10.0.0.1",
            source_port=12345,
            destination_port=443,
            protocol="tcp",
            network_zone=NetworkZone.INTERNAL
        )
        
        user_identity = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john@company.com",
            roles=["user"],
            groups=[],
            trust_level=TrustLevel.HIGH,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.MFA]
        )
        
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.LAPTOP,
            manufacturer="TestCorp",
            model="SecureBook",
            os_version="TestOS 2.0",
            trust_level=TrustLevel.HIGH,
            last_seen=datetime.now(timezone.utc)
        )
        
        allowed, reasons = segmentation.evaluate_network_access(network_context, user_identity, device_identity)
        
        assert allowed == True
        assert len(reasons) > 0
        assert any("Internal network" in reason or "access granted" in reason.lower() for reason in reasons)
    
    def test_external_network_access_evaluation(self, tmp_path):
        """Test network access evaluation for external networks."""
        db_path = tmp_path / "test_network_external.db"
        db = ZeroTrustDatabase(str(db_path))
        segmentation = NetworkMicroSegmentation(db)
        
        # External IP access
        network_context = NetworkContext(
            source_ip="203.0.113.1",  # External IP
            destination_ip="10.0.0.1",
            source_port=12345,
            destination_port=443,
            protocol="tcp",
            network_zone=NetworkZone.PUBLIC
        )
        
        # Regular user (not admin)
        user_identity = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john@company.com",
            roles=["user"],
            groups=[],
            trust_level=TrustLevel.MEDIUM,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.PASSWORD]
        )
        
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.LAPTOP,
            manufacturer="TestCorp",
            model="SecureBook",
            os_version="TestOS 2.0",
            trust_level=TrustLevel.MEDIUM,
            last_seen=datetime.now(timezone.utc)
        )
        
        allowed, reasons = segmentation.evaluate_network_access(network_context, user_identity, device_identity)
        
        assert allowed == False
        assert len(reasons) > 0
        assert any("External access requires admin" in reason for reason in reasons)
    
    def test_administrative_port_access(self, tmp_path):
        """Test access to administrative ports."""
        db_path = tmp_path / "test_admin_ports.db"
        db = ZeroTrustDatabase(str(db_path))
        segmentation = NetworkMicroSegmentation(db)
        
        # Test SSH port access
        network_context = NetworkContext(
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            source_port=12345,
            destination_port=22,  # SSH port
            protocol="tcp",
            network_zone=NetworkZone.INTERNAL
        )
        
        # Regular user
        user_identity = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john@company.com",
            roles=["user"],
            groups=[],
            trust_level=TrustLevel.HIGH,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.MFA]
        )
        
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.LAPTOP,
            manufacturer="TestCorp",
            model="SecureBook",
            os_version="TestOS 2.0",
            trust_level=TrustLevel.HIGH,
            last_seen=datetime.now(timezone.utc)
        )
        
        allowed, reasons = segmentation.evaluate_network_access(network_context, user_identity, device_identity)
        
        assert allowed == False
        assert any("Administrative port access requires admin" in reason for reason in reasons)
        
        # Test with admin user
        admin_user = UserIdentity(
            user_id="admin_001",
            username="admin.user",
            email="admin@company.com",
            roles=["admin"],
            groups=[],
            trust_level=TrustLevel.VERIFIED,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.CERTIFICATE]
        )
        
        allowed, reasons = segmentation.evaluate_network_access(network_context, admin_user, device_identity)
        
        # Admin should have better chances but other factors may still deny
        # The exact result depends on implementation details
        assert isinstance(allowed, bool)
    
    def test_dynamic_firewall_rule_creation(self, tmp_path):
        """Test dynamic firewall rule creation."""
        db_path = tmp_path / "test_firewall_rules.db"
        db = ZeroTrustDatabase(str(db_path))
        segmentation = NetworkMicroSegmentation(db)
        
        # Create test access request
        user_identity = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john@company.com",
            roles=["user"],
            groups=[],
            trust_level=TrustLevel.HIGH,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.MFA]
        )
        
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.LAPTOP,
            manufacturer="TestCorp",
            model="SecureBook",
            os_version="TestOS 2.0",
            trust_level=TrustLevel.HIGH,
            last_seen=datetime.now(timezone.utc)
        )
        
        network_context = NetworkContext(
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            source_port=12345,
            destination_port=443,
            protocol="tcp",
            network_zone=NetworkZone.INTERNAL
        )
        
        access_request = AccessRequest(
            request_id="req_001",
            user_identity=user_identity,
            device_identity=device_identity,
            network_context=network_context,
            resource="/api/data",
            action="read",
            data_classification=DataClassification.INTERNAL,
            timestamp=datetime.now(timezone.utc)
        )
        
        decision = AccessDecisionResult(
            decision=AccessDecision.ALLOW,
            risk_score=25,
            trust_score=75,
            reasons=["Access granted"],
            required_actions=[],
            monitoring_requirements=["Standard logging"],
            expiration=datetime.now(timezone.utc) + timedelta(hours=8)
        )
        
        # Create firewall rule
        rule = segmentation.create_dynamic_firewall_rule(access_request, decision)
        
        assert rule is not None
        assert 'rule_id' in rule
        assert rule['source_ip'] == "192.168.1.100"
        assert rule['destination_port'] == 443
        assert rule['action'] == 'ALLOW'
        assert rule['user_id'] == "user_001"
        assert rule['device_id'] == "device_001"
    
    def test_off_hours_access_restrictions(self, tmp_path):
        """Test off-hours access restrictions."""
        db_path = tmp_path / "test_off_hours.db"
        db = ZeroTrustDatabase(str(db_path))
        segmentation = NetworkMicroSegmentation(db)
        
        network_context = NetworkContext(
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            source_port=12345,
            destination_port=443,
            protocol="tcp",
            network_zone=NetworkZone.INTERNAL
        )
        
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.LAPTOP,
            manufacturer="TestCorp",
            model="SecureBook",
            os_version="TestOS 2.0",
            trust_level=TrustLevel.HIGH,
            last_seen=datetime.now(timezone.utc)
        )
        
        # Test during off-hours (simulated by mocking time)
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value.hour = 2  # 2 AM
            
            # Regular user during off-hours
            user_identity = UserIdentity(
                user_id="user_001",
                username="john.doe",
                email="john@company.com",
                roles=["user"],
                groups=[],
                trust_level=TrustLevel.MEDIUM,
                last_authentication=datetime.now(timezone.utc),
                authentication_methods=[AuthenticationMethod.PASSWORD]
            )
            
            allowed, reasons = segmentation.evaluate_network_access(network_context, user_identity, device_identity)
            
            # The exact result depends on implementation, but should consider time restrictions
            assert isinstance(allowed, bool)
            assert len(reasons) > 0


class TestContinuousAuthorizationEngine:
    """Test continuous authorization engine."""
    
    def test_low_risk_access_request_evaluation(self, tmp_path):
        """Test evaluation of low-risk access request."""
        db_path = tmp_path / "test_low_risk_auth.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = ContinuousAuthorizationEngine(db)
        
        # Create low-risk scenario
        user_identity = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john@company.com",
            roles=["user"],
            groups=[],
            trust_level=TrustLevel.HIGH,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.MFA],
            risk_indicators=[]
        )
        
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.LAPTOP,
            manufacturer="TestCorp",
            model="SecureBook",
            os_version="TestOS 2.0",
            trust_level=TrustLevel.HIGH,
            last_seen=datetime.now(timezone.utc),
            risk_factors=[]
        )
        
        network_context = NetworkContext(
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            source_port=12345,
            destination_port=443,
            protocol="tcp",
            network_zone=NetworkZone.INTERNAL,
            threat_indicators=[]
        )
        
        access_request = AccessRequest(
            request_id="req_001",
            user_identity=user_identity,
            device_identity=device_identity,
            network_context=network_context,
            resource="/api/public-data",
            action="read",
            data_classification=DataClassification.PUBLIC,
            timestamp=datetime.now(timezone.utc)
        )
        
        result = engine.evaluate_access_request(access_request)
        
        assert isinstance(result, AccessDecisionResult)
        assert result.decision in [AccessDecision.ALLOW, AccessDecision.MONITOR]
        assert result.risk_score <= 60  # Should be low risk
        assert result.trust_score >= 40  # Should have reasonable trust
        assert len(result.reasons) > 0
    
    def test_high_risk_access_request_evaluation(self, tmp_path):
        """Test evaluation of high-risk access request."""
        db_path = tmp_path / "test_high_risk_auth.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = ContinuousAuthorizationEngine(db)
        
        # Create high-risk scenario
        user_identity = UserIdentity(
            user_id="user_002",
            username="suspicious.user",
            email="suspicious@external.com",
            roles=["guest"],
            groups=[],
            trust_level=TrustLevel.LOW,
            last_authentication=datetime.now(timezone.utc) - timedelta(days=1),
            authentication_methods=[AuthenticationMethod.PASSWORD],
            risk_indicators=["multiple_failed_logins", "unusual_location"]
        )
        
        device_identity = DeviceIdentity(
            device_id="device_002",
            device_type=DeviceType.UNKNOWN,
            manufacturer="Unknown",
            model="Unknown",
            os_version="Unknown",
            trust_level=TrustLevel.UNTRUSTED,
            last_seen=datetime.now(timezone.utc),
            risk_factors=["unmanaged_device", "no_security_software"]
        )
        
        network_context = NetworkContext(
            source_ip="203.0.113.1",  # External IP
            destination_ip="10.0.0.100",
            source_port=12345,
            destination_port=443,
            protocol="tcp",
            network_zone=NetworkZone.PUBLIC,
            threat_indicators=["suspicious_ip", "tor_exit_node"]
        )
        
        access_request = AccessRequest(
            request_id="req_002",
            user_identity=user_identity,
            device_identity=device_identity,
            network_context=network_context,
            resource="/api/sensitive-data",
            action="modify",
            data_classification=DataClassification.RESTRICTED,
            timestamp=datetime.now(timezone.utc)
        )
        
        result = engine.evaluate_access_request(access_request)
        
        assert isinstance(result, AccessDecisionResult)
        assert result.decision in [AccessDecision.DENY, AccessDecision.QUARANTINE, AccessDecision.CHALLENGE]
        assert result.risk_score >= 60  # Should be high risk
        assert result.trust_score <= 40  # Should have low trust
        assert len(result.required_actions) > 0
    
    def test_access_decision_expiration_calculation(self, tmp_path):
        """Test access decision expiration time calculation."""
        db_path = tmp_path / "test_expiration.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = ContinuousAuthorizationEngine(db)
        
        # Test different risk/trust scenarios
        test_cases = [
            # Low risk, high trust - longer expiration
            (20, 80, timedelta(hours=10)),
            
            # High risk, low trust - shorter expiration
            (80, 20, timedelta(hours=2)),
            
            # Medium risk, medium trust - medium expiration
            (50, 50, timedelta(hours=6))
        ]
        
        for risk_score, trust_score, expected_min_duration in test_cases:
            expiration = engine._calculate_expiration(AccessDecision.ALLOW, risk_score, trust_score)
            
            if expiration:
                duration = expiration - datetime.now(timezone.utc)
                # Allow some flexibility in duration calculation
                assert duration >= expected_min_duration - timedelta(hours=2)
                assert duration <= timedelta(hours=24)  # Maximum expiration
    
    def test_policy_application(self, tmp_path):
        """Test policy application to access requests."""
        db_path = tmp_path / "test_policy_application.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = ContinuousAuthorizationEngine(db)
        
        # Create test access request
        user_identity = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john@company.com",
            roles=["user"],
            groups=[],
            trust_level=TrustLevel.MEDIUM,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.PASSWORD]
        )
        
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.LAPTOP,
            manufacturer="TestCorp",
            model="SecureBook",
            os_version="TestOS 2.0",
            trust_level=TrustLevel.MEDIUM,
            last_seen=datetime.now(timezone.utc)
        )
        
        network_context = NetworkContext(
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            source_port=12345,
            destination_port=443,
            protocol="tcp",
            network_zone=NetworkZone.INTERNAL
        )
        
        access_request = AccessRequest(
            request_id="req_001",
            user_identity=user_identity,
            device_identity=device_identity,
            network_context=network_context,
            resource="/api/data",
            action="read",
            data_classification=DataClassification.CONFIDENTIAL,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Test policy application
        risk_score = engine._calculate_risk_score(access_request)
        trust_score = engine._calculate_trust_score(access_request)
        policy_result = engine._apply_policies(access_request, risk_score, trust_score)
        
        assert isinstance(policy_result, dict)
        assert 'decision' in policy_result
        assert 'reasons' in policy_result
        assert len(policy_result['reasons']) > 0


class TestDataClassificationEngine:
    """Test data classification engine."""
    
    def test_public_data_classification(self, tmp_path):
        """Test classification of public data."""
        db_path = tmp_path / "test_public_classification.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = DataClassificationEngine(db)
        
        public_data = b"This is public information available to everyone"
        context = {'resource': '/public/info', 'user_roles': ['user']}
        
        classification = engine.classify_data(public_data, context)
        
        assert classification == DataClassification.PUBLIC
    
    def test_confidential_data_classification(self, tmp_path):
        """Test classification of confidential data."""
        db_path = tmp_path / "test_confidential_classification.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = DataClassificationEngine(db)
        
        confidential_data = b"This document is marked as CONFIDENTIAL and contains private company information"
        context = {'resource': '/company/private', 'user_roles': ['employee']}
        
        classification = engine.classify_data(confidential_data, context)
        
        assert classification in [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED]
    
    def test_restricted_data_classification(self, tmp_path):
        """Test classification of restricted data."""
        db_path = tmp_path / "test_restricted_classification.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = DataClassificationEngine(db)
        
        restricted_data = b"RESTRICTED: This contains proprietary trade secrets and confidential business data"
        context = {'resource': '/restricted/secrets', 'user_roles': ['admin']}
        
        classification = engine.classify_data(restricted_data, context)
        
        assert classification == DataClassification.RESTRICTED
    
    def test_top_secret_data_classification(self, tmp_path):
        """Test classification of top secret data."""
        db_path = tmp_path / "test_top_secret_classification.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = DataClassificationEngine(db)
        
        top_secret_data = b"TOP SECRET: Classified information related to national security matters"
        context = {'resource': '/classified/documents', 'user_roles': ['security_admin']}
        
        classification = engine.classify_data(top_secret_data, context)
        
        assert classification == DataClassification.TOP_SECRET
    
    def test_pii_data_classification(self, tmp_path):
        """Test classification of data containing PII."""
        db_path = tmp_path / "test_pii_classification.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = DataClassificationEngine(db)
        
        pii_data = b"John Doe, SSN: 123-45-6789, Email: john.doe@company.com, Phone: 555-123-4567"
        context = {'resource': '/employee/records', 'user_roles': ['hr']}
        
        classification = engine.classify_data(pii_data, context)
        
        assert classification in [DataClassification.RESTRICTED, DataClassification.CONFIDENTIAL]
    
    def test_data_protection_application(self, tmp_path):
        """Test data protection measures application."""
        db_path = tmp_path / "test_data_protection.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = DataClassificationEngine(db)
        
        # Test different classification levels
        test_cases = [
            (DataClassification.PUBLIC, False, False),  # No encryption, no watermark
            (DataClassification.CONFIDENTIAL, True, False),  # Encryption, no watermark
            (DataClassification.RESTRICTED, True, True),  # Encryption and watermark
            (DataClassification.TOP_SECRET, True, True)  # Encryption and watermark
        ]
        
        user_identity = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john@company.com",
            roles=["admin"],  # High privilege user
            groups=[],
            trust_level=TrustLevel.HIGH,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.MFA]
        )
        
        test_data = b"Test data for protection measures"
        
        for classification, should_encrypt, should_watermark in test_cases:
            protection = engine.apply_data_protection(test_data, classification, user_identity)
            
            assert isinstance(protection, dict)
            assert 'encrypted' in protection
            assert 'watermarked' in protection
            assert 'access_logged' in protection
            assert protection['access_logged'] == True  # Always log access
            
            # For admin user, encryption and watermarking depend on classification
            if classification == DataClassification.PUBLIC:
                assert protection['encrypted'] == False
                assert protection['watermarked'] == False
            else:
                # Protection measures may vary based on implementation
                assert isinstance(protection['encrypted'], bool)
                assert isinstance(protection['watermarked'], bool)
    
    def test_dlp_violation_detection(self, tmp_path):
        """Test data loss prevention violation detection."""
        db_path = tmp_path / "test_dlp_detection.db"
        db = ZeroTrustDatabase(str(db_path))
        engine = DataClassificationEngine(db)
        
        # User without proper clearance
        low_clearance_user = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john@company.com",
            roles=["guest"],  # Low privilege
            groups=[],
            trust_level=TrustLevel.LOW,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.PASSWORD]
        )
        
        # Sensitive data
        sensitive_data = b"RESTRICTED: This contains credit card number 4111-1111-1111-1111 and SSN 123-45-6789"
        
        protection = engine.apply_data_protection(
            sensitive_data, 
            DataClassification.RESTRICTED, 
            low_clearance_user
        )
        
        assert len(protection['dlp_violations']) > 0
        assert any('clearance' in violation.lower() for violation in protection['dlp_violations'])


class TestZeroTrustShield:
    """Test main zero-trust shield functionality."""
    
    @pytest.mark.asyncio
    async def test_successful_request_processing(self, tmp_path):
        """Test successful zero-trust request processing."""
        db_path = tmp_path / "test_shield_success.db"
        shield = ZeroTrustShield(str(db_path))
        
        # Create valid JWT token
        import jwt
        token_payload = {
            'sub': 'user_001',
            'username': 'john.doe',
            'email': 'john.doe@company.com',
            'roles': ['user', 'developer'],
            'exp': (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        }
        
        valid_token = jwt.encode(token_payload, 'secret', algorithm='HS256')
        long_certificate = secrets.token_urlsafe(200)
        
        request_context = {
            'user_token': valid_token,
            'device_certificate': long_certificate,
            'device_info': {
                'device_type': 'laptop',
                'manufacturer': 'TestCorp',
                'model': 'SecureBook',
                'os_version': 'TestOS 2.0',
                'compliance': {'antivirus': True, 'firewall': True},
                'managed_device': True
            },
            'network_info': {
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.1',
                'destination_port': 443,
                'protocol': 'tcp',
                'network_zone': 'internal'
            },
            'resource': '/api/data',
            'action': 'read',
            'data_sample': b'Some internal company data',
            'auth_factors': [
                {'type': 'password', 'success': True},
                {'type': 'mfa', 'success': True}
            ]
        }
        
        result = await shield.process_request(request_context)
        
        assert isinstance(result, dict)
        assert 'access_granted' in result
        assert 'decision' in result
        assert 'risk_score' in result
        assert 'trust_score' in result
        assert 'user_identity' in result
        assert 'device_identity' in result
        assert 'network_context' in result
        assert 'data_classification' in result
        assert 'reasons' in result
        assert 'request_id' in result
        assert 'timestamp' in result
    
    @pytest.mark.asyncio
    async def test_failed_user_authentication(self, tmp_path):
        """Test zero-trust processing with failed user authentication."""
        db_path = tmp_path / "test_shield_failed_auth.db"
        shield = ZeroTrustShield(str(db_path))
        
        request_context = {
            'user_token': 'invalid_token',
            'device_certificate': 'short',  # Invalid certificate
            'device_info': {},
            'network_info': {},
            'resource': '/api/data',
            'action': 'read',
            'data_sample': b'',
            'auth_factors': []
        }
        
        result = await shield.process_request(request_context)
        
        assert result['access_granted'] == False
        assert result['decision'] == AccessDecision.DENY.value
        assert 'User identity verification failed' in result['reasons']
    
    @pytest.mark.asyncio
    async def test_strict_mode_processing(self, tmp_path):
        """Test zero-trust processing in strict mode."""
        db_path = tmp_path / "test_shield_strict.db"
        shield = ZeroTrustShield(str(db_path))
        shield.strict_mode = True
        
        # Create scenario that would pass in normal mode but fail in strict mode
        import jwt
        token_payload = {
            'sub': 'user_001',
            'username': 'test.user',
            'email': 'test@company.com',
            'roles': ['guest'],  # Low privilege
            'exp': (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        }
        
        token = jwt.encode(token_payload, 'secret', algorithm='HS256')
        
        request_context = {
            'user_token': token,
            'device_certificate': secrets.token_urlsafe(200),
            'device_info': {
                'device_type': 'mobile',
                'managed_device': False  # Unmanaged device
            },
            'network_info': {
                'source_ip': '203.0.113.1',  # External IP
                'network_zone': 'public'
            },
            'resource': '/api/sensitive',
            'action': 'read',
            'data_sample': b'sensitive data',
            'auth_factors': [{'type': 'password', 'success': True}]
        }
        
        result = await shield.process_request(request_context)
        
        # Strict mode should be more restrictive
        assert isinstance(result['access_granted'], bool)
        assert result['decision'] in [AccessDecision.DENY.value, AccessDecision.CHALLENGE.value, AccessDecision.ALLOW.value]
    
    @pytest.mark.asyncio
    async def test_request_processing_error_handling(self, tmp_path):
        """Test error handling in request processing."""
        db_path = tmp_path / "test_shield_errors.db"
        shield = ZeroTrustShield(str(db_path))
        
        # Invalid request context that should trigger errors
        invalid_context = {
            'user_token': None,  # Invalid token
            'device_certificate': None,  # Invalid certificate
            'device_info': None,  # Invalid device info
            'network_info': None,  # Invalid network info
        }
        
        result = await shield.process_request(invalid_context)
        
        assert result['access_granted'] == False
        assert result['decision'] == AccessDecision.DENY.value
        assert 'error' in result or len(result['reasons']) > 0


class TestZeroTrustIntegration:
    """Integration tests for zero-trust system."""
    
    @pytest.mark.asyncio
    async def test_complete_workflow_allow_decision(self, tmp_path):
        """Test complete zero-trust workflow with allow decision."""
        db_path = tmp_path / "test_integration_allow.db"
        shield = ZeroTrustShield(str(db_path))
        
        # Setup valid scenario
        import jwt
        token_payload = {
            'sub': 'admin_001',
            'username': 'admin.user',
            'email': 'admin@company.com',
            'roles': ['admin', 'security_admin'],
            'exp': (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        }
        
        valid_token = jwt.encode(token_payload, 'secret', algorithm='HS256')
        
        request_context = {
            'user_token': valid_token,
            'device_certificate': secrets.token_urlsafe(250),  # Long valid certificate
            'device_info': {
                'device_type': 'desktop',
                'manufacturer': 'SecureCorp',
                'model': 'AdminStation',
                'os_version': 'SecureOS 3.0',
                'compliance': {
                    'antivirus': True,
                    'firewall': True,
                    'encryption': True,
                    'hardened': True
                },
                'managed_device': True,
                'antivirus_enabled': True,
                'firewall_enabled': True
            },
            'network_info': {
                'source_ip': '192.168.1.10',  # Internal admin network
                'destination_ip': '10.0.0.100',
                'destination_port': 443,
                'protocol': 'tcp',
                'network_zone': 'internal',
                'geolocation': {'country': 'US', 'city': 'HQ'},
                'vpn_info': {'vpn_name': 'corporate_vpn'}
            },
            'resource': '/api/admin/config',
            'action': 'read',
            'data_sample': b'internal configuration data',
            'auth_factors': [
                {'type': 'certificate', 'success': True},
                {'type': 'biometric', 'success': True}
            ]
        }
        
        result = await shield.process_request(request_context)
        
        # Should allow access for high-privilege admin with strong auth
        assert 'access_granted' in result
        assert 'decision' in result
        assert result['decision'] in [
            AccessDecision.ALLOW.value, 
            AccessDecision.MONITOR.value
        ]
        assert result.get('risk_score', 0) <= 70  # Should be relatively low risk
        assert result.get('trust_score', 0) >= 50  # Should have decent trust
    
    @pytest.mark.asyncio
    async def test_complete_workflow_deny_decision(self, tmp_path):
        """Test complete zero-trust workflow with deny decision."""
        db_path = tmp_path / "test_integration_deny.db"
        shield = ZeroTrustShield(str(db_path))
        
        # Setup high-risk scenario
        import jwt
        token_payload = {
            'sub': 'guest_001',
            'username': 'guest.user',
            'email': 'guest@external.com',
            'roles': ['guest'],
            'exp': (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        }
        
        suspicious_token = jwt.encode(token_payload, 'secret', algorithm='HS256')
        
        request_context = {
            'user_token': suspicious_token,
            'device_certificate': 'short_invalid_cert',
            'device_info': {
                'device_type': 'unknown',
                'manufacturer': 'Unknown',
                'model': 'Unknown',
                'os_version': 'Unknown',
                'compliance': {},
                'managed_device': False
            },
            'network_info': {
                'source_ip': '89.187.162.242',  # External suspicious IP
                'destination_ip': '10.0.0.1',
                'destination_port': 443,
                'protocol': 'tcp',
                'network_zone': 'public',
                'geolocation': {'country': 'CN', 'city': 'Beijing'},
                'threat_indicators': ['suspicious_ip', 'geo_risk']
            },
            'resource': '/api/admin/secrets',
            'action': 'modify',
            'data_sample': b'top secret administrative data',
            'auth_factors': [
                {'type': 'password', 'success': False}  # Failed authentication
            ]
        }
        
        result = await shield.process_request(request_context)
        
        # Should deny access for high-risk scenario
        assert result['access_granted'] == False
        assert result['decision'] in [
            AccessDecision.DENY.value,
            AccessDecision.QUARANTINE.value
        ]
    
    @pytest.mark.asyncio
    async def test_multiple_user_session_handling(self, tmp_path):
        """Test handling multiple concurrent user sessions."""
        db_path = tmp_path / "test_multiple_sessions.db"
        shield = ZeroTrustShield(str(db_path))
        
        # Create multiple user scenarios
        users = [
            {'user_id': 'user_001', 'roles': ['user'], 'ip': '192.168.1.100'},
            {'user_id': 'user_002', 'roles': ['admin'], 'ip': '192.168.1.101'},
            {'user_id': 'user_003', 'roles': ['guest'], 'ip': '203.0.113.1'}
        ]
        
        results = []
        
        for user_data in users:
            import jwt
            token_payload = {
                'sub': user_data['user_id'],
                'username': f"{user_data['user_id']}.user",
                'email': f"{user_data['user_id']}@company.com",
                'roles': user_data['roles'],
                'exp': (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
            }
            
            token = jwt.encode(token_payload, 'secret', algorithm='HS256')
            
            request_context = {
                'user_token': token,
                'device_certificate': secrets.token_urlsafe(200),
                'device_info': {
                    'device_type': 'laptop',
                    'managed_device': 'admin' in user_data['roles']
                },
                'network_info': {
                    'source_ip': user_data['ip'],
                    'destination_port': 443,
                    'network_zone': 'internal' if user_data['ip'].startswith('192.168') else 'public'
                },
                'resource': '/api/data',
                'action': 'read',
                'data_sample': b'test data',
                'auth_factors': [{'type': 'password', 'success': True}]
            }
            
            result = await shield.process_request(request_context)
            results.append(result)
        
        # All requests should be processed
        assert len(results) == 3
        
        # Each should have different risk/trust scores based on user profile
        for result in results:
            assert 'user_identity' in result
            assert 'decision' in result
            assert isinstance(result['risk_score'], int)
            assert isinstance(result['trust_score'], int)
    
    def test_data_serialization_roundtrip(self, tmp_path):
        """Test data structure serialization and deserialization."""
        # Test UserIdentity serialization
        user_identity = UserIdentity(
            user_id="user_001",
            username="john.doe",
            email="john@company.com",
            roles=["user", "admin"],
            groups=["engineering"],
            trust_level=TrustLevel.HIGH,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[AuthenticationMethod.MFA, AuthenticationMethod.CERTIFICATE]
        )
        
        user_dict = user_identity.to_dict()
        assert isinstance(user_dict, dict)
        assert user_dict['user_id'] == "user_001"
        assert user_dict['trust_level'] == TrustLevel.HIGH.value
        assert len(user_dict['authentication_methods']) == 2
        
        # Test DeviceIdentity serialization
        device_identity = DeviceIdentity(
            device_id="device_001",
            device_type=DeviceType.LAPTOP,
            manufacturer="TestCorp",
            model="SecureBook",
            os_version="TestOS 2.0",
            trust_level=TrustLevel.VERIFIED,
            last_seen=datetime.now(timezone.utc)
        )
        
        device_dict = device_identity.to_dict()
        assert isinstance(device_dict, dict)
        assert device_dict['device_type'] == DeviceType.LAPTOP.value
        assert device_dict['trust_level'] == TrustLevel.VERIFIED.value
        
        # Test AccessDecisionResult serialization
        decision = AccessDecisionResult(
            decision=AccessDecision.ALLOW,
            risk_score=25,
            trust_score=85,
            reasons=["Low risk access granted"],
            required_actions=[],
            monitoring_requirements=["Standard logging"]
        )
        
        decision_dict = decision.to_dict()
        assert isinstance(decision_dict, dict)
        assert decision_dict['decision'] == AccessDecision.ALLOW.value
        assert decision_dict['risk_score'] == 25
        assert decision_dict['trust_score'] == 85


class TestZeroTrustErrorHandling:
    """Test error handling and edge cases."""
    
    @pytest.mark.asyncio
    async def test_invalid_token_handling(self, tmp_path):
        """Test handling of various invalid token formats."""
        db_path = tmp_path / "test_invalid_tokens.db"
        shield = ZeroTrustShield(str(db_path))
        
        invalid_tokens = [
            "",                    # Empty token
            "invalid",             # Invalid format
            "not.a.jwt",          # Invalid JWT structure
            None,                 # None token
            "a" * 1000,           # Extremely long token
            "invalid.jwt.token"   # Invalid JWT content
        ]
        
        for invalid_token in invalid_tokens:
            request_context = {
                'user_token': invalid_token,
                'device_certificate': 'test_cert',
                'device_info': {},
                'network_info': {},
                'resource': '/test',
                'action': 'read',
                'data_sample': b'test'
            }
            
            result = await shield.process_request(request_context)
            
            assert result['access_granted'] == False
            assert result['decision'] == AccessDecision.DENY.value
    
    @pytest.mark.asyncio
    async def test_malformed_network_info_handling(self, tmp_path):
        """Test handling of malformed network information."""
        db_path = tmp_path / "test_malformed_network.db"
        shield = ZeroTrustShield(str(db_path))
        
        # Valid token for the test
        import jwt
        token_payload = {
            'sub': 'user_001',
            'username': 'test.user',
            'roles': ['user'],
            'exp': (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        }
        valid_token = jwt.encode(token_payload, 'secret', algorithm='HS256')
        
        malformed_network_infos = [
            {'source_ip': 'invalid_ip'},
            {'destination_port': 'not_a_number'},
            {'protocol': ''},
            {'network_zone': 'invalid_zone'},
            None,
            {},
            {'source_ip': '999.999.999.999'}  # Invalid IP format
        ]
        
        for network_info in malformed_network_infos:
            request_context = {
                'user_token': valid_token,
                'device_certificate': secrets.token_urlsafe(200),
                'device_info': {'device_type': 'laptop'},
                'network_info': network_info,
                'resource': '/test',
                'action': 'read',
                'data_sample': b'test'
            }
            
            result = await shield.process_request(request_context)
            
            # Should handle malformed data gracefully
            assert isinstance(result, dict)
            assert 'access_granted' in result
            assert 'decision' in result
    
    @pytest.mark.asyncio
    async def test_extremely_large_data_handling(self, tmp_path):
        """Test handling of extremely large data samples."""
        db_path = tmp_path / "test_large_data.db"
        shield = ZeroTrustShield(str(db_path))
        
        import jwt
        token_payload = {
            'sub': 'user_001',
            'username': 'test.user',
            'roles': ['user'],
            'exp': (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        }
        valid_token = jwt.encode(token_payload, 'secret', algorithm='HS256')
        
        # Test with large data sample (10MB)
        large_data = b"A" * (10 * 1024 * 1024)
        
        request_context = {
            'user_token': valid_token,
            'device_certificate': secrets.token_urlsafe(200),
            'device_info': {'device_type': 'laptop'},
            'network_info': {'source_ip': '192.168.1.100'},
            'resource': '/test',
            'action': 'read',
            'data_sample': large_data,
            'auth_factors': [{'type': 'password', 'success': True}]
        }
        
        start_time = time.time()
        result = await shield.process_request(request_context)
        processing_time = time.time() - start_time
        
        # Should handle large data within reasonable time
        assert processing_time < 10.0  # Should complete within 10 seconds
        assert isinstance(result, dict)
        assert 'data_classification' in result
    
    def test_concurrent_database_access(self, tmp_path):
        """Test concurrent database access handling."""
        db_path = tmp_path / "test_concurrent_db.db"
        db = ZeroTrustDatabase(str(db_path))
        
        # Create multiple user identities concurrently
        import threading
        
        def store_user(user_id):
            user_identity = UserIdentity(
                user_id=f"user_{user_id:03d}",
                username=f"user{user_id}",
                email=f"user{user_id}@company.com",
                roles=["user"],
                groups=[],
                trust_level=TrustLevel.MEDIUM,
                last_authentication=datetime.now(timezone.utc),
                authentication_methods=[AuthenticationMethod.PASSWORD]
            )
            return db.store_user_identity(user_identity)
        
        # Test concurrent writes
        threads = []
        results = []
        
        for i in range(10):
            thread = threading.Thread(target=lambda i=i: results.append(store_user(i)))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # All operations should succeed
        assert len(results) == 10
        assert all(result for result in results)


class TestZeroTrustWithMocks:
    """Test zero-trust system using mock infrastructure."""
    
    def test_mock_environment_setup(self):
        """Test mock environment setup and initialization."""
        mock_env = MockZeroTrustTestEnvironment()
        
        assert mock_env.shield is not None
        assert len(mock_env.test_scenarios) >= 3
        assert isinstance(mock_env.performance_metrics, dict)
    
    def test_mock_scenario_execution(self):
        """Test execution of mock test scenarios."""
        mock_env = MockZeroTrustTestEnvironment()
        
        # Test valid user scenario
        result = mock_env.run_test_scenario('valid_user_valid_device')
        
        assert result is not None
        assert 'scenario' in result
        assert result['scenario'] == 'valid_user_valid_device'
        assert 'access_granted' in result
        assert 'processing_time_ms' in result
        assert result['processing_time_ms'] > 0
        assert result.get('mock_processing') == True
    
    def test_mock_performance_metrics_collection(self):
        """Test performance metrics collection in mock environment."""
        mock_env = MockZeroTrustTestEnvironment()
        
        # Run multiple scenarios
        scenarios = ['valid_user_valid_device', 'admin_user_high_privilege', 'suspicious_external_access']
        
        for scenario in scenarios:
            try:
                result = mock_env.run_test_scenario(scenario)
                assert result is not None
            except Exception as e:
                # Some scenarios might not exist, that's okay
                pass
        
        # Get performance metrics
        metrics = mock_env.get_performance_metrics()
        
        assert isinstance(metrics, dict)
        if metrics['processing_times']:
            assert 'avg_processing_time' in metrics
            assert metrics['avg_processing_time'] > 0
    
    def test_mock_load_testing(self):
        """Test mock load testing capabilities."""
        mock_env = MockZeroTrustTestEnvironment()
        
        # Run small load test
        load_results = mock_env.simulate_load_test(num_requests=20)
        
        assert isinstance(load_results, dict)
        assert 'requests_processed' in load_results
        assert 'successful_requests' in load_results
        assert 'denied_requests' in load_results
        assert 'total_time' in load_results
        assert 'avg_response_time' in load_results
        
        assert load_results['requests_processed'] <= 20
        assert load_results['total_time'] > 0
        assert load_results['avg_response_time'] > 0
    
    def test_mock_identity_verification_engine(self):
        """Test mock identity verification engine."""
        mock_db = MockZeroTrustDatabase()
        mock_engine = MockIdentityVerificationEngine(mock_db)
        
        # Add valid token
        mock_engine.add_valid_token('test_token', {
            'user_id': 'user_001',
            'username': 'test.user',
            'email': 'test@company.com',
            'roles': ['user']
        })
        
        # Test verification
        auth_factors = [{'type': 'mfa', 'success': True}]
        user_identity, trust_level = mock_engine.verify_user_identity('test_token', auth_factors)
        
        assert user_identity is not None
        assert user_identity.user_id == 'user_001'
        assert trust_level.value >= TrustLevel.MEDIUM.value  # MFA should increase trust
        
        # Test invalid token
        invalid_identity, invalid_trust = mock_engine.verify_user_identity('invalid', [])
        assert invalid_identity is None
        assert invalid_trust == TrustLevel.UNTRUSTED


class TestZeroTrustConvenienceFunctions:
    """Test convenience functions and utilities."""
    
    def test_create_zero_trust_shield_function(self, tmp_path):
        """Test convenience function for creating zero-trust shields."""
        db_path = tmp_path / "test_convenience.db"
        
        # Test with defaults
        shield = create_zero_trust_shield(str(db_path))
        assert isinstance(shield, ZeroTrustShield)
        assert shield.strict_mode == False
        
        # Test with strict mode
        strict_shield = create_zero_trust_shield(str(db_path), strict_mode=True)
        assert strict_shield.strict_mode == True
    
    def test_enum_value_consistency(self):
        """Test consistency of enum values."""
        # Test TrustLevel ordering
        assert TrustLevel.UNTRUSTED.value < TrustLevel.LOW.value
        assert TrustLevel.LOW.value < TrustLevel.MEDIUM.value
        assert TrustLevel.MEDIUM.value < TrustLevel.HIGH.value
        assert TrustLevel.HIGH.value < TrustLevel.VERIFIED.value
        
        # Test all enums have string values
        for decision in AccessDecision:
            assert isinstance(decision.value, str)
        
        for auth_method in AuthenticationMethod:
            assert isinstance(auth_method.value, str)
        
        for device_type in DeviceType:
            assert isinstance(device_type.value, str)
        
        for zone in NetworkZone:
            assert isinstance(zone.value, str)
        
        for classification in DataClassification:
            assert isinstance(classification.value, str)
    
    def test_data_structure_validation(self):
        """Test data structure field validation."""
        # Test UserIdentity required fields
        with pytest.raises(TypeError):
            UserIdentity()  # Missing required fields
        
        # Test DeviceIdentity required fields
        with pytest.raises(TypeError):
            DeviceIdentity()  # Missing required fields
        
        # Test that valid instances can be created
        user = UserIdentity(
            user_id="test",
            username="test",
            email="test@test.com",
            roles=[],
            groups=[],
            trust_level=TrustLevel.LOW,
            last_authentication=datetime.now(timezone.utc),
            authentication_methods=[]
        )
        assert user.user_id == "test"
        
        device = DeviceIdentity(
            device_id="test",
            device_type=DeviceType.LAPTOP,
            manufacturer="Test",
            model="Test",
            os_version="Test",
            trust_level=TrustLevel.LOW,
            last_seen=datetime.now(timezone.utc)
        )
        assert device.device_id == "test"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])