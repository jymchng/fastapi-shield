"""Comprehensive tests for compliance framework functionality.

This test suite covers all aspects of the compliance framework including:
- GDPR, HIPAA, and PCI-DSS compliance validation
- Audit trail generation and integrity verification
- Policy enforcement and data privacy controls
- Compliance reporting and dashboard functionality
- Real-time compliance monitoring and violation detection
- Performance and scalability testing
- Integration scenarios and edge cases
"""

import asyncio
import json
import time
import pytest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield.compliance_framework import (
    # Core classes
    ComplianceFramework,
    AuditTrailManager,
    PolicyEnforcementEngine,
    ComplianceDashboard,
    ComplianceMiddleware,
    
    # Validators
    GDPRValidator,
    HIPAAValidator,
    PCIDSSValidator,
    
    # Data classes
    ComplianceRule,
    AuditEvent,
    ComplianceViolation,
    DataPrivacyPolicy,
    ComplianceMetrics,
    
    # Enums
    ComplianceRegulation,
    ComplianceStatus,
    AuditEventType,
    DataCategory,
    PrivacyAction,
    ComplianceSeverity,
    
    # Convenience functions and decorators
    create_compliance_framework,
    compliance_required,
    gdpr_compliant,
    hipaa_compliant,
    pci_compliant,
)

from tests.mocks.mock_compliance_infrastructure import (
    MockComplianceTestEnvironment,
    MockComplianceTestConfig,
    MockRequestData,
    MockComplianceDatabase,
    MockRegulationChecker,
    MockDataClassifier,
    MockAuditLogger,
    MockPrivacyProcessor,
    create_sample_audit_event,
    create_sample_violation,
    create_sample_privacy_policy,
    generate_test_dataset,
    mock_compliance_environment
)


class TestComplianceRegulations:
    """Test individual compliance regulation implementations."""
    
    def test_compliance_regulation_enum_values(self):
        """Test compliance regulation enum contains expected values."""
        expected_regulations = ['gdpr', 'hipaa', 'pci_dss', 'sox', 'ccpa', 'iso_27001', 'nist', 'custom']
        
        actual_regulations = [reg.value for reg in ComplianceRegulation]
        
        for expected in expected_regulations:
            assert expected in actual_regulations
        
        assert len(actual_regulations) >= len(expected_regulations)
    
    def test_compliance_status_enum(self):
        """Test compliance status enum values."""
        expected_statuses = ['compliant', 'non_compliant', 'warning', 'unknown', 'exempt']
        actual_statuses = [status.value for status in ComplianceStatus]
        
        for expected in expected_statuses:
            assert expected in actual_statuses


class TestDataStructures:
    """Test compliance data structures and their functionality."""
    
    def test_audit_event_creation_and_integrity(self):
        """Test audit event creation and integrity verification."""
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.DATA_ACCESS,
            regulation=ComplianceRegulation.GDPR,
            user_id="test_user",
            client_ip="192.168.1.100",
            resource="/api/test",
            action="read",
            outcome="success",
            details={"test": "data"},
            data_categories=[DataCategory.PII],
            compliance_status=ComplianceStatus.COMPLIANT
        )
        
        # Test automatic checksum generation
        assert event.checksum is not None
        assert len(event.checksum) == 64  # SHA-256 hex length
        
        # Test integrity verification
        assert event.verify_integrity() is True
        
        # Test integrity failure on tampering
        original_checksum = event.checksum
        event.details["tampered"] = "true"
        event.checksum = original_checksum  # Keep old checksum
        assert event.verify_integrity() is False
    
    def test_compliance_rule_structure(self):
        """Test compliance rule data structure."""
        rule = ComplianceRule(
            id="test_rule",
            regulation=ComplianceRegulation.GDPR,
            name="Test Rule",
            description="Test compliance rule",
            requirement="Test requirement",
            category="test",
            severity=ComplianceSeverity.HIGH,
            data_categories=[DataCategory.PII],
            remediation_steps=["Step 1", "Step 2"],
            references=["Ref 1"],
            tags=["test", "gdpr"]
        )
        
        assert rule.id == "test_rule"
        assert rule.regulation == ComplianceRegulation.GDPR
        assert rule.severity == ComplianceSeverity.HIGH
        assert len(rule.remediation_steps) == 2
        assert rule.is_enabled is True  # Default value
    
    def test_compliance_violation_structure(self):
        """Test compliance violation data structure."""
        violation = ComplianceViolation(
            id=str(uuid.uuid4()),
            rule_id="test_rule",
            regulation=ComplianceRegulation.HIPAA,
            severity=ComplianceSeverity.CRITICAL,
            timestamp=datetime.now(timezone.utc),
            resource="/api/patients",
            violation_details="PHI accessed without authorization",
            affected_data_categories=[DataCategory.PHI],
            remediation_required=True,
            remediation_steps=["Fix authorization", "Update logs"]
        )
        
        assert violation.regulation == ComplianceRegulation.HIPAA
        assert violation.severity == ComplianceSeverity.CRITICAL
        assert violation.remediation_required is True
        assert violation.auto_remediated is False  # Default value
    
    def test_data_privacy_policy_structure(self):
        """Test data privacy policy structure."""
        policy = DataPrivacyPolicy(
            id="test_policy",
            name="Test Privacy Policy",
            regulation=ComplianceRegulation.PCI_DSS,
            data_category=DataCategory.PCI,
            privacy_actions=[PrivacyAction.ENCRYPT, PrivacyAction.LOG_ACCESS],
            retention_period=timedelta(days=365),
            access_restrictions={"role": "authorized"},
            consent_required=True,
            anonymization_rules={"card_number": "redact"}
        )
        
        assert policy.regulation == ComplianceRegulation.PCI_DSS
        assert policy.data_category == DataCategory.PCI
        assert len(policy.privacy_actions) == 2
        assert policy.retention_period == timedelta(days=365)
        assert policy.is_active is True  # Default value
    
    def test_compliance_metrics_calculations(self):
        """Test compliance metrics calculations."""
        metrics = ComplianceMetrics(
            total_requests_evaluated=1000,
            compliant_requests=850,
            non_compliant_requests=150,
            policy_violations=25
        )
        
        assert metrics.compliance_rate == 0.85
        assert metrics.violation_rate == 0.025
        
        # Test edge case with zero requests
        empty_metrics = ComplianceMetrics()
        assert empty_metrics.compliance_rate == 1.0
        assert empty_metrics.violation_rate == 0.0


class TestGDPRValidator:
    """Test GDPR compliance validator."""
    
    @pytest.fixture
    def gdpr_validator(self):
        """Create GDPR validator instance."""
        return GDPRValidator()
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request with GDPR headers."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            'x-gdpr-consent': 'true',
            'x-gdpr-lawful-basis': 'consent'
        }
        mock_request.url.path = "/api/privacy"
        return mock_request
    
    def test_gdpr_validator_compliant_request(self, gdpr_validator, mock_request):
        """Test GDPR validator with compliant request."""
        data = {"email": "test@example.com", "name": "John Doe"}
        
        status = gdpr_validator.validate(mock_request, data)
        assert status == ComplianceStatus.COMPLIANT
    
    def test_gdpr_validator_missing_consent(self, gdpr_validator):
        """Test GDPR validator with missing consent."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.url.path = "/api/test"
        
        data = {"email": "test@example.com"}
        status = gdpr_validator.validate(mock_request, data)
        assert status == ComplianceStatus.NON_COMPLIANT
    
    def test_gdpr_required_actions(self, gdpr_validator, mock_request):
        """Test GDPR required privacy actions."""
        data = {"email": "test@example.com", "phone": "+1-555-123-4567"}
        
        actions = gdpr_validator.get_required_actions(mock_request, data)
        
        assert PrivacyAction.REQUIRE_CONSENT in actions
        assert PrivacyAction.LOG_ACCESS in actions
        assert PrivacyAction.APPLY_RETENTION in actions
        assert (PrivacyAction.PSEUDONYMIZE in actions or PrivacyAction.ENCRYPT in actions)
    
    def test_gdpr_pii_detection(self, gdpr_validator):
        """Test PII detection in GDPR validator."""
        # Test with PII
        pii_data = {
            "email": "user@example.com",
            "phone": "555-123-4567",
            "ssn": "123-45-6789"
        }
        assert gdpr_validator._contains_pii(pii_data) is True
        
        # Test without PII
        non_pii_data = {"product": "widget", "quantity": 5}
        assert gdpr_validator._contains_pii(non_pii_data) is False
    
    def test_gdpr_data_minimization(self, gdpr_validator):
        """Test GDPR data minimization principle."""
        # Small data set should pass
        small_data = {"name": "John", "email": "john@example.com"}
        assert gdpr_validator._implements_data_minimization(small_data) is True
        
        # Large data set should fail
        large_data = {"field_" + str(i): "value" * 100 for i in range(100)}
        assert gdpr_validator._implements_data_minimization(large_data) is False


class TestHIPAAValidator:
    """Test HIPAA compliance validator."""
    
    @pytest.fixture
    def hipaa_validator(self):
        """Create HIPAA validator instance."""
        return HIPAAValidator()
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request with HIPAA headers."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            'authorization': 'Bearer valid-healthcare-token',
            'x-audit-enabled': 'true'
        }
        mock_request.url.scheme = 'https'
        return mock_request
    
    def test_hipaa_validator_compliant_request(self, hipaa_validator, mock_request):
        """Test HIPAA validator with compliant request."""
        data = {"patient_id": "P123", "diagnosis": "Common cold"}
        
        status = hipaa_validator.validate(mock_request, data)
        assert status == ComplianceStatus.COMPLIANT
    
    def test_hipaa_validator_missing_auth(self, hipaa_validator):
        """Test HIPAA validator with missing authentication."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.url.scheme = 'https'
        
        data = {"patient_id": "P123", "medical": "sensitive data"}
        status = hipaa_validator.validate(mock_request, data)
        assert status == ComplianceStatus.NON_COMPLIANT
    
    def test_hipaa_validator_insecure_transmission(self, hipaa_validator):
        """Test HIPAA validator with insecure transmission."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {'authorization': 'Bearer token', 'x-audit-enabled': 'true'}
        mock_request.url.scheme = 'http'  # Insecure
        
        data = {"patient_id": "P123", "health": "data"}
        status = hipaa_validator.validate(mock_request, data)
        assert status == ComplianceStatus.NON_COMPLIANT
    
    def test_hipaa_required_actions(self, hipaa_validator, mock_request):
        """Test HIPAA required privacy actions."""
        data = {"patient_id": "P123", "medical_record": "sensitive PHI"}
        
        actions = hipaa_validator.get_required_actions(mock_request, data)
        
        assert PrivacyAction.ENCRYPT in actions
        assert PrivacyAction.LOG_ACCESS in actions
        assert PrivacyAction.RESTRICT_ACCESS in actions
        assert PrivacyAction.APPLY_RETENTION in actions
    
    def test_hipaa_phi_detection(self, hipaa_validator):
        """Test PHI detection in HIPAA validator."""
        # Test with PHI
        phi_data = {
            "patient": "John Doe",
            "diagnosis": "Hypertension",
            "medical_record": "12345"
        }
        assert hipaa_validator._contains_phi(phi_data) is True
        
        # Test without PHI
        non_phi_data = {"product": "software", "version": "1.0"}
        assert hipaa_validator._contains_phi(non_phi_data) is False


class TestPCIDSSValidator:
    """Test PCI-DSS compliance validator."""
    
    @pytest.fixture
    def pci_validator(self):
        """Create PCI-DSS validator instance."""
        return PCIDSSValidator()
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request with PCI headers."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            'x-pci-encryption': 'aes256',
            'x-user-role': 'authorized_user',
            'x-pci-audit': 'true'
        }
        mock_request.url.scheme = 'https'
        return mock_request
    
    def test_pci_validator_compliant_request(self, pci_validator, mock_request):
        """Test PCI-DSS validator with compliant request."""
        data = {"amount": 100.00, "currency": "USD"}  # No card data
        
        status = pci_validator.validate(mock_request, data)
        assert status == ComplianceStatus.COMPLIANT
    
    def test_pci_validator_unencrypted_card_data(self, pci_validator):
        """Test PCI-DSS validator with unencrypted card data."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.url.scheme = 'https'
        
        data = {"card_number": "4111-1111-1111-1111", "cvv": "123"}
        status = pci_validator.validate(mock_request, data)
        assert status == ComplianceStatus.NON_COMPLIANT
    
    def test_pci_validator_insecure_transmission(self, pci_validator):
        """Test PCI-DSS validator with insecure transmission."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            'x-pci-encryption': 'aes256',
            'x-user-role': 'authorized_user'
        }
        mock_request.url.scheme = 'http'  # Insecure
        
        data = {"card_number": "4111111111111111"}
        status = pci_validator.validate(mock_request, data)
        assert status == ComplianceStatus.NON_COMPLIANT
    
    def test_pci_required_actions(self, pci_validator, mock_request):
        """Test PCI-DSS required privacy actions."""
        data = {"card_number": "4111-1111-1111-1111", "cvv": "123"}
        
        actions = pci_validator.get_required_actions(mock_request, data)
        
        assert PrivacyAction.ENCRYPT in actions
        assert PrivacyAction.LOG_ACCESS in actions
        assert PrivacyAction.RESTRICT_ACCESS in actions
        assert PrivacyAction.REDACT in actions
    
    def test_pci_cardholder_data_detection(self, pci_validator):
        """Test cardholder data detection in PCI validator."""
        # Test with card data
        card_data = {
            "card_number": "4111-1111-1111-1111",
            "cvv": "123",
            "expiry": "12/25"
        }
        assert pci_validator._contains_cardholder_data(card_data) is True
        
        # Test without card data
        non_card_data = {"amount": 50.00, "merchant": "Test Store"}
        assert pci_validator._contains_cardholder_data(non_card_data) is False


class TestAuditTrailManager:
    """Test audit trail management functionality."""
    
    @pytest.fixture
    def audit_manager(self):
        """Create audit trail manager instance."""
        return AuditTrailManager(max_events=1000)
    
    def test_audit_manager_initialization(self, audit_manager):
        """Test audit manager initialization."""
        assert audit_manager.max_events == 1000
        assert len(audit_manager.audit_events) == 0
        assert len(audit_manager.event_index) == 0
        assert audit_manager.integrity_key is not None
    
    def test_record_audit_event(self, audit_manager):
        """Test recording audit events."""
        event = create_sample_audit_event()
        
        event_id = audit_manager.record_event(event)
        
        assert event_id == event.id
        assert len(audit_manager.audit_events) == 1
        assert event.id in audit_manager.event_index
        assert audit_manager.event_index[event.id] == event
    
    def test_audit_event_integrity_protection(self, audit_manager):
        """Test audit event integrity protection."""
        event = create_sample_audit_event()
        
        # Record valid event
        audit_manager.record_event(event)
        
        # Try to record tampered event
        tampered_event = create_sample_audit_event()
        tampered_event.details["tampered"] = "true"
        # Don't update checksum to simulate tampering
        
        with pytest.raises(ValueError, match="integrity verification failed"):
            audit_manager.record_event(tampered_event)
    
    def test_get_audit_events_filtering(self, audit_manager):
        """Test audit event retrieval with filtering."""
        # Create events with different attributes
        gdpr_event = create_sample_audit_event(ComplianceRegulation.GDPR)
        hipaa_event = create_sample_audit_event(ComplianceRegulation.HIPAA)
        
        hipaa_event.event_type = AuditEventType.AUTHENTICATION
        hipaa_event.user_id = "specific_user"
        
        # Record events
        audit_manager.record_event(gdpr_event)
        audit_manager.record_event(hipaa_event)
        
        # Test regulation filter
        gdpr_events = audit_manager.get_events(regulation=ComplianceRegulation.GDPR)
        assert len(gdpr_events) == 1
        assert gdpr_events[0].regulation == ComplianceRegulation.GDPR
        
        # Test event type filter
        auth_events = audit_manager.get_events(event_type=AuditEventType.AUTHENTICATION)
        assert len(auth_events) == 1
        assert auth_events[0].event_type == AuditEventType.AUTHENTICATION
        
        # Test user ID filter
        user_events = audit_manager.get_events(user_id="specific_user")
        assert len(user_events) == 1
        assert user_events[0].user_id == "specific_user"
        
        # Test time range filter
        now = datetime.now(timezone.utc)
        recent_events = audit_manager.get_events(start_time=now - timedelta(minutes=1))
        assert len(recent_events) == 2  # Both events should be recent
    
    def test_audit_trail_integrity_verification(self, audit_manager):
        """Test audit trail integrity verification."""
        # Add multiple events
        for i in range(5):
            event = create_sample_audit_event()
            event.id = f"event_{i}"
            audit_manager.record_event(event)
        
        # Verify integrity
        integrity_report = audit_manager.verify_audit_trail_integrity()
        
        assert integrity_report['total_events'] == 5
        assert integrity_report['valid_events'] == 5
        assert integrity_report['corrupted_events'] == []
        assert integrity_report['integrity_rate'] == 1.0
    
    def test_audit_trail_export(self, audit_manager):
        """Test audit trail export functionality."""
        # Add sample events
        event1 = create_sample_audit_event(ComplianceRegulation.GDPR)
        event2 = create_sample_audit_event(ComplianceRegulation.HIPAA)
        
        audit_manager.record_event(event1)
        audit_manager.record_event(event2)
        
        # Export as JSON
        exported_json = audit_manager.export_audit_trail(format='json', include_signatures=True)
        
        assert isinstance(exported_json, str)
        exported_data = json.loads(exported_json)
        assert len(exported_data) == 2
        
        # Verify exported data structure
        first_event = exported_data[0]
        assert 'id' in first_event
        assert 'timestamp' in first_event
        assert 'event_type' in first_event
        assert 'regulation' in first_event
        assert 'checksum' in first_event  # Signature included
        
        # Test export without signatures
        exported_no_sig = audit_manager.export_audit_trail(include_signatures=False)
        no_sig_data = json.loads(exported_no_sig)
        assert 'checksum' not in no_sig_data[0]


class TestPolicyEnforcementEngine:
    """Test policy enforcement engine functionality."""
    
    @pytest.fixture
    def policy_engine(self):
        """Create policy enforcement engine instance."""
        return PolicyEnforcementEngine()
    
    @pytest.fixture
    def sample_policy(self):
        """Create sample privacy policy."""
        return DataPrivacyPolicy(
            id="test_policy",
            name="Test Policy",
            regulation=ComplianceRegulation.GDPR,
            data_category=DataCategory.PII,
            privacy_actions=[PrivacyAction.ANONYMIZE, PrivacyAction.LOG_ACCESS],
            retention_period=timedelta(days=365),
            access_restrictions={"role": "user"},
            consent_required=True,
            anonymization_rules={"email": "hash", "name": "mask"}
        )
    
    def test_policy_registration(self, policy_engine, sample_policy):
        """Test privacy policy registration."""
        policy_engine.register_policy(sample_policy)
        
        assert sample_policy.id in policy_engine.policies
        assert policy_engine.policies[sample_policy.id] == sample_policy
    
    def test_policy_enforcement_anonymization(self, policy_engine, sample_policy):
        """Test policy enforcement with anonymization."""
        policy_engine.register_policy(sample_policy)
        
        mock_request = Mock(spec=Request)
        mock_request.headers = {'x-consent-pii': 'granted'}
        
        test_data = {"email": "test@example.com", "name": "John Doe", "age": 30}
        data_categories = [DataCategory.PII]
        
        processed_data = policy_engine.enforce_policies(mock_request, test_data, data_categories)
        
        # Verify anonymization was applied
        assert processed_data["email"] != test_data["email"]  # Should be hashed
        assert processed_data["name"] != test_data["name"]    # Should be masked
        assert processed_data["age"] == test_data["age"]      # Should be unchanged
        assert "_compliance_actions" in processed_data
    
    def test_policy_enforcement_consent_required(self, policy_engine, sample_policy):
        """Test policy enforcement with consent requirement."""
        policy_engine.register_policy(sample_policy)
        
        # Test without consent
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        test_data = {"email": "test@example.com"}
        data_categories = [DataCategory.PII]
        
        with pytest.raises(HTTPException) as exc_info:
            policy_engine.enforce_policies(mock_request, test_data, data_categories)
        
        assert exc_info.value.status_code == 403
        assert "consent required" in exc_info.value.detail.lower()
    
    def test_policy_enforcement_statistics(self, policy_engine, sample_policy):
        """Test policy enforcement statistics tracking."""
        policy_engine.register_policy(sample_policy)
        
        mock_request = Mock(spec=Request)
        mock_request.headers = {'x-consent-pii': 'granted'}
        
        test_data = {"email": "test@example.com", "name": "John Doe"}
        data_categories = [DataCategory.PII]
        
        # Process data to generate stats
        policy_engine.enforce_policies(mock_request, test_data, data_categories)
        
        stats = policy_engine.get_enforcement_stats()
        
        assert "gdpr_anonymize" in stats
        assert "gdpr_log_access" in stats
        assert stats["gdpr_anonymize"] >= 1
        assert stats["gdpr_log_access"] >= 1
    
    def test_custom_enforcement_rule(self, policy_engine):
        """Test custom enforcement rule registration and execution."""
        # Register custom rule
        def custom_rule(request, data, data_categories):
            if DataCategory.SENSITIVE in data_categories:
                data["custom_processed"] = True
            return data
        
        policy_engine.register_enforcement_rule(ComplianceRegulation.CUSTOM, custom_rule)
        
        mock_request = Mock(spec=Request)
        test_data = {"sensitive": "data"}
        data_categories = [DataCategory.SENSITIVE]
        
        processed_data = policy_engine.enforce_policies(mock_request, test_data, data_categories)
        
        assert processed_data["custom_processed"] is True


class TestComplianceDashboard:
    """Test compliance dashboard and reporting functionality."""
    
    @pytest.fixture
    def audit_manager(self):
        """Create audit manager for dashboard."""
        return AuditTrailManager()
    
    @pytest.fixture
    def dashboard(self, audit_manager):
        """Create compliance dashboard instance."""
        return ComplianceDashboard(audit_manager)
    
    def test_violation_recording(self, dashboard):
        """Test compliance violation recording."""
        violation = create_sample_violation()
        
        dashboard.record_violation(violation)
        
        assert violation.id in dashboard.violations
        assert dashboard.violations[violation.id] == violation
    
    def test_compliance_report_generation(self, dashboard, audit_manager):
        """Test compliance report generation."""
        # Add sample audit events
        gdpr_event = create_sample_audit_event(ComplianceRegulation.GDPR)
        hipaa_event = create_sample_audit_event(ComplianceRegulation.HIPAA)
        hipaa_event.compliance_status = ComplianceStatus.NON_COMPLIANT
        
        audit_manager.record_event(gdpr_event)
        audit_manager.record_event(hipaa_event)
        
        # Add sample violation
        violation = create_sample_violation(ComplianceRegulation.HIPAA)
        dashboard.record_violation(violation)
        
        # Generate report
        report = dashboard.generate_compliance_report()
        
        # Verify report structure
        assert 'report_generated' in report
        assert 'regulation' in report
        assert 'summary' in report
        assert 'event_breakdown' in report
        assert 'status_distribution' in report
        assert 'violation_severity' in report
        assert 'recent_violations' in report
        assert 'audit_trail_integrity' in report
        
        # Verify report content
        assert report['summary']['total_events'] == 2
        assert report['summary']['total_violations'] == 1
        assert report['summary']['compliance_rate'] == 50.0  # 1 compliant out of 2
        assert len(report['recent_violations']) == 1
    
    def test_compliance_report_filtering(self, dashboard, audit_manager):
        """Test compliance report with filtering."""
        # Add events for different regulations
        gdpr_event = create_sample_audit_event(ComplianceRegulation.GDPR)
        hipaa_event = create_sample_audit_event(ComplianceRegulation.HIPAA)
        
        audit_manager.record_event(gdpr_event)
        audit_manager.record_event(hipaa_event)
        
        # Generate filtered report
        report = dashboard.generate_compliance_report(regulation=ComplianceRegulation.GDPR)
        
        assert report['regulation'] == 'gdpr'
        assert report['summary']['total_events'] == 1
    
    def test_compliance_metrics_calculation(self, dashboard, audit_manager):
        """Test compliance metrics calculation."""
        # Add various events
        events_data = [
            (ComplianceStatus.COMPLIANT, AuditEventType.DATA_ACCESS),
            (ComplianceStatus.COMPLIANT, AuditEventType.AUTHENTICATION),
            (ComplianceStatus.NON_COMPLIANT, AuditEventType.POLICY_VIOLATION),
            (ComplianceStatus.NON_COMPLIANT, AuditEventType.DATA_ACCESS)
        ]
        
        for status, event_type in events_data:
            event = create_sample_audit_event()
            event.compliance_status = status
            event.event_type = event_type
            audit_manager.record_event(event)
        
        metrics = dashboard.get_compliance_metrics()
        
        assert metrics.total_requests_evaluated == 4
        assert metrics.compliant_requests == 2
        assert metrics.non_compliant_requests == 2
        assert metrics.policy_violations == 1
        assert metrics.compliance_rate == 0.5


class TestComplianceFramework:
    """Test main compliance framework functionality."""
    
    @pytest.fixture
    def framework(self):
        """Create compliance framework instance."""
        return ComplianceFramework(
            enabled_regulations=[
                ComplianceRegulation.GDPR,
                ComplianceRegulation.HIPAA,
                ComplianceRegulation.PCI_DSS
            ]
        )
    
    def test_framework_initialization(self, framework):
        """Test compliance framework initialization."""
        assert len(framework.enabled_regulations) == 3
        assert ComplianceRegulation.GDPR in framework.enabled_regulations
        assert ComplianceRegulation.HIPAA in framework.enabled_regulations
        assert ComplianceRegulation.PCI_DSS in framework.enabled_regulations
        
        # Verify components are initialized
        assert framework.audit_manager is not None
        assert framework.policy_engine is not None
        assert framework.dashboard is not None
        assert len(framework.validators) == 3
        assert len(framework.compliance_rules) > 0
    
    def test_framework_compliance_evaluation(self, framework):
        """Test compliance evaluation across regulations."""
        # Create mock request with GDPR-compliant headers
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            'x-gdpr-consent': 'true',
            'x-gdpr-lawful-basis': 'consent',
            'authorization': 'Bearer valid-token',
            'x-audit-enabled': 'true',
            'x-pci-encryption': 'aes256',
            'x-user-role': 'authorized_user'
        }
        mock_request.url.path = "/api/test"
        mock_request.url.scheme = "https"
        mock_request.cookies = {}
        mock_request.client.host = "192.168.1.100"
        
        data = {"email": "test@example.com"}
        data_categories = [DataCategory.PII]
        
        results = framework.evaluate_compliance(mock_request, data, data_categories)
        
        assert len(results) == 3
        assert ComplianceRegulation.GDPR in results
        assert ComplianceRegulation.HIPAA in results
        assert ComplianceRegulation.PCI_DSS in results
        
        # All should be compliant with proper headers
        for regulation, status in results.items():
            assert status in [ComplianceStatus.COMPLIANT, ComplianceStatus.NON_COMPLIANT]
    
    def test_framework_policy_enforcement(self, framework):
        """Test policy enforcement through framework."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {'x-consent-pii': 'granted'}
        
        data = {"email": "test@example.com", "name": "John Doe"}
        data_categories = [DataCategory.PII]
        
        processed_data = framework.enforce_compliance(mock_request, data, data_categories)
        
        # Data should be processed according to policies
        assert isinstance(processed_data, dict)
        # Specific transformations depend on default policies
    
    def test_framework_custom_rule_addition(self, framework):
        """Test adding custom compliance rules."""
        custom_rule = ComplianceRule(
            id="custom_test_rule",
            regulation=ComplianceRegulation.CUSTOM,
            name="Custom Test Rule",
            description="Test custom rule",
            requirement="Custom requirement",
            category="test",
            severity=ComplianceSeverity.MEDIUM,
            data_categories=[DataCategory.CONFIDENTIAL]
        )
        
        framework.add_compliance_rule(custom_rule)
        
        assert custom_rule.id in framework.compliance_rules
        assert framework.compliance_rules[custom_rule.id] == custom_rule
    
    def test_framework_audit_event_recording(self, framework):
        """Test audit event recording through framework."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {'x-user-id': 'test_user'}
        mock_request.client.host = "192.168.1.100"
        mock_request.url.path = "/api/test"
        mock_request.cookies = {}
        
        event_id = framework.record_audit_event(
            event_type=AuditEventType.DATA_ACCESS,
            regulation=ComplianceRegulation.GDPR,
            request=mock_request,
            resource="/api/test",
            action="read",
            outcome="success",
            details={"test": "data"},
            data_categories=[DataCategory.PII]
        )
        
        assert event_id is not None
        
        # Verify event was recorded
        events = framework.get_audit_events(regulation=ComplianceRegulation.GDPR)
        assert len(events) >= 1
        recorded_event = next(e for e in events if e.id == event_id)
        assert recorded_event.event_type == AuditEventType.DATA_ACCESS
    
    def test_framework_compliance_report(self, framework):
        """Test compliance report generation through framework."""
        # Record some test events first
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.client.host = "127.0.0.1"
        mock_request.url.path = "/api/test"
        mock_request.cookies = {}
        
        framework.record_audit_event(
            AuditEventType.COMPLIANCE_CHECK,
            ComplianceRegulation.GDPR,
            mock_request,
            "/api/test",
            "check",
            "passed",
            {},
            [DataCategory.PII],
            ComplianceStatus.COMPLIANT
        )
        
        report = framework.get_compliance_report()
        
        assert isinstance(report, dict)
        assert 'summary' in report
        assert 'event_breakdown' in report
        assert report['summary']['total_events'] >= 1


class TestComplianceDecorators:
    """Test compliance decorators and convenience functions."""
    
    def test_create_compliance_framework_function(self):
        """Test convenience function for creating framework."""
        regulations = [ComplianceRegulation.GDPR, ComplianceRegulation.HIPAA]
        
        framework = create_compliance_framework(
            regulations=regulations,
            audit_retention_days=1000
        )
        
        assert isinstance(framework, ComplianceFramework)
        assert framework.enabled_regulations == regulations
        assert framework.audit_retention == timedelta(days=1000)
    
    @pytest.mark.asyncio
    async def test_gdpr_compliant_decorator(self):
        """Test GDPR compliance decorator."""
        @gdpr_compliant
        async def test_endpoint(request: Request):
            return {"message": "success"}
        
        # Create compliant mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            'x-gdpr-consent': 'true',
            'x-gdpr-lawful-basis': 'consent'
        }
        mock_request.url.path = "/api/test"
        mock_request.url.scheme = "https"
        mock_request.json = AsyncMock(return_value={"email": "test@example.com"})
        mock_request.cookies = {}
        mock_request.client.host = "192.168.1.100"
        
        # Should not raise exception for compliant request
        result = await test_endpoint(mock_request)
        assert result["message"] == "success"
        
        # Test non-compliant request
        non_compliant_request = Mock(spec=Request)
        non_compliant_request.headers = {}  # No consent
        non_compliant_request.url.path = "/api/test"
        non_compliant_request.url.scheme = "https"
        non_compliant_request.json = AsyncMock(return_value={"email": "test@example.com"})
        non_compliant_request.cookies = {}
        non_compliant_request.client.host = "192.168.1.100"
        
        with pytest.raises(HTTPException) as exc_info:
            await test_endpoint(non_compliant_request)
        
        assert exc_info.value.status_code == 403
        assert "gdpr" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio 
    async def test_hipaa_compliant_decorator(self):
        """Test HIPAA compliance decorator."""
        @hipaa_compliant
        async def test_endpoint(request: Request):
            return {"message": "success"}
        
        # Create compliant mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            'authorization': 'Bearer valid-healthcare-token',
            'x-audit-enabled': 'true'
        }
        mock_request.url.path = "/api/patients"
        mock_request.url.scheme = "https"
        mock_request.json = AsyncMock(return_value={"patient_id": "P123"})
        mock_request.cookies = {}
        mock_request.client.host = "192.168.1.100"
        
        result = await test_endpoint(mock_request)
        assert result["message"] == "success"
    
    @pytest.mark.asyncio
    async def test_pci_compliant_decorator(self):
        """Test PCI-DSS compliance decorator."""
        @pci_compliant 
        async def test_endpoint(request: Request):
            return {"message": "success"}
        
        # Create compliant mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            'x-pci-encryption': 'aes256',
            'x-user-role': 'authorized_user',
            'x-pci-audit': 'true'
        }
        mock_request.url.path = "/api/payments"
        mock_request.url.scheme = "https"
        mock_request.json = AsyncMock(return_value={"amount": 100.00})
        mock_request.cookies = {}
        mock_request.client.host = "192.168.1.100"
        
        result = await test_endpoint(mock_request)
        assert result["message"] == "success"


class TestComplianceMiddleware:
    """Test compliance middleware functionality."""
    
    @pytest.fixture
    def app(self):
        """Create test FastAPI app."""
        app = FastAPI()
        
        @app.get("/api/test")
        def test_endpoint():
            return {"message": "test"}
        
        @app.post("/api/users")
        def create_user(user_data: dict):
            return {"user_id": 123}
        
        return app
    
    @pytest.fixture
    def framework(self):
        """Create framework for middleware."""
        return ComplianceFramework()
    
    def test_middleware_integration(self, app, framework):
        """Test middleware integration with FastAPI."""
        # Add middleware
        middleware = ComplianceMiddleware(
            app=app,
            framework=framework,
            auto_enforce=False  # Disable for basic test
        )
        
        assert middleware.app == app
        assert middleware.framework == framework
        assert middleware.auto_enforce is False
        assert "/health" in middleware.excluded_paths
    
    def test_middleware_path_exclusion(self, app, framework):
        """Test middleware path exclusion."""
        middleware = ComplianceMiddleware(
            app=app,
            framework=framework,
            excluded_paths=["/health", "/metrics", "/test"]
        )
        
        assert "/test" in middleware.excluded_paths
        assert len(middleware.excluded_paths) == 3


class TestIntegrationScenarios:
    """Test complete integration scenarios using mock environment."""
    
    @pytest.fixture
    def test_environment(self):
        """Create test environment."""
        return MockComplianceTestEnvironment()
    
    def test_pii_processing_scenario(self, test_environment):
        """Test complete PII processing scenario."""
        # Create PII request
        pii_request = test_environment.create_pii_request(consent_granted=True)
        fastapi_request = pii_request.to_fastapi_request()
        
        # Create framework
        framework = create_compliance_framework([ComplianceRegulation.GDPR])
        
        # Evaluate compliance
        results = framework.evaluate_compliance(
            fastapi_request,
            pii_request.body,
            [DataCategory.PII]
        )
        
        assert ComplianceRegulation.GDPR in results
        assert results[ComplianceRegulation.GDPR] == ComplianceStatus.COMPLIANT
        
        # Enforce policies
        processed_data = framework.enforce_compliance(
            fastapi_request,
            pii_request.body,
            [DataCategory.PII]
        )
        
        assert isinstance(processed_data, dict)
    
    def test_phi_access_scenario(self, test_environment):
        """Test complete PHI access scenario."""
        # Create PHI request
        phi_request = test_environment.create_phi_request(authenticated=True)
        fastapi_request = phi_request.to_fastapi_request()
        
        # Create framework
        framework = create_compliance_framework([ComplianceRegulation.HIPAA])
        
        # Evaluate compliance
        results = framework.evaluate_compliance(
            fastapi_request,
            phi_request.body,
            [DataCategory.PHI]
        )
        
        assert ComplianceRegulation.HIPAA in results
        assert results[ComplianceRegulation.HIPAA] == ComplianceStatus.COMPLIANT
    
    def test_pci_transaction_scenario(self, test_environment):
        """Test complete PCI transaction scenario."""
        # Create PCI request
        pci_request = test_environment.create_pci_request(authorized=True)
        fastapi_request = pci_request.to_fastapi_request()
        
        # Create framework
        framework = create_compliance_framework([ComplianceRegulation.PCI_DSS])
        
        # Evaluate compliance
        results = framework.evaluate_compliance(
            fastapi_request,
            pci_request.body,
            [DataCategory.PCI]
        )
        
        assert ComplianceRegulation.PCI_DSS in results
        assert results[ComplianceRegulation.PCI_DSS] == ComplianceStatus.COMPLIANT
    
    def test_mixed_compliance_scenario(self, test_environment):
        """Test mixed compliance scenario with multiple regulations."""
        # Generate mixed test scenarios
        scenarios = test_environment.simulate_compliance_scenario(
            'mixed_traffic',
            duration_seconds=2,
            requests_per_second=5
        )
        
        assert len(scenarios) >= 8  # Should have multiple scenarios
        
        # Verify scenario variety
        scenario_types = set(s['type'] for s in scenarios)
        assert len(scenario_types) >= 2  # Should have different types
    
    def test_compliance_performance_measurement(self, test_environment):
        """Test compliance framework performance measurement."""
        # Create framework
        framework = create_compliance_framework()
        
        # Generate test requests
        test_requests = []
        for i in range(20):
            if i % 3 == 0:
                req = test_environment.create_pii_request(consent_granted=True)
                test_requests.append({
                    'type': 'pii',
                    'request_data': req,
                    'data_categories': [DataCategory.PII],
                    'expected_compliance': ComplianceStatus.COMPLIANT
                })
            elif i % 3 == 1:
                req = test_environment.create_phi_request(authenticated=True) 
                test_requests.append({
                    'type': 'phi',
                    'request_data': req,
                    'data_categories': [DataCategory.PHI],
                    'expected_compliance': ComplianceStatus.COMPLIANT
                })
            else:
                req = test_environment.create_pci_request(authorized=True)
                test_requests.append({
                    'type': 'pci',
                    'request_data': req,
                    'data_categories': [DataCategory.PCI],
                    'expected_compliance': ComplianceStatus.COMPLIANT
                })
        
        # Measure performance
        performance_results = test_environment.measure_compliance_performance(
            framework,
            test_requests
        )
        
        assert performance_results['total_requests'] == 20
        assert performance_results['average_request_time'] >= 0
        assert performance_results['compliance_rate'] >= 0
        assert performance_results['requests_per_second'] >= 0
        assert len(performance_results['processing_times']) == 20
    
    def test_audit_trail_scenario(self, test_environment):
        """Test complete audit trail scenario."""
        framework = create_compliance_framework()
        
        # Create and process multiple requests
        requests_data = [
            (test_environment.create_pii_request(), [DataCategory.PII]),
            (test_environment.create_phi_request(), [DataCategory.PHI]),
            (test_environment.create_pci_request(), [DataCategory.PCI])
        ]
        
        for req_data, categories in requests_data:
            fastapi_request = req_data.to_fastapi_request()
            framework.evaluate_compliance(fastapi_request, req_data.body, categories)
        
        # Verify audit events were recorded
        all_events = framework.get_audit_events()
        assert len(all_events) >= 3
        
        # Verify different regulations were logged
        regulations = set(event.regulation for event in all_events)
        assert len(regulations) >= 1
        
        # Generate compliance report
        report = framework.get_compliance_report()
        assert report['summary']['total_events'] >= 3
        assert isinstance(report['summary']['compliance_rate'], (int, float))


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases."""
    
    def test_empty_data_compliance(self):
        """Test compliance evaluation with empty data."""
        framework = create_compliance_framework()
        
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.url.path = "/api/test"
        mock_request.cookies = {}
        mock_request.client.host = "127.0.0.1"
        
        results = framework.evaluate_compliance(mock_request, {}, [DataCategory.PUBLIC])
        
        # Should handle empty data gracefully
        assert isinstance(results, dict)
    
    def test_invalid_audit_event_integrity(self):
        """Test handling of invalid audit events."""
        audit_manager = AuditTrailManager()
        
        # Create event with invalid integrity
        event = create_sample_audit_event()
        event.checksum = "invalid_checksum"
        
        with pytest.raises(ValueError, match="integrity verification failed"):
            audit_manager.record_event(event)
    
    def test_framework_with_no_regulations(self):
        """Test framework with no enabled regulations."""
        framework = ComplianceFramework(enabled_regulations=[])
        
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.url.path = "/api/test"
        mock_request.cookies = {}
        mock_request.client.host = "127.0.0.1"
        
        results = framework.evaluate_compliance(mock_request, {}, [DataCategory.PUBLIC])
        
        assert len(results) == 0
    
    def test_large_data_handling(self):
        """Test handling of large data sets."""
        framework = create_compliance_framework([ComplianceRegulation.GDPR])
        
        mock_request = Mock(spec=Request)
        mock_request.headers = {'x-gdpr-consent': 'true', 'x-gdpr-lawful-basis': 'consent'}
        mock_request.url.path = "/api/test"
        mock_request.cookies = {}
        mock_request.client.host = "127.0.0.1"
        
        # Create large data set
        large_data = {f"field_{i}": f"value_{i}" * 100 for i in range(100)}
        
        results = framework.evaluate_compliance(mock_request, large_data, [DataCategory.PII])
        
        # Should handle large data without errors
        assert ComplianceRegulation.GDPR in results


if __name__ == "__main__":
    pytest.main([__file__, "-v"])