"""Mock compliance infrastructure for testing compliance framework.

This module provides mock classes and utilities for testing compliance functionality
without requiring external compliance services or real sensitive data.
"""

import json
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from unittest.mock import Mock, MagicMock

from fastapi import Request
from fastapi.testclient import TestClient

from fastapi_shield.compliance_framework import (
    ComplianceRegulation, ComplianceStatus, AuditEventType, DataCategory,
    PrivacyAction, ComplianceSeverity, ComplianceRule, AuditEvent,
    ComplianceViolation, DataPrivacyPolicy, ComplianceMetrics
)


@dataclass
class MockComplianceTestConfig:
    """Configuration for mock compliance testing."""
    enable_audit_logging: bool = True
    simulate_regulation_failures: bool = False
    failure_rate: float = 0.1
    audit_retention_hours: int = 24
    generate_synthetic_violations: bool = True


@dataclass
class MockRequestData:
    """Mock request data for compliance testing."""
    method: str = "GET"
    path: str = "/api/test"
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    body: Dict[str, Any] = field(default_factory=dict)
    client_ip: str = "192.168.1.100"
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    contains_pii: bool = False
    contains_phi: bool = False
    contains_pci: bool = False
    
    def to_fastapi_request(self) -> Mock:
        """Convert to mock FastAPI Request object."""
        mock_request = Mock(spec=Request)
        mock_request.method = self.method
        mock_request.url.path = self.path
        mock_request.url.scheme = "https"
        mock_request.headers = self.headers
        mock_request.query_params = self.query_params
        mock_request.client.host = self.client_ip
        mock_request.cookies = {}
        
        # Add standard compliance headers if data categories are present
        if self.contains_pii:
            mock_request.headers.setdefault('x-gdpr-consent', 'true')
            mock_request.headers.setdefault('x-gdpr-lawful-basis', 'consent')
        
        if self.contains_phi:
            mock_request.headers.setdefault('x-audit-enabled', 'true')
            mock_request.headers.setdefault('authorization', 'Bearer valid-healthcare-token')
        
        if self.contains_pci:
            mock_request.headers.setdefault('x-pci-audit', 'true')
            mock_request.headers.setdefault('x-pci-encryption', 'aes256')
            mock_request.headers.setdefault('x-user-role', 'authorized_user')
        
        # Mock URL string method
        mock_request.url.__str__ = lambda self: f"https://example.com{self.path}"
        
        # Mock JSON method
        async def mock_json():
            return self.body
        mock_request.json = mock_json
        
        return mock_request


class MockComplianceDatabase:
    """Mock database for compliance data storage."""
    
    def __init__(self):
        self.audit_events: Dict[str, AuditEvent] = {}
        self.compliance_violations: Dict[str, ComplianceViolation] = {}
        self.privacy_policies: Dict[str, DataPrivacyPolicy] = {}
        self.compliance_rules: Dict[str, ComplianceRule] = {}
        self.user_consents: Dict[str, Dict[str, Any]] = {}
        self.data_retention_records: Dict[str, Any] = {}
        
    def store_audit_event(self, event: AuditEvent) -> str:
        """Store audit event in mock database."""
        self.audit_events[event.id] = event
        return event.id
    
    def get_audit_events(self, **filters) -> List[AuditEvent]:
        """Retrieve audit events with filtering."""
        events = list(self.audit_events.values())
        
        if 'regulation' in filters:
            events = [e for e in events if e.regulation == filters['regulation']]
        
        if 'event_type' in filters:
            events = [e for e in events if e.event_type == filters['event_type']]
        
        if 'start_time' in filters:
            events = [e for e in events if e.timestamp >= filters['start_time']]
        
        if 'end_time' in filters:
            events = [e for e in events if e.timestamp <= filters['end_time']]
        
        if 'user_id' in filters:
            events = [e for e in events if e.user_id == filters['user_id']]
        
        return events
    
    def store_violation(self, violation: ComplianceViolation) -> str:
        """Store compliance violation."""
        self.compliance_violations[violation.id] = violation
        return violation.id
    
    def get_violations(self, **filters) -> List[ComplianceViolation]:
        """Retrieve compliance violations with filtering."""
        violations = list(self.compliance_violations.values())
        
        if 'regulation' in filters:
            violations = [v for v in violations if v.regulation == filters['regulation']]
        
        if 'severity' in filters:
            violations = [v for v in violations if v.severity == filters['severity']]
        
        return violations


class MockRegulationChecker:
    """Mock regulation checker for testing compliance validation."""
    
    def __init__(self, config: MockComplianceTestConfig):
        self.config = config
        self.regulation_rules = {
            ComplianceRegulation.GDPR: self._check_gdpr_compliance,
            ComplianceRegulation.HIPAA: self._check_hipaa_compliance,
            ComplianceRegulation.PCI_DSS: self._check_pci_compliance
        }
    
    def check_compliance(self, 
                        regulation: ComplianceRegulation,
                        request_data: MockRequestData) -> Tuple[ComplianceStatus, List[str]]:
        """Check compliance for a specific regulation."""
        if self.config.simulate_regulation_failures and random.random() < self.config.failure_rate:
            return ComplianceStatus.NON_COMPLIANT, ["Simulated compliance failure"]
        
        if regulation in self.regulation_rules:
            return self.regulation_rules[regulation](request_data)
        
        return ComplianceStatus.UNKNOWN, ["Unsupported regulation"]
    
    def _check_gdpr_compliance(self, request_data: MockRequestData) -> Tuple[ComplianceStatus, List[str]]:
        """Check GDPR compliance."""
        issues = []
        
        if request_data.contains_pii:
            if 'x-gdpr-consent' not in request_data.headers:
                issues.append("Missing GDPR consent header")
            elif request_data.headers['x-gdpr-consent'].lower() != 'true':
                issues.append("GDPR consent not granted")
            
            if 'x-gdpr-lawful-basis' not in request_data.headers:
                issues.append("Missing GDPR lawful basis")
        
        return (ComplianceStatus.NON_COMPLIANT if issues else ComplianceStatus.COMPLIANT, issues)
    
    def _check_hipaa_compliance(self, request_data: MockRequestData) -> Tuple[ComplianceStatus, List[str]]:
        """Check HIPAA compliance."""
        issues = []
        
        if request_data.contains_phi:
            if 'authorization' not in request_data.headers:
                issues.append("Missing authentication for PHI access")
            
            if 'x-audit-enabled' not in request_data.headers:
                issues.append("PHI access logging not enabled")
        
        return (ComplianceStatus.NON_COMPLIANT if issues else ComplianceStatus.COMPLIANT, issues)
    
    def _check_pci_compliance(self, request_data: MockRequestData) -> Tuple[ComplianceStatus, List[str]]:
        """Check PCI-DSS compliance."""
        issues = []
        
        if request_data.contains_pci:
            if 'x-pci-encryption' not in request_data.headers:
                issues.append("Missing PCI encryption header")
            
            if 'x-user-role' not in request_data.headers:
                issues.append("Missing user role for PCI data access")
            elif request_data.headers['x-user-role'] not in ['admin', 'authorized_user']:
                issues.append("Insufficient role for PCI data access")
        
        return (ComplianceStatus.NON_COMPLIANT if issues else ComplianceStatus.COMPLIANT, issues)


class MockDataClassifier:
    """Mock data classifier for identifying sensitive data categories."""
    
    def __init__(self):
        self.pii_keywords = [
            'email', 'name', 'address', 'phone', 'ssn', 'social_security',
            'firstname', 'lastname', 'fullname', 'telephone', 'mobile'
        ]
        
        self.phi_keywords = [
            'patient', 'medical', 'health', 'diagnosis', 'treatment',
            'hospital', 'doctor', 'prescription', 'medical_record', 'mrn'
        ]
        
        self.pci_keywords = [
            'card', 'credit', 'payment', 'cvv', 'expiry', 'cardholder',
            'visa', 'mastercard', 'amex', 'discover'
        ]
    
    def classify_data(self, data: Dict[str, Any]) -> List[DataCategory]:
        """Classify data into categories."""
        if not data:
            return [DataCategory.PUBLIC]
        
        categories = []
        data_str = json.dumps(data, default=str).lower()
        
        if any(keyword in data_str for keyword in self.pii_keywords):
            categories.append(DataCategory.PII)
        
        if any(keyword in data_str for keyword in self.phi_keywords):
            categories.append(DataCategory.PHI)
        
        if any(keyword in data_str for keyword in self.pci_keywords):
            categories.append(DataCategory.PCI)
        
        if 'confidential' in data_str or 'secret' in data_str:
            categories.append(DataCategory.CONFIDENTIAL)
        
        if 'sensitive' in data_str:
            categories.append(DataCategory.SENSITIVE)
        
        return categories if categories else [DataCategory.PUBLIC]
    
    def contains_pii_patterns(self, text: str) -> bool:
        """Check if text contains PII patterns."""
        import re
        
        patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
            r'\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'  # Phone pattern
        ]
        
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)
    
    def contains_pci_patterns(self, text: str) -> bool:
        """Check if text contains PCI patterns."""
        import re
        
        patterns = [
            r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Visa
            r'\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # MasterCard
            r'\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b',  # American Express
        ]
        
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


class MockAuditLogger:
    """Mock audit logger for testing audit trail functionality."""
    
    def __init__(self, database: MockComplianceDatabase):
        self.database = database
        self.log_entries = []
        self.integrity_failures = []
    
    def log_event(self, event: AuditEvent) -> str:
        """Log audit event."""
        # Simulate integrity check
        if event.verify_integrity():
            event_id = self.database.store_audit_event(event)
            self.log_entries.append({
                'timestamp': event.timestamp,
                'event_id': event.id,
                'event_type': event.event_type.value,
                'regulation': event.regulation.value,
                'status': 'logged'
            })
            return event_id
        else:
            self.integrity_failures.append(event.id)
            raise ValueError(f"Audit event {event.id} failed integrity check")
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        event_types = defaultdict(int)
        regulations = defaultdict(int)
        
        for entry in self.log_entries:
            event_types[entry['event_type']] += 1
            regulations[entry['regulation']] += 1
        
        return {
            'total_events': len(self.log_entries),
            'integrity_failures': len(self.integrity_failures),
            'event_types': dict(event_types),
            'regulations': dict(regulations)
        }


class MockPrivacyProcessor:
    """Mock privacy processor for testing data anonymization and encryption."""
    
    def __init__(self):
        self.anonymization_count = 0
        self.pseudonymization_count = 0
        self.encryption_count = 0
        self.redaction_count = 0
    
    def anonymize_data(self, data: Dict[str, Any], rules: Dict[str, str]) -> Dict[str, Any]:
        """Apply anonymization rules to data."""
        self.anonymization_count += 1
        anonymized = data.copy()
        
        for field, rule in rules.items():
            if field in anonymized:
                if rule == 'hash':
                    anonymized[field] = f"HASH_{hash(str(anonymized[field])) % 10000}"
                elif rule == 'remove':
                    del anonymized[field]
                elif rule == 'generalize':
                    anonymized[field] = "[GENERALIZED]"
        
        return anonymized
    
    def pseudonymize_data(self, data: Dict[str, Any], rules: Dict[str, str]) -> Dict[str, Any]:
        """Apply pseudonymization rules to data."""
        self.pseudonymization_count += 1
        pseudonymized = data.copy()
        
        for field, rule in rules.items():
            if field in pseudonymized:
                if rule == 'hash':
                    pseudonymized[field] = f"PSEUDO_{hash(str(pseudonymized[field])) % 10000}"
                elif rule == 'mask':
                    value = str(pseudonymized[field])
                    if len(value) > 4:
                        pseudonymized[field] = value[:2] + '*' * (len(value) - 4) + value[-2:]
        
        return pseudonymized
    
    def encrypt_data(self, data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """Encrypt specified fields in data."""
        self.encryption_count += 1
        encrypted = data.copy()
        
        for field in fields:
            if field in encrypted:
                encrypted[field] = f"[ENCRYPTED:{hash(str(encrypted[field])) % 10000}]"
        
        return encrypted
    
    def redact_data(self, data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """Redact specified fields in data."""
        self.redaction_count += 1
        redacted = data.copy()
        
        for field in fields:
            if field in redacted:
                redacted[field] = "[REDACTED]"
        
        return redacted
    
    def get_processing_stats(self) -> Dict[str, int]:
        """Get privacy processing statistics."""
        return {
            'anonymizations': self.anonymization_count,
            'pseudonymizations': self.pseudonymization_count,
            'encryptions': self.encryption_count,
            'redactions': self.redaction_count
        }


class MockComplianceTestEnvironment:
    """Complete mock environment for compliance testing."""
    
    def __init__(self, config: MockComplianceTestConfig = None):
        self.config = config or MockComplianceTestConfig()
        self.database = MockComplianceDatabase()
        self.regulation_checker = MockRegulationChecker(self.config)
        self.data_classifier = MockDataClassifier()
        self.audit_logger = MockAuditLogger(self.database)
        self.privacy_processor = MockPrivacyProcessor()
        
        # Initialize with some sample data
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize environment with sample compliance data."""
        # Sample compliance rules
        sample_rules = [
            ComplianceRule(
                id="test_gdpr_001",
                regulation=ComplianceRegulation.GDPR,
                name="Test GDPR Consent",
                description="Test rule for GDPR consent validation",
                requirement="Test Article 6",
                category="consent",
                severity=ComplianceSeverity.HIGH,
                data_categories=[DataCategory.PII],
                remediation_steps=["Obtain consent"],
                references=["Test GDPR"]
            ),
            ComplianceRule(
                id="test_hipaa_001",
                regulation=ComplianceRegulation.HIPAA,
                name="Test HIPAA PHI Protection",
                description="Test rule for PHI protection",
                requirement="Test 164.312",
                category="encryption",
                severity=ComplianceSeverity.CRITICAL,
                data_categories=[DataCategory.PHI],
                remediation_steps=["Encrypt PHI"],
                references=["Test HIPAA"]
            )
        ]
        
        for rule in sample_rules:
            self.database.compliance_rules[rule.id] = rule
    
    def create_test_request(self, **kwargs) -> MockRequestData:
        """Create test request data with specified parameters."""
        return MockRequestData(**kwargs)
    
    def create_pii_request(self, consent_granted: bool = True) -> MockRequestData:
        """Create request containing PII data."""
        headers = {}
        if consent_granted:
            headers.update({
                'x-gdpr-consent': 'true',
                'x-gdpr-lawful-basis': 'consent'
            })
        
        return MockRequestData(
            method="POST",
            path="/api/users",
            headers=headers,
            body={
                "email": "test@example.com",
                "name": "John Doe",
                "phone": "+1-555-123-4567"
            },
            contains_pii=True
        )
    
    def create_phi_request(self, authenticated: bool = True) -> MockRequestData:
        """Create request containing PHI data."""
        headers = {}
        if authenticated:
            headers.update({
                'authorization': 'Bearer healthcare-token',
                'x-audit-enabled': 'true'
            })
        
        return MockRequestData(
            method="GET",
            path="/api/patients/123",
            headers=headers,
            body={
                "patient_id": "P123456",
                "diagnosis": "Hypertension",
                "treatment": "Medication prescribed"
            },
            contains_phi=True
        )
    
    def create_pci_request(self, authorized: bool = True) -> MockRequestData:
        """Create request containing PCI data."""
        headers = {}
        if authorized:
            headers.update({
                'x-pci-audit': 'true',
                'x-pci-encryption': 'aes256',
                'x-user-role': 'authorized_user'
            })
        
        return MockRequestData(
            method="POST",
            path="/api/payments",
            headers=headers,
            body={
                "card_number": "4111-1111-1111-1111",
                "cvv": "123",
                "cardholder_name": "Jane Smith"
            },
            contains_pci=True
        )
    
    def simulate_compliance_scenario(self, 
                                   scenario_type: str,
                                   duration_seconds: int = 60,
                                   requests_per_second: int = 5) -> List[Dict[str, Any]]:
        """Simulate various compliance scenarios."""
        scenario_results = []
        start_time = time.time()
        
        scenario_generators = {
            'mixed_traffic': self._generate_mixed_traffic,
            'pii_processing': self._generate_pii_scenario,
            'phi_access': self._generate_phi_scenario,
            'pci_transactions': self._generate_pci_scenario,
            'compliance_violations': self._generate_violation_scenario
        }
        
        if scenario_type not in scenario_generators:
            raise ValueError(f"Unknown scenario type: {scenario_type}")
        
        generator = scenario_generators[scenario_type]
        
        while time.time() - start_time < duration_seconds:
            for _ in range(requests_per_second):
                scenario_data = generator()
                scenario_results.append(scenario_data)
            
            time.sleep(1.0)
        
        return scenario_results
    
    def _generate_mixed_traffic(self) -> Dict[str, Any]:
        """Generate mixed compliance traffic."""
        scenarios = [
            ('pii', 0.3),
            ('phi', 0.2),
            ('pci', 0.2),
            ('public', 0.3)
        ]
        
        # Weighted random selection
        rand_val = random.random()
        cumulative = 0
        
        for scenario, weight in scenarios:
            cumulative += weight
            if rand_val <= cumulative:
                if scenario == 'pii':
                    return self._generate_pii_scenario()
                elif scenario == 'phi':
                    return self._generate_phi_scenario()
                elif scenario == 'pci':
                    return self._generate_pci_scenario()
                else:
                    return self._generate_public_scenario()
        
        return self._generate_public_scenario()
    
    def _generate_pii_scenario(self) -> Dict[str, Any]:
        """Generate PII processing scenario."""
        consent_granted = random.choice([True, True, True, False])  # 75% compliance
        request = self.create_pii_request(consent_granted)
        
        return {
            'type': 'pii_processing',
            'request_data': request,
            'expected_compliance': ComplianceStatus.COMPLIANT if consent_granted else ComplianceStatus.NON_COMPLIANT,
            'data_categories': [DataCategory.PII],
            'regulations': [ComplianceRegulation.GDPR]
        }
    
    def _generate_phi_scenario(self) -> Dict[str, Any]:
        """Generate PHI access scenario."""
        authenticated = random.choice([True, True, False])  # 67% compliance
        request = self.create_phi_request(authenticated)
        
        return {
            'type': 'phi_access',
            'request_data': request,
            'expected_compliance': ComplianceStatus.COMPLIANT if authenticated else ComplianceStatus.NON_COMPLIANT,
            'data_categories': [DataCategory.PHI],
            'regulations': [ComplianceRegulation.HIPAA]
        }
    
    def _generate_pci_scenario(self) -> Dict[str, Any]:
        """Generate PCI transaction scenario."""
        authorized = random.choice([True, True, True, False])  # 75% compliance
        request = self.create_pci_request(authorized)
        
        return {
            'type': 'pci_transaction',
            'request_data': request,
            'expected_compliance': ComplianceStatus.COMPLIANT if authorized else ComplianceStatus.NON_COMPLIANT,
            'data_categories': [DataCategory.PCI],
            'regulations': [ComplianceRegulation.PCI_DSS]
        }
    
    def _generate_public_scenario(self) -> Dict[str, Any]:
        """Generate public data scenario."""
        request = MockRequestData(
            path="/api/public/info",
            body={"message": "Public information request"},
            contains_pii=False,
            contains_phi=False,
            contains_pci=False
        )
        
        return {
            'type': 'public_data',
            'request_data': request,
            'expected_compliance': ComplianceStatus.COMPLIANT,
            'data_categories': [DataCategory.PUBLIC],
            'regulations': []
        }
    
    def _generate_violation_scenario(self) -> Dict[str, Any]:
        """Generate compliance violation scenario."""
        violation_types = [
            ('pii_no_consent', self.create_pii_request(False)),
            ('phi_no_auth', self.create_phi_request(False)),
            ('pci_no_auth', self.create_pci_request(False))
        ]
        
        violation_type, request = random.choice(violation_types)
        
        return {
            'type': 'compliance_violation',
            'violation_type': violation_type,
            'request_data': request,
            'expected_compliance': ComplianceStatus.NON_COMPLIANT,
            'severity': ComplianceSeverity.HIGH
        }
    
    def measure_compliance_performance(self, 
                                     framework,
                                     test_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Measure compliance framework performance."""
        start_time = time.time()
        results = {
            'total_requests': len(test_requests),
            'compliant_requests': 0,
            'non_compliant_requests': 0,
            'processing_times': [],
            'regulation_results': defaultdict(lambda: {'compliant': 0, 'non_compliant': 0}),
            'data_category_results': defaultdict(lambda: {'compliant': 0, 'non_compliant': 0})
        }
        
        for test_request in test_requests:
            request_start = time.time()
            
            # Convert to FastAPI request
            request_data = test_request['request_data']
            fastapi_request = request_data.to_fastapi_request()
            
            # Evaluate compliance
            try:
                compliance_results = framework.evaluate_compliance(
                    fastapi_request,
                    request_data.body,
                    test_request['data_categories']
                )
                
                # Analyze results
                overall_compliant = all(
                    status == ComplianceStatus.COMPLIANT
                    for status in compliance_results.values()
                )
                
                if overall_compliant:
                    results['compliant_requests'] += 1
                else:
                    results['non_compliant_requests'] += 1
                
                # Track by regulation
                for regulation, status in compliance_results.items():
                    if status == ComplianceStatus.COMPLIANT:
                        results['regulation_results'][regulation.value]['compliant'] += 1
                    else:
                        results['regulation_results'][regulation.value]['non_compliant'] += 1
                
                # Track by data category
                for category in test_request['data_categories']:
                    if overall_compliant:
                        results['data_category_results'][category.value]['compliant'] += 1
                    else:
                        results['data_category_results'][category.value]['non_compliant'] += 1
            
            except Exception as e:
                results['non_compliant_requests'] += 1
                print(f"Compliance evaluation error: {e}")
            
            request_time = time.time() - request_start
            results['processing_times'].append(request_time)
        
        # Calculate summary statistics
        total_time = time.time() - start_time
        processing_times = results['processing_times']
        
        results.update({
            'total_processing_time': total_time,
            'average_request_time': sum(processing_times) / len(processing_times) if processing_times else 0,
            'min_request_time': min(processing_times) if processing_times else 0,
            'max_request_time': max(processing_times) if processing_times else 0,
            'compliance_rate': results['compliant_requests'] / results['total_requests'] if results['total_requests'] > 0 else 0,
            'requests_per_second': results['total_requests'] / total_time if total_time > 0 else 0
        })
        
        return results
    
    def get_environment_statistics(self) -> Dict[str, Any]:
        """Get comprehensive environment statistics."""
        return {
            'database': {
                'audit_events': len(self.database.audit_events),
                'violations': len(self.database.compliance_violations),
                'policies': len(self.database.privacy_policies),
                'rules': len(self.database.compliance_rules)
            },
            'audit_logger': self.audit_logger.get_log_statistics(),
            'privacy_processor': self.privacy_processor.get_processing_stats(),
            'config': {
                'simulate_failures': self.config.simulate_regulation_failures,
                'failure_rate': self.config.failure_rate,
                'audit_retention_hours': self.config.audit_retention_hours
            }
        }


# Utility functions for creating test data

def create_sample_audit_event(regulation: ComplianceRegulation = ComplianceRegulation.GDPR) -> AuditEvent:
    """Create sample audit event for testing."""
    return AuditEvent(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        event_type=AuditEventType.DATA_ACCESS,
        regulation=regulation,
        user_id="test_user_123",
        client_ip="192.168.1.100",
        resource="/api/test/resource",
        action="read",
        outcome="success",
        details={"test": "sample audit event"},
        data_categories=[DataCategory.PII],
        compliance_status=ComplianceStatus.COMPLIANT,
        session_id="session_123",
        request_id="req_123"
    )


def create_sample_violation(regulation: ComplianceRegulation = ComplianceRegulation.GDPR) -> ComplianceViolation:
    """Create sample compliance violation for testing."""
    return ComplianceViolation(
        id=str(uuid.uuid4()),
        rule_id="test_rule_001",
        regulation=regulation,
        severity=ComplianceSeverity.HIGH,
        timestamp=datetime.now(timezone.utc),
        resource="/api/test/violation",
        violation_details="Sample compliance violation for testing",
        affected_data_categories=[DataCategory.PII],
        remediation_required=True,
        remediation_steps=["Fix the issue", "Update policies"]
    )


def create_sample_privacy_policy(regulation: ComplianceRegulation = ComplianceRegulation.GDPR) -> DataPrivacyPolicy:
    """Create sample privacy policy for testing."""
    return DataPrivacyPolicy(
        id=f"test_policy_{regulation.value}",
        name=f"Test {regulation.value} Policy",
        regulation=regulation,
        data_category=DataCategory.PII,
        privacy_actions=[PrivacyAction.LOG_ACCESS, PrivacyAction.REQUIRE_CONSENT],
        retention_period=timedelta(days=365),
        access_restrictions={"min_auth_level": "authenticated"},
        consent_required=True,
        anonymization_rules={"email": "hash", "name": "mask"}
    )


def generate_test_dataset(size: int = 100) -> List[Dict[str, Any]]:
    """Generate test dataset for compliance testing."""
    env = MockComplianceTestEnvironment()
    dataset = []
    
    for _ in range(size):
        scenario_type = random.choice(['pii_processing', 'phi_access', 'pci_transactions'])
        scenario_data = env.simulate_compliance_scenario(scenario_type, duration_seconds=1, requests_per_second=1)
        
        if scenario_data:
            dataset.extend(scenario_data)
    
    return dataset[:size]  # Trim to exact size


# Context manager for compliance testing
class mock_compliance_environment:
    """Context manager for mock compliance testing environment."""
    
    def __init__(self, config: MockComplianceTestConfig = None):
        self.config = config or MockComplianceTestConfig()
        self.environment = None
    
    def __enter__(self) -> MockComplianceTestEnvironment:
        self.environment = MockComplianceTestEnvironment(self.config)
        return self.environment
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clean up if needed
        pass


if __name__ == "__main__":
    # Example usage
    with mock_compliance_environment() as env:
        # Create test requests
        pii_request = env.create_pii_request()
        phi_request = env.create_phi_request()
        pci_request = env.create_pci_request()
        
        # Simulate scenarios
        mixed_scenarios = env.simulate_compliance_scenario('mixed_traffic', duration_seconds=5)
        
        print(f"Created {len(mixed_scenarios)} test scenarios")
        print(f"Environment statistics: {env.get_environment_statistics()}")