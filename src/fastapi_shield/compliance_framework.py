"""FastAPI-Shield Compliance Framework

This module provides comprehensive compliance validation, audit trail generation,
and regulatory requirement enforcement for GDPR, HIPAA, PCI-DSS, and other standards.

Features:
- Multi-regulatory compliance validation (GDPR, HIPAA, PCI-DSS)
- Automated policy enforcement and validation
- Comprehensive audit trail generation with tamper-proof logging
- Data privacy controls including anonymization and pseudonymization
- Real-time compliance monitoring and alerting
- Compliance reporting and dashboard capabilities
- Policy-based access controls and data handling
- Regulatory requirement mapping and validation
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from pathlib import Path
from threading import RLock, Lock
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    NamedTuple, Protocol, TypeVar
)
import re

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# Compliance regulation types
class ComplianceRegulation(Enum):
    """Supported compliance regulations."""
    GDPR = "gdpr"           # General Data Protection Regulation
    HIPAA = "hipaa"         # Health Insurance Portability and Accountability Act
    PCI_DSS = "pci_dss"     # Payment Card Industry Data Security Standard
    SOX = "sox"             # Sarbanes-Oxley Act
    CCPA = "ccpa"           # California Consumer Privacy Act
    ISO_27001 = "iso_27001" # ISO/IEC 27001 Information Security Management
    NIST = "nist"           # NIST Cybersecurity Framework
    CUSTOM = "custom"       # Custom regulatory requirements


class ComplianceStatus(Enum):
    """Compliance validation status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    WARNING = "warning"
    UNKNOWN = "unknown"
    EXEMPT = "exempt"


class AuditEventType(Enum):
    """Types of audit events."""
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    DATA_EXPORT = "data_export"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    POLICY_VIOLATION = "policy_violation"
    COMPLIANCE_CHECK = "compliance_check"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_INCIDENT = "security_incident"
    USER_CONSENT = "user_consent"
    DATA_RETENTION = "data_retention"
    ANONYMIZATION = "anonymization"


class DataCategory(Enum):
    """Data categories for privacy classification."""
    PII = "personally_identifiable_information"      # Personal identifiable information
    PHI = "protected_health_information"            # Protected health information
    PCI = "payment_card_information"               # Payment card information
    SENSITIVE = "sensitive_data"                   # General sensitive data
    CONFIDENTIAL = "confidential_data"             # Confidential business data
    PUBLIC = "public_data"                         # Public information
    RESTRICTED = "restricted_data"                 # Access-restricted data


class PrivacyAction(Enum):
    """Privacy actions for data handling."""
    ANONYMIZE = "anonymize"
    PSEUDONYMIZE = "pseudonymize"
    ENCRYPT = "encrypt"
    REDACT = "redact"
    LOG_ACCESS = "log_access"
    REQUIRE_CONSENT = "require_consent"
    APPLY_RETENTION = "apply_retention"
    RESTRICT_ACCESS = "restrict_access"


class ComplianceSeverity(Enum):
    """Severity levels for compliance violations."""
    CRITICAL = "critical"      # Immediate regulatory violation
    HIGH = "high"             # Significant compliance risk
    MEDIUM = "medium"         # Moderate compliance concern
    LOW = "low"               # Minor compliance issue
    INFO = "info"             # Informational compliance note


@dataclass
class ComplianceRule:
    """Individual compliance rule definition."""
    id: str
    regulation: ComplianceRegulation
    name: str
    description: str
    requirement: str
    category: str
    severity: ComplianceSeverity
    data_categories: List[DataCategory]
    validation_func: Optional[Callable[[Any], bool]] = None
    remediation_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    is_enabled: bool = True
    tags: List[str] = field(default_factory=list)


@dataclass
class AuditEvent:
    """Audit event record with tamper-proof integrity."""
    id: str
    timestamp: datetime
    event_type: AuditEventType
    regulation: ComplianceRegulation
    user_id: Optional[str]
    client_ip: str
    resource: str
    action: str
    outcome: str
    details: Dict[str, Any]
    data_categories: List[DataCategory]
    compliance_status: ComplianceStatus
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    checksum: Optional[str] = None
    
    def __post_init__(self):
        """Generate tamper-proof checksum for audit integrity."""
        if not self.checksum:
            self.checksum = self._generate_checksum()
    
    def _generate_checksum(self) -> str:
        """Generate SHA-256 checksum for audit event integrity."""
        data = {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'regulation': self.regulation.value,
            'user_id': self.user_id,
            'client_ip': self.client_ip,
            'resource': self.resource,
            'action': self.action,
            'outcome': self.outcome,
            'details': self.details,
            'data_categories': [cat.value for cat in self.data_categories],
            'compliance_status': self.compliance_status.value,
            'session_id': self.session_id,
            'request_id': self.request_id
        }
        
        json_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify audit event integrity using checksum."""
        expected_checksum = self._generate_checksum()
        return hmac.compare_digest(self.checksum or "", expected_checksum)


@dataclass
class ComplianceViolation:
    """Compliance violation record."""
    id: str
    rule_id: str
    regulation: ComplianceRegulation
    severity: ComplianceSeverity
    timestamp: datetime
    resource: str
    violation_details: str
    affected_data_categories: List[DataCategory]
    remediation_required: bool
    auto_remediated: bool = False
    remediation_steps: List[str] = field(default_factory=list)
    related_audit_events: List[str] = field(default_factory=list)


@dataclass
class DataPrivacyPolicy:
    """Data privacy policy definition."""
    id: str
    name: str
    regulation: ComplianceRegulation
    data_category: DataCategory
    privacy_actions: List[PrivacyAction]
    retention_period: Optional[timedelta]
    access_restrictions: Dict[str, Any]
    consent_required: bool
    anonymization_rules: Dict[str, str]
    is_active: bool = True


@dataclass
class ComplianceMetrics:
    """Compliance metrics and statistics."""
    total_requests_evaluated: int = 0
    compliant_requests: int = 0
    non_compliant_requests: int = 0
    policy_violations: int = 0
    audit_events_generated: int = 0
    data_anonymizations: int = 0
    consent_requests: int = 0
    retention_policies_applied: int = 0
    
    @property
    def compliance_rate(self) -> float:
        """Calculate overall compliance rate."""
        if self.total_requests_evaluated == 0:
            return 1.0
        return self.compliant_requests / self.total_requests_evaluated
    
    @property
    def violation_rate(self) -> float:
        """Calculate violation rate."""
        if self.total_requests_evaluated == 0:
            return 0.0
        return self.policy_violations / self.total_requests_evaluated


class ComplianceValidator(ABC):
    """Abstract base class for compliance validators."""
    
    @abstractmethod
    def validate(self, request: Request, data: Dict[str, Any]) -> ComplianceStatus:
        """Validate compliance for a request."""
        pass
    
    @abstractmethod
    def get_required_actions(self, request: Request, data: Dict[str, Any]) -> List[PrivacyAction]:
        """Get required privacy actions for compliance."""
        pass


class GDPRValidator(ComplianceValidator):
    """GDPR compliance validator."""
    
    def __init__(self):
        self.pii_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN-like patterns
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Credit card patterns
            r'\b\+?[1-9]\d{1,14}\b',  # Phone numbers
        ]
    
    def validate(self, request: Request, data: Dict[str, Any]) -> ComplianceStatus:
        """Validate GDPR compliance."""
        issues = []
        
        # Check for PII in request without consent
        if self._contains_pii(data) and not self._has_valid_consent(request):
            issues.append("PII processing without valid consent")
        
        # Check for proper data minimization
        if not self._implements_data_minimization(data):
            issues.append("Data minimization principle not followed")
        
        # Check for lawful basis
        if not self._has_lawful_basis(request):
            issues.append("No lawful basis for data processing")
        
        # Check for data subject rights implementation
        if not self._supports_data_subject_rights(request):
            issues.append("Data subject rights not properly implemented")
        
        if issues:
            logger.warning(f"GDPR compliance issues: {', '.join(issues)}")
            return ComplianceStatus.NON_COMPLIANT
        
        return ComplianceStatus.COMPLIANT
    
    def get_required_actions(self, request: Request, data: Dict[str, Any]) -> List[PrivacyAction]:
        """Get required GDPR privacy actions."""
        actions = []
        
        if self._contains_pii(data):
            actions.extend([
                PrivacyAction.REQUIRE_CONSENT,
                PrivacyAction.LOG_ACCESS,
                PrivacyAction.APPLY_RETENTION
            ])
            
            # Pseudonymize if possible, otherwise encrypt
            if self._can_pseudonymize(data):
                actions.append(PrivacyAction.PSEUDONYMIZE)
            else:
                actions.append(PrivacyAction.ENCRYPT)
        
        return actions
    
    def _contains_pii(self, data: Dict[str, Any]) -> bool:
        """Check if data contains PII."""
        data_str = json.dumps(data, default=str)
        return any(re.search(pattern, data_str, re.IGNORECASE) for pattern in self.pii_patterns)
    
    def _has_valid_consent(self, request: Request) -> bool:
        """Check for valid GDPR consent."""
        consent_header = request.headers.get('x-gdpr-consent')
        return bool(consent_header and consent_header.lower() == 'true')
    
    def _implements_data_minimization(self, data: Dict[str, Any]) -> bool:
        """Check data minimization principle."""
        # Simple check: ensure not collecting excessive data
        return len(str(data)) < 10000  # Configurable threshold
    
    def _has_lawful_basis(self, request: Request) -> bool:
        """Check for lawful basis for processing."""
        basis = request.headers.get('x-gdpr-lawful-basis')
        valid_bases = ['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interests']
        return basis in valid_bases
    
    def _supports_data_subject_rights(self, request: Request) -> bool:
        """Check if data subject rights are supported."""
        # Check if endpoint supports GDPR subject requests
        path = request.url.path
        return any(keyword in path.lower() for keyword in ['privacy', 'gdpr', 'consent', 'data-subject'])
    
    def _can_pseudonymize(self, data: Dict[str, Any]) -> bool:
        """Check if data can be pseudonymized instead of encrypted."""
        # Simple heuristic: smaller datasets can be pseudonymized
        return len(json.dumps(data, default=str)) < 5000


class HIPAAValidator(ComplianceValidator):
    """HIPAA compliance validator."""
    
    def __init__(self):
        self.phi_indicators = [
            'patient', 'medical', 'diagnosis', 'treatment', 'health',
            'ssn', 'mrn', 'dob', 'birthdate', 'insurance'
        ]
    
    def validate(self, request: Request, data: Dict[str, Any]) -> ComplianceStatus:
        """Validate HIPAA compliance."""
        issues = []
        
        # Check for PHI encryption
        if self._contains_phi(data) and not self._is_encrypted_transmission(request):
            issues.append("PHI transmitted without encryption")
        
        # Check for proper authentication
        if not self._has_proper_authentication(request):
            issues.append("Insufficient authentication for PHI access")
        
        # Check access logging
        if not self._has_access_logging(request):
            issues.append("PHI access not properly logged")
        
        # Check for minimum necessary standard
        if not self._implements_minimum_necessary(data):
            issues.append("Minimum necessary standard not implemented")
        
        if issues:
            logger.warning(f"HIPAA compliance issues: {', '.join(issues)}")
            return ComplianceStatus.NON_COMPLIANT
        
        return ComplianceStatus.COMPLIANT
    
    def get_required_actions(self, request: Request, data: Dict[str, Any]) -> List[PrivacyAction]:
        """Get required HIPAA privacy actions."""
        actions = []
        
        if self._contains_phi(data):
            actions.extend([
                PrivacyAction.ENCRYPT,
                PrivacyAction.LOG_ACCESS,
                PrivacyAction.RESTRICT_ACCESS,
                PrivacyAction.APPLY_RETENTION
            ])
        
        return actions
    
    def _contains_phi(self, data: Dict[str, Any]) -> bool:
        """Check if data contains PHI."""
        data_str = json.dumps(data, default=str).lower()
        return any(indicator in data_str for indicator in self.phi_indicators)
    
    def _is_encrypted_transmission(self, request: Request) -> bool:
        """Check if transmission is encrypted."""
        return request.url.scheme == 'https'
    
    def _has_proper_authentication(self, request: Request) -> bool:
        """Check for proper authentication."""
        auth_header = request.headers.get('authorization')
        return bool(auth_header and len(auth_header) > 20)
    
    def _has_access_logging(self, request: Request) -> bool:
        """Check if access logging is enabled."""
        return request.headers.get('x-audit-enabled', 'false').lower() == 'true'
    
    def _implements_minimum_necessary(self, data: Dict[str, Any]) -> bool:
        """Check minimum necessary standard."""
        # Simple check: ensure reasonable data size
        return len(json.dumps(data, default=str)) < 50000


class PCIDSSValidator(ComplianceValidator):
    """PCI-DSS compliance validator."""
    
    def __init__(self):
        self.pci_patterns = [
            r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Visa
            r'\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # MasterCard
            r'\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b',  # American Express
            r'\bcvv\d{3,4}\b',  # CVV patterns
        ]
    
    def validate(self, request: Request, data: Dict[str, Any]) -> ComplianceStatus:
        """Validate PCI-DSS compliance."""
        issues = []
        
        # Check for unencrypted cardholder data
        if self._contains_cardholder_data(data) and not self._is_properly_encrypted(request):
            issues.append("Cardholder data not properly encrypted")
        
        # Check for secure transmission
        if not self._uses_secure_transmission(request):
            issues.append("Insecure transmission protocols")
        
        # Check access controls
        if not self._has_proper_access_controls(request):
            issues.append("Inadequate access controls")
        
        # Check logging and monitoring
        if not self._has_proper_logging(request):
            issues.append("Insufficient logging and monitoring")
        
        if issues:
            logger.warning(f"PCI-DSS compliance issues: {', '.join(issues)}")
            return ComplianceStatus.NON_COMPLIANT
        
        return ComplianceStatus.COMPLIANT
    
    def get_required_actions(self, request: Request, data: Dict[str, Any]) -> List[PrivacyAction]:
        """Get required PCI-DSS privacy actions."""
        actions = []
        
        if self._contains_cardholder_data(data):
            actions.extend([
                PrivacyAction.ENCRYPT,
                PrivacyAction.LOG_ACCESS,
                PrivacyAction.RESTRICT_ACCESS,
                PrivacyAction.REDACT  # Redact sensitive card data in logs
            ])
        
        return actions
    
    def _contains_cardholder_data(self, data: Dict[str, Any]) -> bool:
        """Check if data contains cardholder data."""
        data_str = json.dumps(data, default=str)
        return any(re.search(pattern, data_str, re.IGNORECASE) for pattern in self.pci_patterns)
    
    def _is_properly_encrypted(self, request: Request) -> bool:
        """Check if cardholder data is properly encrypted."""
        encryption_header = request.headers.get('x-pci-encryption')
        return bool(encryption_header and encryption_header.lower() == 'aes256')
    
    def _uses_secure_transmission(self, request: Request) -> bool:
        """Check for secure transmission protocols."""
        return request.url.scheme == 'https'
    
    def _has_proper_access_controls(self, request: Request) -> bool:
        """Check for proper access controls."""
        role_header = request.headers.get('x-user-role')
        return bool(role_header and role_header in ['admin', 'authorized_user'])
    
    def _has_proper_logging(self, request: Request) -> bool:
        """Check for proper logging."""
        return request.headers.get('x-pci-audit', 'false').lower() == 'true'


class AuditTrailManager:
    """Manages tamper-proof audit trail generation and storage."""
    
    def __init__(self, max_events: int = 100000):
        self.max_events = max_events
        self.audit_events: deque = deque(maxlen=max_events)
        self.event_index: Dict[str, AuditEvent] = {}
        self._lock = RLock()
        self.integrity_key = self._generate_integrity_key()
    
    def _generate_integrity_key(self) -> bytes:
        """Generate integrity key for HMAC operations."""
        return hashlib.sha256(f"compliance-audit-{time.time()}".encode()).digest()
    
    def record_event(self, event: AuditEvent) -> str:
        """Record audit event with integrity protection."""
        with self._lock:
            # Ensure event integrity
            if not event.verify_integrity():
                logger.error(f"Audit event {event.id} failed integrity check")
                raise ValueError("Audit event integrity verification failed")
            
            # Add HMAC for additional protection
            event_data = json.dumps({
                'id': event.id,
                'checksum': event.checksum,
                'timestamp': event.timestamp.isoformat()
            }, sort_keys=True)
            
            hmac_signature = hmac.new(
                self.integrity_key,
                event_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Store event with HMAC
            event.details['_hmac'] = hmac_signature
            
            self.audit_events.append(event)
            self.event_index[event.id] = event
            
            logger.info(f"Recorded audit event {event.id} for regulation {event.regulation.value}")
            return event.id
    
    def get_events(self, 
                   regulation: Optional[ComplianceRegulation] = None,
                   event_type: Optional[AuditEventType] = None,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   user_id: Optional[str] = None) -> List[AuditEvent]:
        """Retrieve audit events with optional filtering."""
        with self._lock:
            filtered_events = []
            
            for event in self.audit_events:
                # Apply filters
                if regulation and event.regulation != regulation:
                    continue
                if event_type and event.event_type != event_type:
                    continue
                if start_time and event.timestamp < start_time:
                    continue
                if end_time and event.timestamp > end_time:
                    continue
                if user_id and event.user_id != user_id:
                    continue
                
                # Verify event integrity before including
                if event.verify_integrity():
                    filtered_events.append(event)
                else:
                    logger.warning(f"Audit event {event.id} failed integrity verification")
            
            return filtered_events
    
    def verify_audit_trail_integrity(self) -> Dict[str, Any]:
        """Verify integrity of entire audit trail."""
        with self._lock:
            total_events = len(self.audit_events)
            valid_events = 0
            corrupted_events = []
            
            for event in self.audit_events:
                if event.verify_integrity():
                    # Also verify HMAC if present
                    hmac_sig = event.details.get('_hmac')
                    if hmac_sig:
                        event_data = json.dumps({
                            'id': event.id,
                            'checksum': event.checksum,
                            'timestamp': event.timestamp.isoformat()
                        }, sort_keys=True)
                        
                        expected_hmac = hmac.new(
                            self.integrity_key,
                            event_data.encode(),
                            hashlib.sha256
                        ).hexdigest()
                        
                        if hmac.compare_digest(hmac_sig, expected_hmac):
                            valid_events += 1
                        else:
                            corrupted_events.append(event.id)
                    else:
                        valid_events += 1
                else:
                    corrupted_events.append(event.id)
            
            return {
                'total_events': total_events,
                'valid_events': valid_events,
                'corrupted_events': corrupted_events,
                'integrity_rate': valid_events / total_events if total_events > 0 else 1.0
            }
    
    def export_audit_trail(self, 
                          format: str = 'json',
                          include_signatures: bool = True) -> str:
        """Export audit trail in specified format."""
        with self._lock:
            events_data = []
            
            for event in self.audit_events:
                event_dict = {
                    'id': event.id,
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type.value,
                    'regulation': event.regulation.value,
                    'user_id': event.user_id,
                    'client_ip': event.client_ip,
                    'resource': event.resource,
                    'action': event.action,
                    'outcome': event.outcome,
                    'details': event.details,
                    'data_categories': [cat.value for cat in event.data_categories],
                    'compliance_status': event.compliance_status.value,
                    'session_id': event.session_id,
                    'request_id': event.request_id
                }
                
                if include_signatures:
                    event_dict['checksum'] = event.checksum
                
                events_data.append(event_dict)
            
            if format.lower() == 'json':
                return json.dumps(events_data, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported export format: {format}")


class PolicyEnforcementEngine:
    """Automated policy enforcement for compliance regulations."""
    
    def __init__(self):
        self.policies: Dict[str, DataPrivacyPolicy] = {}
        self.enforcement_rules: Dict[ComplianceRegulation, List[Callable]] = {}
        self._lock = RLock()
        self.enforcement_stats = defaultdict(int)
    
    def register_policy(self, policy: DataPrivacyPolicy):
        """Register a data privacy policy."""
        with self._lock:
            self.policies[policy.id] = policy
            logger.info(f"Registered privacy policy {policy.id} for {policy.regulation.value}")
    
    def register_enforcement_rule(self, regulation: ComplianceRegulation, rule_func: Callable):
        """Register custom enforcement rule."""
        with self._lock:
            if regulation not in self.enforcement_rules:
                self.enforcement_rules[regulation] = []
            self.enforcement_rules[regulation].append(rule_func)
    
    def enforce_policies(self, 
                        request: Request,
                        data: Dict[str, Any],
                        data_categories: List[DataCategory]) -> Dict[str, Any]:
        """Enforce privacy policies on data."""
        with self._lock:
            processed_data = data.copy()
            enforcement_actions = []
            
            for policy in self.policies.values():
                if not policy.is_active:
                    continue
                
                if policy.data_category in data_categories:
                    # Apply privacy actions
                    for action in policy.privacy_actions:
                        if action == PrivacyAction.ANONYMIZE:
                            processed_data = self._anonymize_data(processed_data, policy)
                            enforcement_actions.append(f"Anonymized data per {policy.id}")
                        
                        elif action == PrivacyAction.PSEUDONYMIZE:
                            processed_data = self._pseudonymize_data(processed_data, policy)
                            enforcement_actions.append(f"Pseudonymized data per {policy.id}")
                        
                        elif action == PrivacyAction.ENCRYPT:
                            processed_data = self._encrypt_sensitive_fields(processed_data, policy)
                            enforcement_actions.append(f"Encrypted sensitive fields per {policy.id}")
                        
                        elif action == PrivacyAction.REDACT:
                            processed_data = self._redact_sensitive_data(processed_data, policy)
                            enforcement_actions.append(f"Redacted sensitive data per {policy.id}")
                        
                        elif action == PrivacyAction.REQUIRE_CONSENT:
                            if not self._has_valid_consent(request, policy):
                                raise HTTPException(
                                    status_code=403,
                                    detail=f"Valid consent required for {policy.data_category.value} processing"
                                )
                        
                        self.enforcement_stats[f"{policy.regulation.value}_{action.value}"] += 1
            
            # Apply custom enforcement rules
            for regulation, rules in self.enforcement_rules.items():
                for rule_func in rules:
                    try:
                        processed_data = rule_func(request, processed_data, data_categories)
                    except Exception as e:
                        logger.error(f"Enforcement rule failed: {e}")
            
            # Add enforcement metadata
            if enforcement_actions:
                processed_data['_compliance_actions'] = enforcement_actions
            
            return processed_data
    
    def _anonymize_data(self, data: Dict[str, Any], policy: DataPrivacyPolicy) -> Dict[str, Any]:
        """Anonymize data according to policy rules."""
        anonymized = data.copy()
        
        for field, rule in policy.anonymization_rules.items():
            if field in anonymized:
                if rule == 'hash':
                    anonymized[field] = hashlib.sha256(str(anonymized[field]).encode()).hexdigest()[:16]
                elif rule == 'remove':
                    del anonymized[field]
                elif rule == 'generalize':
                    # Simple generalization - replace with category
                    anonymized[field] = f"[{policy.data_category.value}]"
        
        return anonymized
    
    def _pseudonymize_data(self, data: Dict[str, Any], policy: DataPrivacyPolicy) -> Dict[str, Any]:
        """Pseudonymize data while maintaining relationships."""
        pseudonymized = data.copy()
        
        for field, rule in policy.anonymization_rules.items():
            if field in pseudonymized:
                if rule == 'hash':
                    # Use consistent hashing for pseudonymization
                    hash_input = f"{policy.id}-{str(pseudonymized[field])}"
                    pseudonymized[field] = hashlib.md5(hash_input.encode()).hexdigest()[:12]
                elif rule == 'mask':
                    value = str(pseudonymized[field])
                    if len(value) > 4:
                        pseudonymized[field] = value[:2] + '*' * (len(value) - 4) + value[-2:]
        
        return pseudonymized
    
    def _encrypt_sensitive_fields(self, data: Dict[str, Any], policy: DataPrivacyPolicy) -> Dict[str, Any]:
        """Encrypt sensitive fields (simplified encryption for demo)."""
        encrypted = data.copy()
        
        sensitive_fields = ['ssn', 'credit_card', 'password', 'medical_record']
        
        for field in sensitive_fields:
            if field in encrypted:
                # In production, use proper encryption (AES, RSA, etc.)
                encrypted[field] = f"[ENCRYPTED:{hashlib.sha256(str(encrypted[field]).encode()).hexdigest()[:16]}]"
        
        return encrypted
    
    def _redact_sensitive_data(self, data: Dict[str, Any], policy: DataPrivacyPolicy) -> Dict[str, Any]:
        """Redact sensitive data for logging/auditing."""
        redacted = data.copy()
        
        for field, rule in policy.anonymization_rules.items():
            if field in redacted and rule == 'redact':
                redacted[field] = '[REDACTED]'
        
        return redacted
    
    def _has_valid_consent(self, request: Request, policy: DataPrivacyPolicy) -> bool:
        """Check if valid consent exists for data processing."""
        if not policy.consent_required:
            return True
        
        consent_header = request.headers.get(f'x-consent-{policy.data_category.value}')
        return bool(consent_header and consent_header.lower() == 'granted')
    
    def get_enforcement_stats(self) -> Dict[str, int]:
        """Get policy enforcement statistics."""
        with self._lock:
            return dict(self.enforcement_stats)


class ComplianceDashboard:
    """Compliance monitoring and reporting dashboard."""
    
    def __init__(self, audit_manager: AuditTrailManager):
        self.audit_manager = audit_manager
        self.violations: Dict[str, ComplianceViolation] = {}
        self._lock = RLock()
    
    def record_violation(self, violation: ComplianceViolation):
        """Record a compliance violation."""
        with self._lock:
            self.violations[violation.id] = violation
            logger.warning(f"Recorded compliance violation {violation.id}: {violation.violation_details}")
    
    def generate_compliance_report(self, 
                                  regulation: Optional[ComplianceRegulation] = None,
                                  time_range: Optional[Tuple[datetime, datetime]] = None) -> Dict[str, Any]:
        """Generate comprehensive compliance report."""
        with self._lock:
            # Get audit events for analysis
            start_time, end_time = time_range if time_range else (None, None)
            events = self.audit_manager.get_events(
                regulation=regulation,
                start_time=start_time,
                end_time=end_time
            )
            
            # Analyze events
            event_stats = defaultdict(int)
            status_counts = defaultdict(int)
            violation_severity = defaultdict(int)
            
            for event in events:
                event_stats[event.event_type.value] += 1
                status_counts[event.compliance_status.value] += 1
            
            # Analyze violations
            filtered_violations = []
            for violation in self.violations.values():
                if regulation and violation.regulation != regulation:
                    continue
                if time_range:
                    if violation.timestamp < time_range[0] or violation.timestamp > time_range[1]:
                        continue
                
                filtered_violations.append(violation)
                violation_severity[violation.severity.value] += 1
            
            # Calculate compliance metrics
            total_events = len(events)
            compliant_events = status_counts.get('compliant', 0)
            compliance_rate = compliant_events / total_events if total_events > 0 else 1.0
            
            return {
                'report_generated': datetime.now(timezone.utc).isoformat(),
                'regulation': regulation.value if regulation else 'all',
                'time_range': {
                    'start': start_time.isoformat() if start_time else None,
                    'end': end_time.isoformat() if end_time else None
                },
                'summary': {
                    'total_events': total_events,
                    'compliance_rate': round(compliance_rate * 100, 2),
                    'total_violations': len(filtered_violations),
                    'critical_violations': violation_severity.get('critical', 0)
                },
                'event_breakdown': dict(event_stats),
                'status_distribution': dict(status_counts),
                'violation_severity': dict(violation_severity),
                'recent_violations': [
                    {
                        'id': v.id,
                        'severity': v.severity.value,
                        'details': v.violation_details,
                        'timestamp': v.timestamp.isoformat(),
                        'auto_remediated': v.auto_remediated
                    }
                    for v in sorted(filtered_violations, key=lambda x: x.timestamp, reverse=True)[:10]
                ],
                'audit_trail_integrity': self.audit_manager.verify_audit_trail_integrity()
            }
    
    def get_compliance_metrics(self) -> ComplianceMetrics:
        """Get current compliance metrics."""
        events = self.audit_manager.get_events()
        
        metrics = ComplianceMetrics()
        metrics.total_requests_evaluated = len(events)
        metrics.audit_events_generated = len(events)
        
        for event in events:
            if event.compliance_status == ComplianceStatus.COMPLIANT:
                metrics.compliant_requests += 1
            elif event.compliance_status == ComplianceStatus.NON_COMPLIANT:
                metrics.non_compliant_requests += 1
            
            if event.event_type == AuditEventType.POLICY_VIOLATION:
                metrics.policy_violations += 1
            elif event.event_type == AuditEventType.ANONYMIZATION:
                metrics.data_anonymizations += 1
            elif event.event_type == AuditEventType.USER_CONSENT:
                metrics.consent_requests += 1
            elif event.event_type == AuditEventType.DATA_RETENTION:
                metrics.retention_policies_applied += 1
        
        return metrics


class ComplianceFramework:
    """Main compliance framework orchestrating all compliance components."""
    
    def __init__(self, 
                 enabled_regulations: List[ComplianceRegulation] = None,
                 audit_retention_days: int = 2555):  # 7 years default
        
        self.enabled_regulations = enabled_regulations or [
            ComplianceRegulation.GDPR,
            ComplianceRegulation.HIPAA,
            ComplianceRegulation.PCI_DSS
        ]
        
        # Initialize core components
        self.audit_manager = AuditTrailManager()
        self.policy_engine = PolicyEnforcementEngine()
        self.dashboard = ComplianceDashboard(self.audit_manager)
        
        # Initialize validators
        self.validators: Dict[ComplianceRegulation, ComplianceValidator] = {}
        self._initialize_validators()
        
        # Initialize compliance rules
        self.compliance_rules: Dict[str, ComplianceRule] = {}
        self._initialize_compliance_rules()
        
        # Initialize default policies
        self._initialize_default_policies()
        
        # Configuration
        self.audit_retention = timedelta(days=audit_retention_days)
        self._lock = RLock()
        
        logger.info(f"Initialized Compliance Framework with regulations: {[r.value for r in self.enabled_regulations]}")
    
    def _initialize_validators(self):
        """Initialize compliance validators."""
        if ComplianceRegulation.GDPR in self.enabled_regulations:
            self.validators[ComplianceRegulation.GDPR] = GDPRValidator()
        
        if ComplianceRegulation.HIPAA in self.enabled_regulations:
            self.validators[ComplianceRegulation.HIPAA] = HIPAAValidator()
        
        if ComplianceRegulation.PCI_DSS in self.enabled_regulations:
            self.validators[ComplianceRegulation.PCI_DSS] = PCIDSSValidator()
    
    def _initialize_compliance_rules(self):
        """Initialize standard compliance rules."""
        # GDPR Rules
        if ComplianceRegulation.GDPR in self.enabled_regulations:
            gdpr_rules = [
                ComplianceRule(
                    id="gdpr_001",
                    regulation=ComplianceRegulation.GDPR,
                    name="Data Processing Consent",
                    description="Valid consent required for personal data processing",
                    requirement="Article 6 - Lawful basis for processing",
                    category="consent",
                    severity=ComplianceSeverity.HIGH,
                    data_categories=[DataCategory.PII],
                    remediation_steps=["Obtain valid consent", "Implement consent management"],
                    references=["GDPR Article 6", "GDPR Article 7"]
                ),
                ComplianceRule(
                    id="gdpr_002",
                    regulation=ComplianceRegulation.GDPR,
                    name="Data Subject Rights",
                    description="Support for data subject access, rectification, erasure rights",
                    requirement="Articles 15-22 - Data subject rights",
                    category="subject_rights",
                    severity=ComplianceSeverity.CRITICAL,
                    data_categories=[DataCategory.PII],
                    remediation_steps=["Implement data subject request handling", "Automate right to erasure"],
                    references=["GDPR Articles 15-22"]
                )
            ]
            
            for rule in gdpr_rules:
                self.compliance_rules[rule.id] = rule
        
        # HIPAA Rules
        if ComplianceRegulation.HIPAA in self.enabled_regulations:
            hipaa_rules = [
                ComplianceRule(
                    id="hipaa_001",
                    regulation=ComplianceRegulation.HIPAA,
                    name="PHI Encryption",
                    description="Protected Health Information must be encrypted in transit and at rest",
                    requirement="164.312(a)(2)(iv) - Encryption and decryption",
                    category="encryption",
                    severity=ComplianceSeverity.CRITICAL,
                    data_categories=[DataCategory.PHI],
                    remediation_steps=["Implement AES-256 encryption", "Enable TLS 1.3"],
                    references=["45 CFR 164.312"]
                )
            ]
            
            for rule in hipaa_rules:
                self.compliance_rules[rule.id] = rule
        
        # PCI-DSS Rules
        if ComplianceRegulation.PCI_DSS in self.enabled_regulations:
            pci_rules = [
                ComplianceRule(
                    id="pci_001",
                    regulation=ComplianceRegulation.PCI_DSS,
                    name="Cardholder Data Protection",
                    description="Protect stored cardholder data",
                    requirement="Requirement 3 - Protect stored cardholder data",
                    category="data_protection",
                    severity=ComplianceSeverity.CRITICAL,
                    data_categories=[DataCategory.PCI],
                    remediation_steps=["Encrypt cardholder data", "Implement key management"],
                    references=["PCI DSS Requirement 3"]
                )
            ]
            
            for rule in pci_rules:
                self.compliance_rules[rule.id] = rule
    
    def _initialize_default_policies(self):
        """Initialize default privacy policies."""
        # GDPR PII Policy
        if ComplianceRegulation.GDPR in self.enabled_regulations:
            gdpr_pii_policy = DataPrivacyPolicy(
                id="gdpr_pii_default",
                name="GDPR PII Processing Policy",
                regulation=ComplianceRegulation.GDPR,
                data_category=DataCategory.PII,
                privacy_actions=[
                    PrivacyAction.REQUIRE_CONSENT,
                    PrivacyAction.LOG_ACCESS,
                    PrivacyAction.PSEUDONYMIZE,
                    PrivacyAction.APPLY_RETENTION
                ],
                retention_period=timedelta(days=2555),  # 7 years
                access_restrictions={"min_auth_level": "authenticated"},
                consent_required=True,
                anonymization_rules={
                    "email": "hash",
                    "phone": "mask",
                    "ssn": "hash"
                }
            )
            self.policy_engine.register_policy(gdpr_pii_policy)
        
        # HIPAA PHI Policy
        if ComplianceRegulation.HIPAA in self.enabled_regulations:
            hipaa_phi_policy = DataPrivacyPolicy(
                id="hipaa_phi_default",
                name="HIPAA PHI Processing Policy",
                regulation=ComplianceRegulation.HIPAA,
                data_category=DataCategory.PHI,
                privacy_actions=[
                    PrivacyAction.ENCRYPT,
                    PrivacyAction.LOG_ACCESS,
                    PrivacyAction.RESTRICT_ACCESS,
                    PrivacyAction.APPLY_RETENTION
                ],
                retention_period=timedelta(days=2555),  # 7 years
                access_restrictions={"role": "healthcare_provider"},
                consent_required=False,  # Different consent model for healthcare
                anonymization_rules={
                    "patient_id": "hash",
                    "medical_record": "redact",
                    "diagnosis": "redact"
                }
            )
            self.policy_engine.register_policy(hipaa_phi_policy)
        
        # PCI-DSS Cardholder Data Policy
        if ComplianceRegulation.PCI_DSS in self.enabled_regulations:
            pci_policy = DataPrivacyPolicy(
                id="pci_cardholder_default",
                name="PCI-DSS Cardholder Data Policy",
                regulation=ComplianceRegulation.PCI_DSS,
                data_category=DataCategory.PCI,
                privacy_actions=[
                    PrivacyAction.ENCRYPT,
                    PrivacyAction.LOG_ACCESS,
                    PrivacyAction.RESTRICT_ACCESS,
                    PrivacyAction.REDACT
                ],
                retention_period=timedelta(days=365),  # 1 year for payment data
                access_restrictions={"pci_authorized": True},
                consent_required=True,
                anonymization_rules={
                    "credit_card": "redact",
                    "cvv": "remove",
                    "card_holder_name": "mask"
                }
            )
            self.policy_engine.register_policy(pci_policy)
    
    def evaluate_compliance(self, 
                           request: Request,
                           data: Dict[str, Any],
                           data_categories: List[DataCategory]) -> Dict[ComplianceRegulation, ComplianceStatus]:
        """Evaluate compliance across all enabled regulations."""
        results = {}
        
        with self._lock:
            for regulation in self.enabled_regulations:
                if regulation in self.validators:
                    try:
                        status = self.validators[regulation].validate(request, data)
                        results[regulation] = status
                        
                        # Record audit event
                        audit_event = AuditEvent(
                            id=str(uuid.uuid4()),
                            timestamp=datetime.now(timezone.utc),
                            event_type=AuditEventType.COMPLIANCE_CHECK,
                            regulation=regulation,
                            user_id=self._extract_user_id(request),
                            client_ip=self._extract_client_ip(request),
                            resource=str(request.url.path),
                            action="compliance_validation",
                            outcome=status.value,
                            details={
                                "data_categories": [cat.value for cat in data_categories],
                                "validation_result": status.value
                            },
                            data_categories=data_categories,
                            compliance_status=status,
                            session_id=self._extract_session_id(request),
                            request_id=self._extract_request_id(request)
                        )
                        
                        self.audit_manager.record_event(audit_event)
                        
                    except Exception as e:
                        logger.error(f"Compliance validation failed for {regulation.value}: {e}")
                        results[regulation] = ComplianceStatus.UNKNOWN
        
        return results
    
    def enforce_compliance(self, 
                          request: Request,
                          data: Dict[str, Any],
                          data_categories: List[DataCategory]) -> Dict[str, Any]:
        """Enforce compliance policies on data."""
        return self.policy_engine.enforce_policies(request, data, data_categories)
    
    def record_audit_event(self, 
                          event_type: AuditEventType,
                          regulation: ComplianceRegulation,
                          request: Request,
                          resource: str,
                          action: str,
                          outcome: str,
                          details: Dict[str, Any],
                          data_categories: List[DataCategory],
                          compliance_status: ComplianceStatus = ComplianceStatus.COMPLIANT) -> str:
        """Record custom audit event."""
        
        audit_event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            regulation=regulation,
            user_id=self._extract_user_id(request),
            client_ip=self._extract_client_ip(request),
            resource=resource,
            action=action,
            outcome=outcome,
            details=details,
            data_categories=data_categories,
            compliance_status=compliance_status,
            session_id=self._extract_session_id(request),
            request_id=self._extract_request_id(request)
        )
        
        return self.audit_manager.record_event(audit_event)
    
    def get_compliance_report(self, 
                             regulation: Optional[ComplianceRegulation] = None,
                             time_range: Optional[Tuple[datetime, datetime]] = None) -> Dict[str, Any]:
        """Generate compliance report."""
        return self.dashboard.generate_compliance_report(regulation, time_range)
    
    def get_audit_events(self, **filters) -> List[AuditEvent]:
        """Get filtered audit events."""
        return self.audit_manager.get_events(**filters)
    
    def add_compliance_rule(self, rule: ComplianceRule):
        """Add custom compliance rule."""
        with self._lock:
            self.compliance_rules[rule.id] = rule
            logger.info(f"Added compliance rule {rule.id} for {rule.regulation.value}")
    
    def add_privacy_policy(self, policy: DataPrivacyPolicy):
        """Add custom privacy policy."""
        self.policy_engine.register_policy(policy)
    
    def _extract_user_id(self, request: Request) -> Optional[str]:
        """Extract user ID from request."""
        # Try various common headers and patterns
        user_id = (request.headers.get('x-user-id') or
                  request.headers.get('x-authenticated-user') or
                  request.headers.get('x-subject-id'))
        
        # Try to extract from JWT or other auth tokens
        if not user_id:
            auth_header = request.headers.get('authorization', '')
            if 'Bearer' in auth_header:
                # In a real implementation, decode JWT to extract user ID
                user_id = f"jwt_user_{hash(auth_header) % 10000}"
        
        return user_id
    
    def _extract_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check forwarded headers first
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip.strip()
        
        return getattr(request.client, 'host', '127.0.0.1')
    
    def _extract_session_id(self, request: Request) -> Optional[str]:
        """Extract session ID from request."""
        session_id = (request.headers.get('x-session-id') or
                     request.cookies.get('session_id') or
                     request.cookies.get('sessionid'))
        
        if not session_id:
            # Generate deterministic session ID based on client info
            client_info = f"{self._extract_client_ip(request)}-{request.headers.get('user-agent', '')}"
            session_id = hashlib.md5(client_info.encode()).hexdigest()[:16]
        
        return session_id
    
    def _extract_request_id(self, request: Request) -> Optional[str]:
        """Extract request ID from request."""
        return (request.headers.get('x-request-id') or
                request.headers.get('x-correlation-id') or
                str(uuid.uuid4())[:8])


# Convenience functions and decorators

def create_compliance_framework(
    regulations: List[ComplianceRegulation] = None,
    audit_retention_days: int = 2555,
    **kwargs
) -> ComplianceFramework:
    """Create a compliance framework with specified configurations."""
    return ComplianceFramework(
        enabled_regulations=regulations,
        audit_retention_days=audit_retention_days
    )


def compliance_required(*regulations: ComplianceRegulation):
    """Decorator to enforce compliance requirements on endpoints."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args (FastAPI dependency injection)
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                # Try to find request in kwargs
                request = kwargs.get('request')
            
            if not request:
                raise ValueError("Request object not found for compliance validation")
            
            # Initialize framework if not provided
            framework = getattr(func, '_compliance_framework', None)
            if not framework:
                framework = create_compliance_framework(list(regulations))
            
            # Extract data from request (simplified)
            try:
                if hasattr(request, 'json'):
                    data = await request.json()
                else:
                    data = {}
            except:
                data = {}
            
            # Classify data categories (simplified heuristic)
            data_categories = []
            data_str = json.dumps(data, default=str).lower()
            
            if any(keyword in data_str for keyword in ['email', 'name', 'address', 'phone']):
                data_categories.append(DataCategory.PII)
            if any(keyword in data_str for keyword in ['patient', 'medical', 'health', 'diagnosis']):
                data_categories.append(DataCategory.PHI)
            if any(keyword in data_str for keyword in ['card', 'payment', 'cvv', 'expiry']):
                data_categories.append(DataCategory.PCI)
            
            if not data_categories:
                data_categories = [DataCategory.PUBLIC]
            
            # Evaluate compliance
            compliance_results = framework.evaluate_compliance(request, data, data_categories)
            
            # Check if all required regulations are compliant
            for regulation in regulations:
                if regulation in compliance_results:
                    if compliance_results[regulation] == ComplianceStatus.NON_COMPLIANT:
                        framework.record_audit_event(
                            AuditEventType.ACCESS_DENIED,
                            regulation,
                            request,
                            str(request.url.path),
                            "compliance_check",
                            "denied",
                            {"reason": f"Non-compliant with {regulation.value}"},
                            data_categories,
                            ComplianceStatus.NON_COMPLIANT
                        )
                        
                        raise HTTPException(
                            status_code=403,
                            detail=f"Request does not comply with {regulation.value} requirements"
                        )
            
            # Enforce policies
            if data:
                processed_data = framework.enforce_compliance(request, data, data_categories)
                # Update request data (in a real implementation, this would be more sophisticated)
                kwargs['processed_data'] = processed_data
            
            # Record successful compliance check
            for regulation in regulations:
                framework.record_audit_event(
                    AuditEventType.ACCESS_GRANTED,
                    regulation,
                    request,
                    str(request.url.path),
                    "compliance_check",
                    "granted",
                    {"compliance_status": "passed"},
                    data_categories,
                    ComplianceStatus.COMPLIANT
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def gdpr_compliant(func):
    """Decorator for GDPR compliance."""
    return compliance_required(ComplianceRegulation.GDPR)(func)


def hipaa_compliant(func):
    """Decorator for HIPAA compliance."""
    return compliance_required(ComplianceRegulation.HIPAA)(func)


def pci_compliant(func):
    """Decorator for PCI-DSS compliance."""
    return compliance_required(ComplianceRegulation.PCI_DSS)(func)


class ComplianceMiddleware:
    """FastAPI middleware for automatic compliance checking."""
    
    def __init__(self, 
                 app,
                 framework: ComplianceFramework,
                 auto_enforce: bool = True,
                 excluded_paths: List[str] = None):
        
        self.app = app
        self.framework = framework
        self.auto_enforce = auto_enforce
        self.excluded_paths = excluded_paths or ['/health', '/metrics', '/docs', '/openapi.json']
    
    async def __call__(self, scope, receive, send):
        """ASGI middleware entry point."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # Skip compliance checking for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            await self.app(scope, receive, send)
            return
        
        # Check compliance if auto_enforce is enabled
        if self.auto_enforce:
            try:
                # Extract request data
                data = {}
                if request.method in ['POST', 'PUT', 'PATCH']:
                    try:
                        data = await request.json()
                    except:
                        pass
                
                # Classify data
                data_categories = self._classify_data(data)
                
                # Evaluate compliance
                compliance_results = self.framework.evaluate_compliance(request, data, data_categories)
                
                # Check for non-compliance
                non_compliant_regulations = [
                    reg for reg, status in compliance_results.items()
                    if status == ComplianceStatus.NON_COMPLIANT
                ]
                
                if non_compliant_regulations:
                    # Send compliance error response
                    response = JSONResponse(
                        status_code=403,
                        content={
                            "error": "Compliance violation",
                            "non_compliant_regulations": [reg.value for reg in non_compliant_regulations],
                            "message": "Request violates regulatory compliance requirements"
                        }
                    )
                    await response(scope, receive, send)
                    return
                
                # Enforce policies on data
                if data and data_categories != [DataCategory.PUBLIC]:
                    processed_data = self.framework.enforce_compliance(request, data, data_categories)
                    # In a real implementation, modify the request body
                
            except Exception as e:
                logger.error(f"Compliance middleware error: {e}")
                # Continue without blocking in case of errors
        
        # Continue with the request
        await self.app(scope, receive, send)
    
    def _classify_data(self, data: Dict[str, Any]) -> List[DataCategory]:
        """Classify data categories from request data."""
        if not data:
            return [DataCategory.PUBLIC]
        
        categories = []
        data_str = json.dumps(data, default=str).lower()
        
        # PII indicators
        if any(keyword in data_str for keyword in ['email', 'name', 'address', 'phone', 'ssn']):
            categories.append(DataCategory.PII)
        
        # PHI indicators
        if any(keyword in data_str for keyword in ['patient', 'medical', 'health', 'diagnosis', 'treatment']):
            categories.append(DataCategory.PHI)
        
        # PCI indicators
        if any(keyword in data_str for keyword in ['card', 'payment', 'cvv', 'credit']):
            categories.append(DataCategory.PCI)
        
        # Sensitive indicators
        if any(keyword in data_str for keyword in ['password', 'secret', 'confidential']):
            categories.append(DataCategory.SENSITIVE)
        
        return categories if categories else [DataCategory.PUBLIC]


# Export all public classes and functions
__all__ = [
    # Enums
    'ComplianceRegulation',
    'ComplianceStatus', 
    'AuditEventType',
    'DataCategory',
    'PrivacyAction',
    'ComplianceSeverity',
    
    # Data classes
    'ComplianceRule',
    'AuditEvent',
    'ComplianceViolation',
    'DataPrivacyPolicy',
    'ComplianceMetrics',
    
    # Core classes
    'ComplianceValidator',
    'GDPRValidator',
    'HIPAAValidator', 
    'PCIDSSValidator',
    'AuditTrailManager',
    'PolicyEnforcementEngine',
    'ComplianceDashboard',
    'ComplianceFramework',
    'ComplianceMiddleware',
    
    # Convenience functions
    'create_compliance_framework',
    'compliance_required',
    'gdpr_compliant',
    'hipaa_compliant', 
    'pci_compliant',
]