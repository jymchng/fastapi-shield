"""FastAPI-Shield Advanced Security Compliance and Governance Framework

This module provides a comprehensive security compliance and governance framework
that enables automated compliance monitoring, governance policy enforcement,
regulatory audit trails, and continuous compliance assessment across multiple
security frameworks and regulatory requirements.

Features:
- Multi-framework compliance engine (SOC 2, ISO 27001, NIST, GDPR, HIPAA, PCI DSS)
- Governance policy management with dynamic enforcement
- Automated compliance assessment and continuous monitoring
- Risk management integration with threat correlation
- Immutable audit trail and evidence management
- Automated control testing and effectiveness assessment
- Regulatory change management and impact assessment
- Third-party risk management and vendor assessment
- Executive reporting and compliance analytics
- Integration with major GRC platforms and regulatory systems
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
import re
import threading
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    NamedTuple, Protocol, AsyncIterator, TypeVar, Generic, Awaitable
)
import sqlite3
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
import csv
from io import StringIO, BytesIO
import zipfile

logger = logging.getLogger(__name__)

T = TypeVar('T')


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    SOC2_TYPE1 = "soc2_type1"
    SOC2_TYPE2 = "soc2_type2"
    ISO27001 = "iso27001"
    ISO27002 = "iso27002"
    NIST_CSF = "nist_csf"
    NIST_800_53 = "nist_800_53"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    FEDRAMP = "fedramp"
    COBIT = "cobit"
    COSO = "coso"


class ControlStatus(Enum):
    """Security control implementation status."""
    NOT_IMPLEMENTED = "not_implemented"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    OPERATING_EFFECTIVELY = "operating_effectively"
    NEEDS_IMPROVEMENT = "needs_improvement"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class RiskLevel(Enum):
    """Risk assessment levels."""
    VERY_LOW = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4
    CRITICAL = 5


class PolicyType(Enum):
    """Types of governance policies."""
    SECURITY_POLICY = "security_policy"
    DATA_GOVERNANCE = "data_governance"
    ACCESS_CONTROL = "access_control"
    INCIDENT_RESPONSE = "incident_response"
    BUSINESS_CONTINUITY = "business_continuity"
    VENDOR_MANAGEMENT = "vendor_management"
    CHANGE_MANAGEMENT = "change_management"
    TRAINING_AWARENESS = "training_awareness"


class AuditEventType(Enum):
    """Types of audit events."""
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_VIOLATED = "policy_violated"
    CONTROL_TESTED = "control_tested"
    CONTROL_FAILED = "control_failed"
    RISK_IDENTIFIED = "risk_identified"
    RISK_MITIGATED = "risk_mitigated"
    COMPLIANCE_ASSESSED = "compliance_assessed"
    AUDIT_PERFORMED = "audit_performed"
    EVIDENCE_COLLECTED = "evidence_collected"


class ComplianceStatus(Enum):
    """Overall compliance status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_ASSESSED = "not_assessed"
    REMEDIATION_REQUIRED = "remediation_required"


@dataclass
class SecurityControl:
    """Security control definition and assessment."""
    control_id: str
    framework: ComplianceFramework
    control_family: str
    control_name: str
    control_description: str
    implementation_guidance: str
    testing_procedures: str
    status: ControlStatus
    risk_rating: RiskLevel
    owner: str
    implementation_date: Optional[datetime] = None
    last_tested: Optional[datetime] = None
    next_test_date: Optional[datetime] = None
    test_frequency_days: int = 365
    evidence_artifacts: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    remediation_plan: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'control_id': self.control_id,
            'framework': self.framework.value,
            'control_family': self.control_family,
            'control_name': self.control_name,
            'control_description': self.control_description,
            'implementation_guidance': self.implementation_guidance,
            'testing_procedures': self.testing_procedures,
            'status': self.status.value,
            'risk_rating': self.risk_rating.value,
            'owner': self.owner,
            'implementation_date': self.implementation_date.isoformat() if self.implementation_date else None,
            'last_tested': self.last_tested.isoformat() if self.last_tested else None,
            'next_test_date': self.next_test_date.isoformat() if self.next_test_date else None,
            'test_frequency_days': self.test_frequency_days,
            'evidence_artifacts': self.evidence_artifacts,
            'findings': self.findings,
            'remediation_plan': self.remediation_plan,
            'metadata': self.metadata
        }


@dataclass
class GovernancePolicy:
    """Governance policy definition."""
    policy_id: str
    policy_name: str
    policy_type: PolicyType
    description: str
    policy_statement: str
    scope: str
    roles_responsibilities: Dict[str, List[str]]
    enforcement_rules: Dict[str, Any]
    exceptions: List[Dict[str, Any]]
    version: str
    effective_date: datetime
    review_date: datetime
    approval_status: str
    approved_by: str
    owner: str
    created_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_modified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = field(default_factory=list)
    related_controls: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'policy_id': self.policy_id,
            'policy_name': self.policy_name,
            'policy_type': self.policy_type.value,
            'description': self.description,
            'policy_statement': self.policy_statement,
            'scope': self.scope,
            'roles_responsibilities': self.roles_responsibilities,
            'enforcement_rules': self.enforcement_rules,
            'exceptions': self.exceptions,
            'version': self.version,
            'effective_date': self.effective_date.isoformat(),
            'review_date': self.review_date.isoformat(),
            'approval_status': self.approval_status,
            'approved_by': self.approved_by,
            'owner': self.owner,
            'created_date': self.created_date.isoformat(),
            'last_modified': self.last_modified.isoformat(),
            'tags': self.tags,
            'related_controls': self.related_controls
        }


@dataclass
class RiskAssessment:
    """Risk assessment record."""
    risk_id: str
    risk_name: str
    risk_description: str
    risk_category: str
    threat_sources: List[str]
    vulnerabilities: List[str]
    impact_description: str
    likelihood_description: str
    inherent_risk_level: RiskLevel
    residual_risk_level: RiskLevel
    risk_owner: str
    mitigation_controls: List[str]
    mitigation_plan: Dict[str, Any]
    assessment_date: datetime
    review_date: datetime
    status: str = "active"
    business_impact: Dict[str, Any] = field(default_factory=dict)
    regulatory_implications: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'risk_id': self.risk_id,
            'risk_name': self.risk_name,
            'risk_description': self.risk_description,
            'risk_category': self.risk_category,
            'threat_sources': self.threat_sources,
            'vulnerabilities': self.vulnerabilities,
            'impact_description': self.impact_description,
            'likelihood_description': self.likelihood_description,
            'inherent_risk_level': self.inherent_risk_level.value,
            'residual_risk_level': self.residual_risk_level.value,
            'risk_owner': self.risk_owner,
            'mitigation_controls': self.mitigation_controls,
            'mitigation_plan': self.mitigation_plan,
            'assessment_date': self.assessment_date.isoformat(),
            'review_date': self.review_date.isoformat(),
            'status': self.status,
            'business_impact': self.business_impact,
            'regulatory_implications': self.regulatory_implications
        }


@dataclass
class AuditEvent:
    """Immutable audit trail event."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    user_id: str
    source_ip: str
    resource: str
    action: str
    result: str
    details: Dict[str, Any]
    risk_level: RiskLevel = RiskLevel.LOW
    compliance_impact: bool = False
    digital_signature: str = ""
    
    def __post_init__(self):
        """Generate digital signature after initialization."""
        if not self.digital_signature:
            self.digital_signature = self._generate_signature()
    
    def _generate_signature(self) -> str:
        """Generate digital signature for audit event integrity."""
        data_to_sign = f"{self.event_id}{self.timestamp.isoformat()}{self.user_id}{self.resource}{self.action}{self.result}"
        signature = hashlib.sha256(data_to_sign.encode()).hexdigest()
        return signature
    
    def verify_integrity(self) -> bool:
        """Verify audit event integrity."""
        expected_signature = self._generate_signature()
        return hmac.compare_digest(self.digital_signature, expected_signature)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'source_ip': self.source_ip,
            'resource': self.resource,
            'action': self.action,
            'result': self.result,
            'details': self.details,
            'risk_level': self.risk_level.value,
            'compliance_impact': self.compliance_impact,
            'digital_signature': self.digital_signature
        }


@dataclass
class ComplianceAssessment:
    """Compliance framework assessment results."""
    assessment_id: str
    framework: ComplianceFramework
    assessment_date: datetime
    assessor: str
    scope: str
    overall_status: ComplianceStatus
    controls_assessed: int
    controls_compliant: int
    controls_non_compliant: int
    control_results: Dict[str, ControlStatus]
    findings: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    next_assessment_date: datetime
    certification_status: str = "pending"
    risk_score: float = 0.0
    maturity_level: int = 1
    
    def calculate_compliance_percentage(self) -> float:
        """Calculate compliance percentage."""
        if self.controls_assessed == 0:
            return 0.0
        return (self.controls_compliant / self.controls_assessed) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'assessment_id': self.assessment_id,
            'framework': self.framework.value,
            'assessment_date': self.assessment_date.isoformat(),
            'assessor': self.assessor,
            'scope': self.scope,
            'overall_status': self.overall_status.value,
            'controls_assessed': self.controls_assessed,
            'controls_compliant': self.controls_compliant,
            'controls_non_compliant': self.controls_non_compliant,
            'control_results': {k: v.value for k, v in self.control_results.items()},
            'findings': self.findings,
            'recommendations': self.recommendations,
            'next_assessment_date': self.next_assessment_date.isoformat(),
            'certification_status': self.certification_status,
            'risk_score': self.risk_score,
            'maturity_level': self.maturity_level,
            'compliance_percentage': self.calculate_compliance_percentage()
        }


class ComplianceGovernanceDatabase:
    """Database for compliance and governance framework data."""
    
    def __init__(self, db_path: str = "compliance_governance.db"):
        self.db_path = db_path
        self._lock = RLock()
        self._init_database()
        logger.info(f"Compliance Governance Database initialized at {db_path}")
    
    def _init_database(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            # Security controls table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_controls (
                    control_id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    control_family TEXT,
                    control_name TEXT NOT NULL,
                    control_description TEXT,
                    implementation_guidance TEXT,
                    testing_procedures TEXT,
                    status TEXT NOT NULL,
                    risk_rating INTEGER,
                    owner TEXT,
                    implementation_date TIMESTAMP,
                    last_tested TIMESTAMP,
                    next_test_date TIMESTAMP,
                    test_frequency_days INTEGER,
                    evidence_artifacts TEXT,
                    findings TEXT,
                    remediation_plan TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Governance policies table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS governance_policies (
                    policy_id TEXT PRIMARY KEY,
                    policy_name TEXT NOT NULL,
                    policy_type TEXT NOT NULL,
                    description TEXT,
                    policy_statement TEXT,
                    scope TEXT,
                    roles_responsibilities TEXT,
                    enforcement_rules TEXT,
                    exceptions TEXT,
                    version TEXT,
                    effective_date TIMESTAMP,
                    review_date TIMESTAMP,
                    approval_status TEXT,
                    approved_by TEXT,
                    owner TEXT,
                    created_date TIMESTAMP,
                    last_modified TIMESTAMP,
                    tags TEXT,
                    related_controls TEXT
                )
            """)
            
            # Risk assessments table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS risk_assessments (
                    risk_id TEXT PRIMARY KEY,
                    risk_name TEXT NOT NULL,
                    risk_description TEXT,
                    risk_category TEXT,
                    threat_sources TEXT,
                    vulnerabilities TEXT,
                    impact_description TEXT,
                    likelihood_description TEXT,
                    inherent_risk_level INTEGER,
                    residual_risk_level INTEGER,
                    risk_owner TEXT,
                    mitigation_controls TEXT,
                    mitigation_plan TEXT,
                    assessment_date TIMESTAMP,
                    review_date TIMESTAMP,
                    status TEXT,
                    business_impact TEXT,
                    regulatory_implications TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Audit events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    user_id TEXT NOT NULL,
                    source_ip TEXT,
                    resource TEXT,
                    action TEXT,
                    result TEXT,
                    details TEXT,
                    risk_level INTEGER,
                    compliance_impact BOOLEAN,
                    digital_signature TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Compliance assessments table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    assessment_date TIMESTAMP,
                    assessor TEXT,
                    scope TEXT,
                    overall_status TEXT,
                    controls_assessed INTEGER,
                    controls_compliant INTEGER,
                    controls_non_compliant INTEGER,
                    control_results TEXT,
                    findings TEXT,
                    recommendations TEXT,
                    next_assessment_date TIMESTAMP,
                    certification_status TEXT,
                    risk_score REAL,
                    maturity_level INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Framework mappings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS framework_mappings (
                    mapping_id TEXT PRIMARY KEY,
                    source_framework TEXT NOT NULL,
                    source_control_id TEXT NOT NULL,
                    target_framework TEXT NOT NULL,
                    target_control_id TEXT NOT NULL,
                    mapping_type TEXT,
                    confidence_level REAL,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Compliance metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_metrics (
                    metric_id TEXT PRIMARY KEY,
                    framework TEXT,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    metric_type TEXT,
                    measurement_date TIMESTAMP,
                    trend_direction TEXT,
                    target_value REAL,
                    status TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Regulatory updates table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS regulatory_updates (
                    update_id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    update_title TEXT NOT NULL,
                    update_description TEXT,
                    update_type TEXT,
                    effective_date TIMESTAMP,
                    impact_assessment TEXT,
                    affected_controls TEXT,
                    implementation_plan TEXT,
                    status TEXT,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Third party assessments table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS third_party_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    vendor_name TEXT NOT NULL,
                    vendor_type TEXT,
                    assessment_date TIMESTAMP,
                    assessor TEXT,
                    risk_rating INTEGER,
                    security_score REAL,
                    compliance_frameworks TEXT,
                    findings TEXT,
                    recommendations TEXT,
                    contract_requirements TEXT,
                    next_review_date TIMESTAMP,
                    status TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_controls_framework ON security_controls(framework)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_controls_status ON security_controls(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_controls_owner ON security_controls(owner)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_policies_type ON governance_policies(policy_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_policies_status ON governance_policies(approval_status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risks_level ON risk_assessments(residual_risk_level)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risks_owner ON risk_assessments(risk_owner)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assessments_framework ON compliance_assessments(framework)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assessments_date ON compliance_assessments(assessment_date)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_framework ON compliance_metrics(framework)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_date ON compliance_metrics(measurement_date)")
            
            conn.commit()
    
    def store_security_control(self, control: SecurityControl) -> bool:
        """Store security control."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO security_controls
                        (control_id, framework, control_family, control_name, control_description,
                         implementation_guidance, testing_procedures, status, risk_rating, owner,
                         implementation_date, last_tested, next_test_date, test_frequency_days,
                         evidence_artifacts, findings, remediation_plan, metadata, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        control.control_id,
                        control.framework.value,
                        control.control_family,
                        control.control_name,
                        control.control_description,
                        control.implementation_guidance,
                        control.testing_procedures,
                        control.status.value,
                        control.risk_rating.value,
                        control.owner,
                        control.implementation_date,
                        control.last_tested,
                        control.next_test_date,
                        control.test_frequency_days,
                        json.dumps(control.evidence_artifacts),
                        json.dumps(control.findings),
                        json.dumps(control.remediation_plan),
                        json.dumps(control.metadata),
                        datetime.now(timezone.utc)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing security control: {e}")
                return False
    
    def store_governance_policy(self, policy: GovernancePolicy) -> bool:
        """Store governance policy."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO governance_policies
                        (policy_id, policy_name, policy_type, description, policy_statement,
                         scope, roles_responsibilities, enforcement_rules, exceptions, version,
                         effective_date, review_date, approval_status, approved_by, owner,
                         created_date, last_modified, tags, related_controls)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        policy.policy_id,
                        policy.policy_name,
                        policy.policy_type.value,
                        policy.description,
                        policy.policy_statement,
                        policy.scope,
                        json.dumps(policy.roles_responsibilities),
                        json.dumps(policy.enforcement_rules),
                        json.dumps(policy.exceptions),
                        policy.version,
                        policy.effective_date,
                        policy.review_date,
                        policy.approval_status,
                        policy.approved_by,
                        policy.owner,
                        policy.created_date,
                        policy.last_modified,
                        json.dumps(policy.tags),
                        json.dumps(policy.related_controls)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing governance policy: {e}")
                return False
    
    def store_risk_assessment(self, risk: RiskAssessment) -> bool:
        """Store risk assessment."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO risk_assessments
                        (risk_id, risk_name, risk_description, risk_category, threat_sources,
                         vulnerabilities, impact_description, likelihood_description,
                         inherent_risk_level, residual_risk_level, risk_owner, mitigation_controls,
                         mitigation_plan, assessment_date, review_date, status, business_impact,
                         regulatory_implications)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        risk.risk_id,
                        risk.risk_name,
                        risk.risk_description,
                        risk.risk_category,
                        json.dumps(risk.threat_sources),
                        json.dumps(risk.vulnerabilities),
                        risk.impact_description,
                        risk.likelihood_description,
                        risk.inherent_risk_level.value,
                        risk.residual_risk_level.value,
                        risk.risk_owner,
                        json.dumps(risk.mitigation_controls),
                        json.dumps(risk.mitigation_plan),
                        risk.assessment_date,
                        risk.review_date,
                        risk.status,
                        json.dumps(risk.business_impact),
                        json.dumps(risk.regulatory_implications)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing risk assessment: {e}")
                return False
    
    def store_audit_event(self, event: AuditEvent) -> bool:
        """Store audit event."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO audit_events
                        (event_id, event_type, timestamp, user_id, source_ip, resource,
                         action, result, details, risk_level, compliance_impact, digital_signature)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id,
                        event.event_type.value,
                        event.timestamp,
                        event.user_id,
                        event.source_ip,
                        event.resource,
                        event.action,
                        event.result,
                        json.dumps(event.details),
                        event.risk_level.value,
                        event.compliance_impact,
                        event.digital_signature
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing audit event: {e}")
                return False
    
    def store_compliance_assessment(self, assessment: ComplianceAssessment) -> bool:
        """Store compliance assessment."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO compliance_assessments
                        (assessment_id, framework, assessment_date, assessor, scope, overall_status,
                         controls_assessed, controls_compliant, controls_non_compliant,
                         control_results, findings, recommendations, next_assessment_date,
                         certification_status, risk_score, maturity_level)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        assessment.assessment_id,
                        assessment.framework.value,
                        assessment.assessment_date,
                        assessment.assessor,
                        assessment.scope,
                        assessment.overall_status.value,
                        assessment.controls_assessed,
                        assessment.controls_compliant,
                        assessment.controls_non_compliant,
                        json.dumps({k: v.value for k, v in assessment.control_results.items()}),
                        json.dumps(assessment.findings),
                        json.dumps(assessment.recommendations),
                        assessment.next_assessment_date,
                        assessment.certification_status,
                        assessment.risk_score,
                        assessment.maturity_level
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing compliance assessment: {e}")
                return False
    
    def get_security_controls(self, framework: Optional[ComplianceFramework] = None, 
                             status: Optional[ControlStatus] = None, limit: int = 1000) -> List[SecurityControl]:
        """Get security controls with optional filters."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = "SELECT * FROM security_controls WHERE 1=1"
                params = []
                
                if framework:
                    query += " AND framework = ?"
                    params.append(framework.value)
                
                if status:
                    query += " AND status = ?"
                    params.append(status.value)
                
                query += " ORDER BY control_id LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                controls = []
                
                for row in cursor.fetchall():
                    control = SecurityControl(
                        control_id=row[0],
                        framework=ComplianceFramework(row[1]),
                        control_family=row[2] or "",
                        control_name=row[3],
                        control_description=row[4] or "",
                        implementation_guidance=row[5] or "",
                        testing_procedures=row[6] or "",
                        status=ControlStatus(row[7]),
                        risk_rating=RiskLevel(row[8]) if row[8] is not None else RiskLevel.MEDIUM,
                        owner=row[9] or "",
                        implementation_date=datetime.fromisoformat(row[10].replace('Z', '+00:00')) if row[10] else None,
                        last_tested=datetime.fromisoformat(row[11].replace('Z', '+00:00')) if row[11] else None,
                        next_test_date=datetime.fromisoformat(row[12].replace('Z', '+00:00')) if row[12] else None,
                        test_frequency_days=row[13] or 365,
                        evidence_artifacts=json.loads(row[14]) if row[14] else [],
                        findings=json.loads(row[15]) if row[15] else [],
                        remediation_plan=json.loads(row[16]) if row[16] else {},
                        metadata=json.loads(row[17]) if row[17] else {}
                    )
                    controls.append(control)
                
                return controls
                
        except Exception as e:
            logger.error(f"Error retrieving security controls: {e}")
            return []
    
    def get_compliance_assessment(self, assessment_id: str) -> Optional[ComplianceAssessment]:
        """Get compliance assessment by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT * FROM compliance_assessments WHERE assessment_id = ?",
                    (assessment_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    control_results = {}
                    if row[9]:  # control_results
                        control_data = json.loads(row[9])
                        control_results = {k: ControlStatus(v) for k, v in control_data.items()}
                    
                    return ComplianceAssessment(
                        assessment_id=row[0],
                        framework=ComplianceFramework(row[1]),
                        assessment_date=datetime.fromisoformat(row[2].replace('Z', '+00:00')) if isinstance(row[2], str) else row[2],
                        assessor=row[3] or "",
                        scope=row[4] or "",
                        overall_status=ComplianceStatus(row[5]),
                        controls_assessed=row[6] or 0,
                        controls_compliant=row[7] or 0,
                        controls_non_compliant=row[8] or 0,
                        control_results=control_results,
                        findings=json.loads(row[10]) if row[10] else [],
                        recommendations=json.loads(row[11]) if row[11] else [],
                        next_assessment_date=datetime.fromisoformat(row[12].replace('Z', '+00:00')) if isinstance(row[12], str) else row[12],
                        certification_status=row[13] or "pending",
                        risk_score=row[14] or 0.0,
                        maturity_level=row[15] or 1
                    )
                    
        except Exception as e:
            logger.error(f"Error retrieving compliance assessment: {e}")
        
        return None


class ComplianceEngine:
    """Multi-framework compliance monitoring and assessment engine."""
    
    def __init__(self, database: ComplianceGovernanceDatabase):
        self.database = database
        self.framework_controls = {}
        self.compliance_rules = {}
        self.assessment_schedules = {}
        
        self._initialize_framework_controls()
        logger.info("ComplianceEngine initialized")
    
    def _initialize_framework_controls(self):
        """Initialize framework-specific controls and mappings."""
        self.framework_controls = {
            ComplianceFramework.SOC2_TYPE2: self._get_soc2_controls(),
            ComplianceFramework.ISO27001: self._get_iso27001_controls(),
            ComplianceFramework.NIST_CSF: self._get_nist_csf_controls(),
            ComplianceFramework.GDPR: self._get_gdpr_controls(),
            ComplianceFramework.HIPAA: self._get_hipaa_controls(),
            ComplianceFramework.PCI_DSS: self._get_pci_dss_controls()
        }
    
    def _get_soc2_controls(self) -> List[Dict[str, Any]]:
        """Get SOC 2 Type II trust service criteria controls."""
        return [
            {
                'control_id': 'CC1.1',
                'control_family': 'Control Environment',
                'control_name': 'Integrity and Ethical Values',
                'description': 'The entity demonstrates a commitment to integrity and ethical values.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 365
            },
            {
                'control_id': 'CC2.1',
                'control_family': 'Communication and Information',
                'control_name': 'Information Quality',
                'description': 'The entity obtains or generates and uses relevant, quality information.',
                'risk_rating': RiskLevel.MEDIUM,
                'test_frequency_days': 180
            },
            {
                'control_id': 'CC3.1',
                'control_family': 'Risk Assessment',
                'control_name': 'Risk Identification',
                'description': 'The entity specifies objectives with sufficient clarity.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 365
            },
            {
                'control_id': 'CC6.1',
                'control_family': 'Logical and Physical Access Controls',
                'control_name': 'Access Control',
                'description': 'The entity implements logical access security software.',
                'risk_rating': RiskLevel.CRITICAL,
                'test_frequency_days': 90
            },
            {
                'control_id': 'CC7.1',
                'control_family': 'System Operations',
                'control_name': 'System Monitoring',
                'description': 'The entity monitors system components and operation.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 180
            }
        ]
    
    def _get_iso27001_controls(self) -> List[Dict[str, Any]]:
        """Get ISO 27001 security controls."""
        return [
            {
                'control_id': 'A.5.1.1',
                'control_family': 'Information Security Policies',
                'control_name': 'Policies for Information Security',
                'description': 'A set of policies for information security shall be defined.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 365
            },
            {
                'control_id': 'A.6.1.1',
                'control_family': 'Organization of Information Security',
                'control_name': 'Information Security Roles and Responsibilities',
                'description': 'All information security responsibilities shall be defined.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 365
            },
            {
                'control_id': 'A.9.1.1',
                'control_family': 'Access Control',
                'control_name': 'Access Control Policy',
                'description': 'An access control policy shall be established.',
                'risk_rating': RiskLevel.CRITICAL,
                'test_frequency_days': 180
            },
            {
                'control_id': 'A.12.1.1',
                'control_family': 'Operations Security',
                'control_name': 'Documented Operating Procedures',
                'description': 'Operating procedures shall be documented and available.',
                'risk_rating': RiskLevel.MEDIUM,
                'test_frequency_days': 180
            }
        ]
    
    def _get_nist_csf_controls(self) -> List[Dict[str, Any]]:
        """Get NIST Cybersecurity Framework controls."""
        return [
            {
                'control_id': 'ID.AM-1',
                'control_family': 'Identify',
                'control_name': 'Asset Management',
                'description': 'Physical devices and systems are inventoried.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 180
            },
            {
                'control_id': 'PR.AC-1',
                'control_family': 'Protect',
                'control_name': 'Access Control',
                'description': 'Identities and credentials are issued and managed.',
                'risk_rating': RiskLevel.CRITICAL,
                'test_frequency_days': 90
            },
            {
                'control_id': 'DE.AE-1',
                'control_family': 'Detect',
                'control_name': 'Event Detection',
                'description': 'A baseline of network operations is established.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 180
            },
            {
                'control_id': 'RS.RP-1',
                'control_family': 'Respond',
                'control_name': 'Response Planning',
                'description': 'Response plan is executed during or after an incident.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 365
            }
        ]
    
    def _get_gdpr_controls(self) -> List[Dict[str, Any]]:
        """Get GDPR privacy controls."""
        return [
            {
                'control_id': 'GDPR.7',
                'control_family': 'Lawful Basis',
                'control_name': 'Consent',
                'description': 'Consent is obtained and managed for data processing.',
                'risk_rating': RiskLevel.CRITICAL,
                'test_frequency_days': 180
            },
            {
                'control_id': 'GDPR.25',
                'control_family': 'Data Protection by Design',
                'control_name': 'Privacy by Design',
                'description': 'Data protection measures are implemented by design.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 365
            },
            {
                'control_id': 'GDPR.32',
                'control_family': 'Security of Processing',
                'control_name': 'Security Measures',
                'description': 'Appropriate technical and organizational measures.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 180
            }
        ]
    
    def _get_hipaa_controls(self) -> List[Dict[str, Any]]:
        """Get HIPAA security controls."""
        return [
            {
                'control_id': '164.308(a)(1)',
                'control_family': 'Administrative Safeguards',
                'control_name': 'Security Officer',
                'description': 'Assign security responsibility to an individual.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 365
            },
            {
                'control_id': '164.312(a)(1)',
                'control_family': 'Technical Safeguards',
                'control_name': 'Access Control',
                'description': 'Unique user identification and access controls.',
                'risk_rating': RiskLevel.CRITICAL,
                'test_frequency_days': 180
            },
            {
                'control_id': '164.312(e)(1)',
                'control_family': 'Technical Safeguards',
                'control_name': 'Transmission Security',
                'description': 'Guard against unauthorized access to ePHI.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 180
            }
        ]
    
    def _get_pci_dss_controls(self) -> List[Dict[str, Any]]:
        """Get PCI DSS security controls."""
        return [
            {
                'control_id': 'PCI.1.1',
                'control_family': 'Network Security',
                'control_name': 'Firewall Configuration',
                'description': 'Establish and maintain firewall configuration standards.',
                'risk_rating': RiskLevel.CRITICAL,
                'test_frequency_days': 90
            },
            {
                'control_id': 'PCI.2.1',
                'control_family': 'System Security',
                'control_name': 'Default Passwords',
                'description': 'Change vendor-supplied defaults for system passwords.',
                'risk_rating': RiskLevel.HIGH,
                'test_frequency_days': 180
            },
            {
                'control_id': 'PCI.3.4',
                'control_family': 'Data Protection',
                'control_name': 'Cardholder Data Protection',
                'description': 'Render cardholder data unreadable anywhere it is stored.',
                'risk_rating': RiskLevel.CRITICAL,
                'test_frequency_days': 90
            }
        ]
    
    async def initialize_framework_controls(self, framework: ComplianceFramework, owner: str) -> List[str]:
        """Initialize security controls for a compliance framework."""
        try:
            if framework not in self.framework_controls:
                logger.warning(f"Framework {framework.value} not supported")
                return []
            
            control_ids = []
            controls_data = self.framework_controls[framework]
            
            for control_data in controls_data:
                control = SecurityControl(
                    control_id=control_data['control_id'],
                    framework=framework,
                    control_family=control_data['control_family'],
                    control_name=control_data['control_name'],
                    control_description=control_data['description'],
                    implementation_guidance=f"Implement {control_data['control_name']} according to {framework.value} requirements",
                    testing_procedures=f"Test {control_data['control_name']} effectiveness quarterly",
                    status=ControlStatus.NOT_IMPLEMENTED,
                    risk_rating=control_data['risk_rating'],
                    owner=owner,
                    test_frequency_days=control_data['test_frequency_days']
                )
                
                if self.database.store_security_control(control):
                    control_ids.append(control.control_id)
            
            logger.info(f"Initialized {len(control_ids)} controls for {framework.value}")
            return control_ids
            
        except Exception as e:
            logger.error(f"Error initializing framework controls: {e}")
            return []
    
    async def assess_compliance(self, framework: ComplianceFramework, assessor: str, 
                               scope: str = "Full Organization") -> ComplianceAssessment:
        """Perform comprehensive compliance assessment."""
        try:
            assessment_id = f"assessment_{framework.value}_{uuid.uuid4().hex[:12]}"
            
            # Get all controls for the framework
            controls = self.database.get_security_controls(framework=framework)
            
            # Assess each control
            controls_assessed = len(controls)
            controls_compliant = 0
            controls_non_compliant = 0
            control_results = {}
            findings = []
            recommendations = []
            
            for control in controls:
                # Perform automated control assessment
                assessment_result = await self._assess_control(control)
                control_results[control.control_id] = assessment_result['status']
                
                if assessment_result['status'] in [ControlStatus.IMPLEMENTED, ControlStatus.OPERATING_EFFECTIVELY]:
                    controls_compliant += 1
                elif assessment_result['status'] in [ControlStatus.FAILED, ControlStatus.NOT_IMPLEMENTED]:
                    controls_non_compliant += 1
                    findings.append({
                        'control_id': control.control_id,
                        'finding': assessment_result.get('finding', 'Control not properly implemented'),
                        'risk_level': control.risk_rating.value,
                        'remediation': assessment_result.get('remediation', 'Implement control according to requirements')
                    })
                
                # Generate recommendations
                if assessment_result['status'] == ControlStatus.NEEDS_IMPROVEMENT:
                    recommendations.append({
                        'control_id': control.control_id,
                        'recommendation': f"Improve implementation of {control.control_name}",
                        'priority': control.risk_rating.value,
                        'timeline': '30 days'
                    })
            
            # Calculate overall status
            compliance_percentage = (controls_compliant / controls_assessed) * 100 if controls_assessed > 0 else 0
            
            if compliance_percentage >= 95:
                overall_status = ComplianceStatus.COMPLIANT
            elif compliance_percentage >= 80:
                overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
            elif compliance_percentage >= 50:
                overall_status = ComplianceStatus.REMEDIATION_REQUIRED
            else:
                overall_status = ComplianceStatus.NON_COMPLIANT
            
            # Calculate risk score and maturity level
            risk_score = self._calculate_risk_score(controls, control_results)
            maturity_level = self._calculate_maturity_level(controls, control_results)
            
            # Create assessment
            assessment = ComplianceAssessment(
                assessment_id=assessment_id,
                framework=framework,
                assessment_date=datetime.now(timezone.utc),
                assessor=assessor,
                scope=scope,
                overall_status=overall_status,
                controls_assessed=controls_assessed,
                controls_compliant=controls_compliant,
                controls_non_compliant=controls_non_compliant,
                control_results=control_results,
                findings=findings,
                recommendations=recommendations,
                next_assessment_date=datetime.now(timezone.utc) + timedelta(days=365),
                risk_score=risk_score,
                maturity_level=maturity_level
            )
            
            # Store assessment
            self.database.store_compliance_assessment(assessment)
            
            logger.info(f"Completed compliance assessment for {framework.value}: {compliance_percentage:.1f}% compliant")
            return assessment
            
        except Exception as e:
            logger.error(f"Error performing compliance assessment: {e}")
            # Return minimal assessment on error
            return ComplianceAssessment(
                assessment_id=f"error_{uuid.uuid4().hex[:8]}",
                framework=framework,
                assessment_date=datetime.now(timezone.utc),
                assessor=assessor,
                scope=scope,
                overall_status=ComplianceStatus.NOT_ASSESSED,
                controls_assessed=0,
                controls_compliant=0,
                controls_non_compliant=0,
                control_results={},
                findings=[{'error': str(e)}],
                recommendations=[],
                next_assessment_date=datetime.now(timezone.utc) + timedelta(days=30)
            )
    
    async def _assess_control(self, control: SecurityControl) -> Dict[str, Any]:
        """Assess individual security control implementation."""
        try:
            # Simplified control assessment logic
            # In production, this would integrate with various security tools
            
            assessment_result = {
                'status': control.status,
                'finding': '',
                'remediation': '',
                'evidence': []
            }
            
            # Check if control has been implemented
            if control.status == ControlStatus.NOT_IMPLEMENTED:
                assessment_result.update({
                    'status': ControlStatus.NOT_IMPLEMENTED,
                    'finding': f"Control {control.control_id} has not been implemented",
                    'remediation': "Implement control according to framework requirements"
                })
                return assessment_result
            
            # Check if control has evidence
            if not control.evidence_artifacts:
                assessment_result.update({
                    'status': ControlStatus.NEEDS_IMPROVEMENT,
                    'finding': "No evidence artifacts documented for control",
                    'remediation': "Document evidence of control implementation"
                })
                return assessment_result
            
            # Check if control testing is current
            if control.last_tested:
                days_since_test = (datetime.now(timezone.utc) - control.last_tested).days
                if days_since_test > control.test_frequency_days:
                    assessment_result.update({
                        'status': ControlStatus.NEEDS_IMPROVEMENT,
                        'finding': f"Control testing overdue by {days_since_test - control.test_frequency_days} days",
                        'remediation': "Perform control testing according to schedule"
                    })
                    return assessment_result
            
            # If all checks pass, control is operating effectively
            assessment_result.update({
                'status': ControlStatus.OPERATING_EFFECTIVELY,
                'finding': '',
                'remediation': ''
            })
            
            return assessment_result
            
        except Exception as e:
            logger.error(f"Error assessing control {control.control_id}: {e}")
            return {
                'status': ControlStatus.FAILED,
                'finding': f"Assessment error: {str(e)}",
                'remediation': "Review control implementation and resolve assessment issues",
                'evidence': []
            }
    
    def _calculate_risk_score(self, controls: List[SecurityControl], results: Dict[str, ControlStatus]) -> float:
        """Calculate overall risk score based on control assessments."""
        try:
            if not controls:
                return 0.0
            
            total_risk = 0.0
            total_weight = 0.0
            
            for control in controls:
                # Weight by risk rating
                weight = control.risk_rating.value + 1  # 1-6 scale
                total_weight += weight
                
                # Calculate risk based on control status
                control_status = results.get(control.control_id, ControlStatus.NOT_IMPLEMENTED)
                
                if control_status == ControlStatus.OPERATING_EFFECTIVELY:
                    risk_contribution = 0.1  # Very low risk
                elif control_status == ControlStatus.IMPLEMENTED:
                    risk_contribution = 0.3  # Low risk
                elif control_status == ControlStatus.NEEDS_IMPROVEMENT:
                    risk_contribution = 0.6  # Medium risk
                elif control_status == ControlStatus.FAILED:
                    risk_contribution = 0.9  # High risk
                else:  # NOT_IMPLEMENTED
                    risk_contribution = 1.0  # Maximum risk
                
                total_risk += (risk_contribution * weight)
            
            # Normalize to 0-100 scale
            normalized_risk = (total_risk / total_weight) * 100 if total_weight > 0 else 100
            return round(normalized_risk, 2)
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 100.0  # Maximum risk on error
    
    def _calculate_maturity_level(self, controls: List[SecurityControl], results: Dict[str, ControlStatus]) -> int:
        """Calculate security maturity level (1-5 scale)."""
        try:
            if not controls:
                return 1
            
            status_counts = defaultdict(int)
            for control_id, status in results.items():
                status_counts[status] += 1
            
            total_controls = len(controls)
            operating_effectively_pct = (status_counts[ControlStatus.OPERATING_EFFECTIVELY] / total_controls) * 100
            implemented_pct = (status_counts[ControlStatus.IMPLEMENTED] / total_controls) * 100
            
            # Maturity level calculation
            if operating_effectively_pct >= 90:
                return 5  # Optimizing
            elif operating_effectively_pct >= 70:
                return 4  # Managed
            elif implemented_pct >= 50:
                return 3  # Defined
            elif implemented_pct >= 25:
                return 2  # Developing
            else:
                return 1  # Initial
                
        except Exception as e:
            logger.error(f"Error calculating maturity level: {e}")
            return 1


class PolicyManagementSystem:
    """Governance policy creation, enforcement, and lifecycle management."""
    
    def __init__(self, database: ComplianceGovernanceDatabase):
        self.database = database
        self.active_policies = {}
        self.policy_violations = []
        self.enforcement_rules = {}
        
        logger.info("PolicyManagementSystem initialized")
    
    async def create_policy(self, policy_name: str, policy_type: PolicyType, description: str,
                           policy_statement: str, scope: str, owner: str,
                           roles_responsibilities: Dict[str, List[str]] = None,
                           enforcement_rules: Dict[str, Any] = None) -> str:
        """Create new governance policy."""
        try:
            policy_id = f"policy_{policy_type.value}_{uuid.uuid4().hex[:12]}"
            
            policy = GovernancePolicy(
                policy_id=policy_id,
                policy_name=policy_name,
                policy_type=policy_type,
                description=description,
                policy_statement=policy_statement,
                scope=scope,
                roles_responsibilities=roles_responsibilities or {},
                enforcement_rules=enforcement_rules or {},
                exceptions=[],
                version="1.0",
                effective_date=datetime.now(timezone.utc),
                review_date=datetime.now(timezone.utc) + timedelta(days=365),
                approval_status="pending",
                approved_by="",
                owner=owner
            )
            
            # Store policy
            if self.database.store_governance_policy(policy):
                self.active_policies[policy_id] = policy
                logger.info(f"Created governance policy: {policy_id}")
                return policy_id
            else:
                raise Exception("Failed to store policy in database")
                
        except Exception as e:
            logger.error(f"Error creating policy: {e}")
            return ""
    
    async def approve_policy(self, policy_id: str, approved_by: str) -> bool:
        """Approve governance policy for implementation."""
        try:
            if policy_id not in self.active_policies:
                logger.error(f"Policy {policy_id} not found")
                return False
            
            policy = self.active_policies[policy_id]
            policy.approval_status = "approved"
            policy.approved_by = approved_by
            policy.last_modified = datetime.now(timezone.utc)
            
            # Update database
            if self.database.store_governance_policy(policy):
                logger.info(f"Policy {policy_id} approved by {approved_by}")
                return True
            
        except Exception as e:
            logger.error(f"Error approving policy: {e}")
        
        return False
    
    async def enforce_policy(self, policy_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Enforce governance policy against provided context."""
        try:
            if policy_id not in self.active_policies:
                return {'allowed': False, 'reason': 'Policy not found'}
            
            policy = self.active_policies[policy_id]
            
            if policy.approval_status != "approved":
                return {'allowed': True, 'reason': 'Policy not yet approved'}
            
            # Check if policy is in effect
            now = datetime.now(timezone.utc)
            if now < policy.effective_date:
                return {'allowed': True, 'reason': 'Policy not yet effective'}
            
            # Apply enforcement rules
            enforcement_result = await self._apply_enforcement_rules(policy, context)
            
            if not enforcement_result['allowed']:
                # Log policy violation
                await self._log_policy_violation(policy, context, enforcement_result['reason'])
            
            return enforcement_result
            
        except Exception as e:
            logger.error(f"Error enforcing policy: {e}")
            return {'allowed': False, 'reason': f'Policy enforcement error: {str(e)}'}
    
    async def _apply_enforcement_rules(self, policy: GovernancePolicy, context: Dict[str, Any]) -> Dict[str, Any]:
        """Apply specific enforcement rules based on policy type."""
        try:
            rules = policy.enforcement_rules
            
            if policy.policy_type == PolicyType.ACCESS_CONTROL:
                return await self._enforce_access_control_policy(rules, context)
            elif policy.policy_type == PolicyType.DATA_GOVERNANCE:
                return await self._enforce_data_governance_policy(rules, context)
            elif policy.policy_type == PolicyType.SECURITY_POLICY:
                return await self._enforce_security_policy(rules, context)
            elif policy.policy_type == PolicyType.CHANGE_MANAGEMENT:
                return await self._enforce_change_management_policy(rules, context)
            else:
                # Generic enforcement
                return await self._enforce_generic_policy(rules, context)
                
        except Exception as e:
            logger.error(f"Error applying enforcement rules: {e}")
            return {'allowed': False, 'reason': f'Rule application error: {str(e)}'}
    
    async def _enforce_access_control_policy(self, rules: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Enforce access control policy rules."""
        user_id = context.get('user_id', '')
        user_roles = context.get('user_roles', [])
        resource = context.get('resource', '')
        action = context.get('action', '')
        
        # Check required roles
        required_roles = rules.get('required_roles', [])
        if required_roles and not any(role in user_roles for role in required_roles):
            return {'allowed': False, 'reason': f'User lacks required roles: {required_roles}'}
        
        # Check MFA requirements
        mfa_required = rules.get('mfa_required', False)
        if mfa_required and not context.get('mfa_verified', False):
            return {'allowed': False, 'reason': 'Multi-factor authentication required'}
        
        # Check restricted resources
        restricted_resources = rules.get('restricted_resources', [])
        if any(restricted in resource for restricted in restricted_resources):
            if 'admin' not in user_roles:
                return {'allowed': False, 'reason': 'Access to restricted resource requires admin privileges'}
        
        # Check time-based restrictions
        time_restrictions = rules.get('time_restrictions', {})
        if time_restrictions:
            current_hour = datetime.now(timezone.utc).hour
            allowed_hours = time_restrictions.get('allowed_hours', list(range(24)))
            if current_hour not in allowed_hours:
                return {'allowed': False, 'reason': 'Access outside permitted hours'}
        
        return {'allowed': True, 'reason': 'Access control policy satisfied'}
    
    async def _enforce_data_governance_policy(self, rules: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Enforce data governance policy rules."""
        data_classification = context.get('data_classification', 'public')
        user_clearance = context.get('user_clearance', 'public')
        data_location = context.get('data_location', '')
        
        # Check data classification access
        classification_requirements = rules.get('classification_access', {})
        required_clearance = classification_requirements.get(data_classification, 'public')
        
        clearance_hierarchy = {'public': 0, 'internal': 1, 'confidential': 2, 'restricted': 3, 'top_secret': 4}
        if clearance_hierarchy.get(user_clearance, 0) < clearance_hierarchy.get(required_clearance, 0):
            return {'allowed': False, 'reason': f'Insufficient clearance for {data_classification} data'}
        
        # Check data residency requirements
        residency_rules = rules.get('data_residency', {})
        if residency_rules:
            allowed_locations = residency_rules.get('allowed_locations', [])
            if allowed_locations and data_location not in allowed_locations:
                return {'allowed': False, 'reason': f'Data location {data_location} not permitted'}
        
        return {'allowed': True, 'reason': 'Data governance policy satisfied'}
    
    async def _enforce_security_policy(self, rules: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Enforce security policy rules."""
        # Check password requirements
        password_rules = rules.get('password_requirements', {})
        if password_rules and context.get('action') == 'password_change':
            password = context.get('new_password', '')
            
            min_length = password_rules.get('min_length', 8)
            if len(password) < min_length:
                return {'allowed': False, 'reason': f'Password must be at least {min_length} characters'}
            
            require_uppercase = password_rules.get('require_uppercase', False)
            if require_uppercase and not any(c.isupper() for c in password):
                return {'allowed': False, 'reason': 'Password must contain uppercase letters'}
        
        # Check MFA requirements
        mfa_required = rules.get('mfa_required', False)
        if mfa_required and not context.get('mfa_verified', False):
            return {'allowed': False, 'reason': 'Multi-factor authentication required'}
        
        return {'allowed': True, 'reason': 'Security policy satisfied'}
    
    async def _enforce_change_management_policy(self, rules: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Enforce change management policy rules."""
        change_type = context.get('change_type', 'standard')
        change_impact = context.get('change_impact', 'low')
        approvals = context.get('approvals', [])
        
        # Check emergency change procedures first
        if change_type == 'emergency':
            emergency_approver = rules.get('emergency_approver')
            if emergency_approver and emergency_approver not in approvals:
                return {'allowed': False, 'reason': 'Emergency changes require emergency approver authorization'}
            # If emergency approver is present, skip regular approval requirements
            if emergency_approver and emergency_approver in approvals:
                return {'allowed': True, 'reason': 'Emergency change approved by emergency approver'}
        
        # Check regular approval requirements
        approval_requirements = rules.get('approval_requirements', {})
        required_approvers = approval_requirements.get(change_impact, 1)
        
        if len(approvals) < required_approvers:
            return {'allowed': False, 'reason': f'{change_impact} impact changes require {required_approvers} approvals'}
        
        return {'allowed': True, 'reason': 'Change management policy satisfied'}
    
    async def _enforce_generic_policy(self, rules: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Enforce generic policy rules."""
        # Apply basic rule checks
        for rule_name, rule_value in rules.items():
            context_value = context.get(rule_name)
            
            if isinstance(rule_value, list):
                if context_value not in rule_value:
                    return {'allowed': False, 'reason': f'{rule_name} must be one of {rule_value}'}
            elif isinstance(rule_value, bool):
                if bool(context_value) != rule_value:
                    return {'allowed': False, 'reason': f'{rule_name} requirement not met'}
        
        return {'allowed': True, 'reason': 'Generic policy rules satisfied'}
    
    async def _log_policy_violation(self, policy: GovernancePolicy, context: Dict[str, Any], reason: str):
        """Log policy violation for audit trail."""
        try:
            violation_event = AuditEvent(
                event_id=f"violation_{uuid.uuid4().hex[:12]}",
                event_type=AuditEventType.POLICY_VIOLATED,
                timestamp=datetime.now(timezone.utc),
                user_id=context.get('user_id', 'unknown'),
                source_ip=context.get('source_ip', ''),
                resource=policy.policy_id,
                action='policy_enforcement',
                result='violation',
                details={
                    'policy_name': policy.policy_name,
                    'policy_type': policy.policy_type.value,
                    'violation_reason': reason,
                    'context': context
                },
                risk_level=RiskLevel.MEDIUM,
                compliance_impact=True
            )
            
            self.database.store_audit_event(violation_event)
            self.policy_violations.append(violation_event)
            
            logger.warning(f"Policy violation logged: {policy.policy_name} - {reason}")
            
        except Exception as e:
            logger.error(f"Error logging policy violation: {e}")


class ComplianceGovernanceFramework:
    """Main compliance and governance framework coordinator."""
    
    def __init__(self, db_path: str = "compliance_governance.db"):
        self.database = ComplianceGovernanceDatabase(db_path)
        self.compliance_engine = ComplianceEngine(self.database)
        self.policy_system = PolicyManagementSystem(self.database)
        
        # Framework configuration
        self.enabled = True
        self.continuous_monitoring = True
        self.audit_retention_days = 2557  # 7 years
        self.supported_frameworks = list(ComplianceFramework)
        
        logger.info("ComplianceGovernanceFramework initialized")
    
    async def initialize_compliance_framework(self, framework: ComplianceFramework, 
                                            organization: str, owner: str) -> Dict[str, Any]:
        """Initialize compliance framework for organization."""
        try:
            # Initialize framework controls
            control_ids = await self.compliance_engine.initialize_framework_controls(framework, owner)
            
            # Create framework-specific policies
            policy_ids = await self._create_framework_policies(framework, organization, owner)
            
            # Schedule initial assessment
            assessment_date = datetime.now(timezone.utc) + timedelta(days=30)
            
            result = {
                'framework': framework.value,
                'organization': organization,
                'controls_initialized': len(control_ids),
                'policies_created': len(policy_ids),
                'initial_assessment_scheduled': assessment_date.isoformat(),
                'status': 'initialized'
            }
            
            # Log initialization
            await self._log_audit_event(
                AuditEventType.COMPLIANCE_ASSESSED,
                'system',
                '',
                f'framework_{framework.value}',
                'initialize',
                'success',
                result
            )
            
            logger.info(f"Initialized {framework.value} compliance framework for {organization}")
            return result
            
        except Exception as e:
            logger.error(f"Error initializing compliance framework: {e}")
            return {'error': f'Framework initialization failed: {str(e)}'}
    
    async def _create_framework_policies(self, framework: ComplianceFramework, 
                                       organization: str, owner: str) -> List[str]:
        """Create standard policies for compliance framework."""
        policy_ids = []
        
        try:
            # Common policies for all frameworks
            common_policies = [
                {
                    'name': f'{organization} Information Security Policy',
                    'type': PolicyType.SECURITY_POLICY,
                    'description': 'Comprehensive information security policy',
                    'statement': f'{organization} is committed to protecting information assets through comprehensive security controls.'
                },
                {
                    'name': f'{organization} Access Control Policy',
                    'type': PolicyType.ACCESS_CONTROL,
                    'description': 'Access control and identity management policy',
                    'statement': 'Access to information systems shall be controlled and monitored.'
                },
                {
                    'name': f'{organization} Data Governance Policy',
                    'type': PolicyType.DATA_GOVERNANCE,
                    'description': 'Data classification and protection policy',
                    'statement': 'Data shall be classified and protected according to its sensitivity and business value.'
                }
            ]
            
            # Framework-specific policies
            if framework == ComplianceFramework.GDPR:
                common_policies.extend([
                    {
                        'name': f'{organization} Privacy Policy',
                        'type': PolicyType.DATA_GOVERNANCE,
                        'description': 'GDPR privacy protection policy',
                        'statement': 'Personal data shall be processed lawfully and protected according to GDPR requirements.'
                    }
                ])
            
            if framework == ComplianceFramework.SOC2_TYPE2:
                common_policies.extend([
                    {
                        'name': f'{organization} Service Organization Controls Policy',
                        'type': PolicyType.SECURITY_POLICY,
                        'description': 'SOC 2 service delivery controls',
                        'statement': 'Service delivery shall meet SOC 2 trust service criteria for security, availability, and confidentiality.'
                    }
                ])
            
            # Create policies
            for policy_data in common_policies:
                policy_id = await self.policy_system.create_policy(
                    policy_name=policy_data['name'],
                    policy_type=policy_data['type'],
                    description=policy_data['description'],
                    policy_statement=policy_data['statement'],
                    scope=f'{organization} - All systems and users',
                    owner=owner
                )
                
                if policy_id:
                    policy_ids.append(policy_id)
            
        except Exception as e:
            logger.error(f"Error creating framework policies: {e}")
        
        return policy_ids
    
    async def perform_compliance_assessment(self, framework: ComplianceFramework, 
                                          assessor: str, scope: str = None) -> ComplianceAssessment:
        """Perform comprehensive compliance assessment."""
        try:
            if scope is None:
                scope = "Full Organization Assessment"
            
            # Perform assessment
            assessment = await self.compliance_engine.assess_compliance(framework, assessor, scope)
            
            # Log assessment
            await self._log_audit_event(
                AuditEventType.COMPLIANCE_ASSESSED,
                assessor,
                '',
                f'assessment_{assessment.assessment_id}',
                'assess_compliance',
                'completed',
                {
                    'framework': framework.value,
                    'compliance_percentage': assessment.calculate_compliance_percentage(),
                    'overall_status': assessment.overall_status.value,
                    'controls_assessed': assessment.controls_assessed,
                    'findings_count': len(assessment.findings)
                }
            )
            
            logger.info(f"Completed compliance assessment {assessment.assessment_id}: {assessment.calculate_compliance_percentage():.1f}% compliant")
            return assessment
            
        except Exception as e:
            logger.error(f"Error performing compliance assessment: {e}")
            raise
    
    async def generate_compliance_report(self, framework: ComplianceFramework, 
                                       assessment_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate comprehensive compliance report."""
        try:
            report_data = {
                'report_id': f'report_{framework.value}_{uuid.uuid4().hex[:12]}',
                'framework': framework.value,
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'report_type': 'compliance_status'
            }
            
            # Get assessment data
            if assessment_id:
                assessment = self.database.get_compliance_assessment(assessment_id)
                if assessment:
                    report_data['assessment'] = assessment.to_dict()
            
            # Get controls summary
            controls = self.database.get_security_controls(framework=framework)
            status_summary = defaultdict(int)
            for control in controls:
                status_summary[control.status.value] += 1
            
            report_data['controls_summary'] = dict(status_summary)
            report_data['total_controls'] = len(controls)
            
            # Calculate compliance metrics
            implemented_controls = (
                status_summary.get('implemented', 0) + 
                status_summary.get('operating_effectively', 0)
            )
            compliance_percentage = (implemented_controls / len(controls)) * 100 if controls else 0
            
            report_data['compliance_metrics'] = {
                'compliance_percentage': round(compliance_percentage, 2),
                'implemented_controls': implemented_controls,
                'controls_needing_attention': (
                    status_summary.get('not_implemented', 0) + 
                    status_summary.get('failed', 0) + 
                    status_summary.get('needs_improvement', 0)
                )
            }
            
            # Add high-priority findings
            high_priority_controls = [
                control for control in controls 
                if control.risk_rating.value >= RiskLevel.HIGH.value and 
                control.status not in [ControlStatus.IMPLEMENTED, ControlStatus.OPERATING_EFFECTIVELY]
            ]
            
            report_data['high_priority_findings'] = [
                {
                    'control_id': control.control_id,
                    'control_name': control.control_name,
                    'status': control.status.value,
                    'risk_rating': control.risk_rating.value
                }
                for control in high_priority_controls
            ]
            
            logger.info(f"Generated compliance report for {framework.value}")
            return report_data
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {e}")
            return {'error': f'Report generation failed: {str(e)}'}
    
    async def _log_audit_event(self, event_type: AuditEventType, user_id: str, source_ip: str,
                              resource: str, action: str, result: str, details: Dict[str, Any]):
        """Log audit event for compliance tracking."""
        try:
            audit_event = AuditEvent(
                event_id=f'audit_{uuid.uuid4().hex[:12]}',
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                user_id=user_id,
                source_ip=source_ip,
                resource=resource,
                action=action,
                result=result,
                details=details,
                compliance_impact=True
            )
            
            self.database.store_audit_event(audit_event)
            
        except Exception as e:
            logger.error(f"Error logging audit event: {e}")
    
    async def get_compliance_dashboard(self) -> Dict[str, Any]:
        """Get compliance governance dashboard data."""
        try:
            dashboard_data = {
                'dashboard_id': f'dashboard_{uuid.uuid4().hex[:8]}',
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'frameworks_status': {},
                'overall_metrics': {},
                'recent_activities': [],
                'risk_indicators': {}
            }
            
            # Framework status summary
            for framework in self.supported_frameworks:
                controls = self.database.get_security_controls(framework=framework)
                if controls:
                    status_counts = defaultdict(int)
                    for control in controls:
                        status_counts[control.status.value] += 1
                    
                    compliance_score = (
                        (status_counts.get('implemented', 0) + status_counts.get('operating_effectively', 0)) / 
                        len(controls) * 100
                    ) if controls else 0
                    
                    dashboard_data['frameworks_status'][framework.value] = {
                        'total_controls': len(controls),
                        'compliance_score': round(compliance_score, 1),
                        'status_distribution': dict(status_counts)
                    }
            
            # Overall metrics
            all_controls = self.database.get_security_controls()
            total_controls = len(all_controls)
            
            if total_controls > 0:
                overall_status_counts = defaultdict(int)
                for control in all_controls:
                    overall_status_counts[control.status.value] += 1
                
                dashboard_data['overall_metrics'] = {
                    'total_controls': total_controls,
                    'overall_compliance': round(
                        (overall_status_counts.get('implemented', 0) + 
                         overall_status_counts.get('operating_effectively', 0)) / total_controls * 100, 1
                    ),
                    'critical_findings': len([
                        c for c in all_controls 
                        if c.risk_rating == RiskLevel.CRITICAL and 
                        c.status not in [ControlStatus.IMPLEMENTED, ControlStatus.OPERATING_EFFECTIVELY]
                    ]),
                    'overdue_assessments': len([
                        c for c in all_controls 
                        if c.next_test_date and c.next_test_date < datetime.now(timezone.utc)
                    ])
                }
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Error generating compliance dashboard: {e}")
            return {'error': f'Dashboard generation failed: {str(e)}'}


# Convenience functions
def create_compliance_governance_framework(db_path: str = "compliance_governance.db", 
                                         continuous_monitoring: bool = True) -> ComplianceGovernanceFramework:
    """Create compliance governance framework with configuration."""
    framework = ComplianceGovernanceFramework(db_path)
    framework.continuous_monitoring = continuous_monitoring
    return framework


# Export all classes and functions
__all__ = [
    # Enums
    'ComplianceFramework',
    'ControlStatus',
    'RiskLevel',
    'PolicyType',
    'AuditEventType',
    'ComplianceStatus',
    
    # Data classes
    'SecurityControl',
    'GovernancePolicy',
    'RiskAssessment',
    'AuditEvent',
    'ComplianceAssessment',
    
    # Core classes
    'ComplianceGovernanceDatabase',
    'ComplianceEngine',
    'PolicyManagementSystem',
    'ComplianceGovernanceFramework',
    
    # Convenience functions
    'create_compliance_governance_framework',
]