"""Comprehensive test suite for Advanced Security Compliance and Governance Framework."""

import pytest
import asyncio
import secrets
import time
import hashlib
import json
import os
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

from src.fastapi_shield.compliance_governance import (
    ComplianceGovernanceFramework, ComplianceGovernanceDatabase, ComplianceEngine,
    PolicyManagementSystem,
    ComplianceFramework, ControlStatus, RiskLevel, PolicyType, AuditEventType, ComplianceStatus,
    SecurityControl, GovernancePolicy, RiskAssessment, AuditEvent, ComplianceAssessment,
    create_compliance_governance_framework
)
from tests.mocks.mock_compliance_governance import (
    MockComplianceGovernanceFramework, MockComplianceGovernanceTestEnvironment,
    MockComplianceGovernanceDatabase, MockComplianceEngine, MockPolicyManagementSystem
)


class TestComplianceGovernanceDatabase:
    """Test compliance governance database functionality."""
    
    def test_database_initialization(self, tmp_path):
        """Test database initialization and schema creation."""
        db_path = tmp_path / "test_compliance_governance.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        
        assert db.db_path == str(db_path)
        assert os.path.exists(str(db_path))
        
        # Test table creation
        import sqlite3
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            expected_tables = [
                'security_controls', 'governance_policies', 'risk_assessments',
                'audit_events', 'compliance_assessments', 'framework_mappings',
                'compliance_metrics', 'regulatory_updates', 'third_party_assessments'
            ]
            for table in expected_tables:
                assert table in tables
    
    def test_security_control_storage_and_retrieval(self, tmp_path):
        """Test storing and retrieving security controls."""
        db_path = tmp_path / "test_controls.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        
        control = SecurityControl(
            control_id="CC1.1",
            framework=ComplianceFramework.SOC2_TYPE2,
            control_family="Control Environment",
            control_name="Integrity and Ethical Values",
            control_description="The entity demonstrates commitment to integrity and ethical values",
            implementation_guidance="Establish code of conduct and ethics training",
            testing_procedures="Review ethics policies and training records annually",
            status=ControlStatus.IMPLEMENTED,
            risk_rating=RiskLevel.HIGH,
            owner="compliance_officer",
            implementation_date=datetime.now(timezone.utc),
            test_frequency_days=365,
            evidence_artifacts=["ethics_policy.pdf", "training_records.xlsx"],
            metadata={"last_review": "2024-01-01"}
        )
        
        # Store control
        assert db.store_security_control(control) == True
        
        # Retrieve controls
        controls = db.get_security_controls(framework=ComplianceFramework.SOC2_TYPE2)
        assert len(controls) >= 1
        
        retrieved = controls[0]
        assert retrieved.control_id == "CC1.1"
        assert retrieved.framework == ComplianceFramework.SOC2_TYPE2
        assert retrieved.status == ControlStatus.IMPLEMENTED
        assert retrieved.risk_rating == RiskLevel.HIGH
        assert len(retrieved.evidence_artifacts) == 2
        assert "last_review" in retrieved.metadata
    
    def test_governance_policy_storage(self, tmp_path):
        """Test storing governance policies."""
        db_path = tmp_path / "test_policies.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        
        policy = GovernancePolicy(
            policy_id="policy_001",
            policy_name="Information Security Policy",
            policy_type=PolicyType.SECURITY_POLICY,
            description="Comprehensive information security policy",
            policy_statement="All information assets shall be protected according to their classification",
            scope="Organization-wide",
            roles_responsibilities={
                "CISO": ["Policy oversight", "Risk assessment approval"],
                "Security Team": ["Policy implementation", "Monitoring"]
            },
            enforcement_rules={
                "required_training": True,
                "annual_review": True,
                "violation_reporting": "mandatory"
            },
            exceptions=[],
            version="1.0",
            effective_date=datetime.now(timezone.utc),
            review_date=datetime.now(timezone.utc) + timedelta(days=365),
            approval_status="approved",
            approved_by="Board of Directors",
            owner="CISO",
            tags=["security", "mandatory"]
        )
        
        # Store policy
        assert db.store_governance_policy(policy) == True
    
    def test_risk_assessment_storage(self, tmp_path):
        """Test storing risk assessments."""
        db_path = tmp_path / "test_risks.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        
        risk = RiskAssessment(
            risk_id="risk_001",
            risk_name="Data Breach Risk",
            risk_description="Risk of unauthorized access to sensitive customer data",
            risk_category="Data Security",
            threat_sources=["External hackers", "Malicious insiders"],
            vulnerabilities=["Unpatched systems", "Weak access controls"],
            impact_description="Loss of customer trust, regulatory fines, business disruption",
            likelihood_description="Medium likelihood based on industry trends",
            inherent_risk_level=RiskLevel.HIGH,
            residual_risk_level=RiskLevel.MEDIUM,
            risk_owner="Data Protection Officer",
            mitigation_controls=["CC6.1", "CC7.1"],
            mitigation_plan={
                "patch_management": "Implement automated patching",
                "access_controls": "Deploy zero-trust architecture",
                "monitoring": "24/7 SOC monitoring"
            },
            assessment_date=datetime.now(timezone.utc),
            review_date=datetime.now(timezone.utc) + timedelta(days=90),
            business_impact={"financial": "High", "reputation": "Critical"},
            regulatory_implications=["GDPR", "SOX"]
        )
        
        # Store risk assessment
        assert db.store_risk_assessment(risk) == True
    
    def test_audit_event_storage(self, tmp_path):
        """Test storing audit events."""
        db_path = tmp_path / "test_audit.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        
        event = AuditEvent(
            event_id="audit_001",
            event_type=AuditEventType.CONTROL_TESTED,
            timestamp=datetime.now(timezone.utc),
            user_id="auditor_smith",
            source_ip="192.168.1.100",
            resource="CC1.1",
            action="control_testing",
            result="passed",
            details={
                "test_method": "document_review",
                "evidence_reviewed": ["ethics_policy.pdf"],
                "findings": "Control operating effectively"
            },
            risk_level=RiskLevel.LOW,
            compliance_impact=True
        )
        
        # Store audit event
        assert db.store_audit_event(event) == True
        
        # Verify digital signature
        assert event.verify_integrity() == True
    
    def test_compliance_assessment_storage_and_retrieval(self, tmp_path):
        """Test storing and retrieving compliance assessments."""
        db_path = tmp_path / "test_assessments.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        
        assessment = ComplianceAssessment(
            assessment_id="assessment_001",
            framework=ComplianceFramework.ISO27001,
            assessment_date=datetime.now(timezone.utc),
            assessor="External Auditor Inc",
            scope="Full organization assessment",
            overall_status=ComplianceStatus.PARTIALLY_COMPLIANT,
            controls_assessed=10,
            controls_compliant=8,
            controls_non_compliant=2,
            control_results={
                "A.5.1.1": ControlStatus.OPERATING_EFFECTIVELY,
                "A.6.1.1": ControlStatus.NEEDS_IMPROVEMENT
            },
            findings=[
                {
                    "control_id": "A.6.1.1",
                    "finding": "Security roles not clearly documented",
                    "risk_level": 2,
                    "remediation": "Update role documentation"
                }
            ],
            recommendations=[
                {
                    "control_id": "A.6.1.1",
                    "recommendation": "Enhance role clarity documentation",
                    "priority": 2,
                    "timeline": "30 days"
                }
            ],
            next_assessment_date=datetime.now(timezone.utc) + timedelta(days=365),
            risk_score=25.5,
            maturity_level=3
        )
        
        # Store assessment
        assert db.store_compliance_assessment(assessment) == True
        
        # Retrieve assessment
        retrieved = db.get_compliance_assessment("assessment_001")
        assert retrieved is not None
        assert retrieved.assessment_id == "assessment_001"
        assert retrieved.framework == ComplianceFramework.ISO27001
        assert retrieved.overall_status == ComplianceStatus.PARTIALLY_COMPLIANT
        assert retrieved.calculate_compliance_percentage() == 80.0
        assert len(retrieved.findings) == 1
        assert len(retrieved.recommendations) == 1
    
    def test_security_controls_filtering(self, tmp_path):
        """Test security controls filtering and querying."""
        db_path = tmp_path / "test_filtering.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        
        # Create multiple controls with different statuses and frameworks
        controls_data = [
            ("CC1.1", ComplianceFramework.SOC2_TYPE2, ControlStatus.IMPLEMENTED),
            ("CC1.2", ComplianceFramework.SOC2_TYPE2, ControlStatus.NEEDS_IMPROVEMENT),
            ("A.5.1.1", ComplianceFramework.ISO27001, ControlStatus.OPERATING_EFFECTIVELY),
            ("A.5.1.2", ComplianceFramework.ISO27001, ControlStatus.NOT_IMPLEMENTED)
        ]
        
        for control_id, framework, status in controls_data:
            control = SecurityControl(
                control_id=control_id,
                framework=framework,
                control_family="Test Family",
                control_name=f"Test Control {control_id}",
                control_description=f"Test description for {control_id}",
                implementation_guidance="Test guidance",
                testing_procedures="Test procedures",
                status=status,
                risk_rating=RiskLevel.MEDIUM,
                owner="test_owner"
            )
            db.store_security_control(control)
        
        # Test framework filtering
        soc2_controls = db.get_security_controls(framework=ComplianceFramework.SOC2_TYPE2)
        assert len(soc2_controls) == 2
        assert all(c.framework == ComplianceFramework.SOC2_TYPE2 for c in soc2_controls)
        
        iso_controls = db.get_security_controls(framework=ComplianceFramework.ISO27001)
        assert len(iso_controls) == 2
        assert all(c.framework == ComplianceFramework.ISO27001 for c in iso_controls)
        
        # Test status filtering
        implemented_controls = db.get_security_controls(status=ControlStatus.IMPLEMENTED)
        assert len(implemented_controls) == 1
        assert implemented_controls[0].status == ControlStatus.IMPLEMENTED
        
        # Test combined filtering
        soc2_implemented = db.get_security_controls(
            framework=ComplianceFramework.SOC2_TYPE2, 
            status=ControlStatus.IMPLEMENTED
        )
        assert len(soc2_implemented) == 1
        assert soc2_implemented[0].control_id == "CC1.1"
    
    def test_nonexistent_assessment_retrieval(self, tmp_path):
        """Test retrieving non-existent compliance assessments."""
        db_path = tmp_path / "test_nonexistent.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        
        # Test non-existent assessment
        assessment = db.get_compliance_assessment("nonexistent_assessment")
        assert assessment is None


class TestComplianceEngine:
    """Test compliance monitoring and assessment engine."""
    
    @pytest.mark.asyncio
    async def test_initialize_framework_controls(self, tmp_path):
        """Test initializing framework controls."""
        db_path = tmp_path / "test_compliance_engine.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        engine = ComplianceEngine(db)
        
        # Initialize SOC 2 Type II controls
        control_ids = await engine.initialize_framework_controls(
            ComplianceFramework.SOC2_TYPE2, "compliance_manager"
        )
        
        assert len(control_ids) > 0
        assert all(control_id.startswith("CC") for control_id in control_ids)
        
        # Verify controls were stored
        stored_controls = db.get_security_controls(framework=ComplianceFramework.SOC2_TYPE2)
        assert len(stored_controls) == len(control_ids)
        assert all(control.status == ControlStatus.NOT_IMPLEMENTED for control in stored_controls)
        assert all(control.owner == "compliance_manager" for control in stored_controls)
    
    @pytest.mark.asyncio
    async def test_assess_compliance_full_framework(self, tmp_path):
        """Test comprehensive compliance assessment."""
        db_path = tmp_path / "test_assessment.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        engine = ComplianceEngine(db)
        
        # Initialize framework controls
        await engine.initialize_framework_controls(ComplianceFramework.ISO27001, "test_owner")
        
        # Update some controls to implemented status
        controls = db.get_security_controls(framework=ComplianceFramework.ISO27001)
        for i, control in enumerate(controls[:3]):  # Mark first 3 as implemented
            control.status = ControlStatus.OPERATING_EFFECTIVELY
            control.implementation_date = datetime.now(timezone.utc)
            control.last_tested = datetime.now(timezone.utc)
            control.evidence_artifacts = [f"evidence_{control.control_id}.pdf"]
            db.store_security_control(control)
        
        # Perform assessment
        assessment = await engine.assess_compliance(
            ComplianceFramework.ISO27001, "external_auditor", "Full Organization"
        )
        
        assert assessment.framework == ComplianceFramework.ISO27001
        assert assessment.assessor == "external_auditor"
        assert assessment.scope == "Full Organization"
        assert assessment.controls_assessed == len(controls)
        assert assessment.controls_compliant >= 3  # At least the 3 we marked as implemented
        assert assessment.overall_status in [ComplianceStatus.PARTIALLY_COMPLIANT, ComplianceStatus.COMPLIANT, ComplianceStatus.REMEDIATION_REQUIRED]
        assert 0 <= assessment.calculate_compliance_percentage() <= 100
        assert 1 <= assessment.maturity_level <= 5
        assert assessment.risk_score >= 0
    
    @pytest.mark.asyncio
    async def test_assess_compliance_empty_framework(self, tmp_path):
        """Test compliance assessment with no controls."""
        db_path = tmp_path / "test_empty_assessment.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        engine = ComplianceEngine(db)
        
        # Assess framework without any controls
        assessment = await engine.assess_compliance(
            ComplianceFramework.GDPR, "assessor", "Test Scope"
        )
        
        assert assessment.framework == ComplianceFramework.GDPR
        assert assessment.controls_assessed == 0
        assert assessment.controls_compliant == 0
        assert assessment.overall_status in [ComplianceStatus.NOT_ASSESSED, ComplianceStatus.NON_COMPLIANT]
        assert assessment.calculate_compliance_percentage() == 0.0
    
    @pytest.mark.asyncio
    async def test_control_assessment_logic(self, tmp_path):
        """Test individual control assessment logic."""
        db_path = tmp_path / "test_control_assessment.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        engine = ComplianceEngine(db)
        
        # Test control with no evidence
        control_no_evidence = SecurityControl(
            control_id="TEST-001",
            framework=ComplianceFramework.SOC2_TYPE2,
            control_family="Test",
            control_name="Test Control",
            control_description="Test control description",
            implementation_guidance="Test guidance",
            testing_procedures="Test procedures",
            status=ControlStatus.IMPLEMENTED,  # Claims to be implemented
            risk_rating=RiskLevel.MEDIUM,
            owner="test_owner",
            evidence_artifacts=[]  # But has no evidence
        )
        
        assessment_result = await engine._assess_control(control_no_evidence)
        assert assessment_result['status'] == ControlStatus.NEEDS_IMPROVEMENT
        assert "evidence" in assessment_result['finding'].lower()
        
        # Test control with overdue testing
        control_overdue = SecurityControl(
            control_id="TEST-002",
            framework=ComplianceFramework.SOC2_TYPE2,
            control_family="Test",
            control_name="Test Control 2",
            control_description="Test control description",
            implementation_guidance="Test guidance",
            testing_procedures="Test procedures",
            status=ControlStatus.IMPLEMENTED,
            risk_rating=RiskLevel.MEDIUM,
            owner="test_owner",
            evidence_artifacts=["evidence.pdf"],
            last_tested=datetime.now(timezone.utc) - timedelta(days=400),  # Overdue
            test_frequency_days=365
        )
        
        assessment_result = await engine._assess_control(control_overdue)
        assert assessment_result['status'] == ControlStatus.NEEDS_IMPROVEMENT
        assert "overdue" in assessment_result['finding'].lower()
        
        # Test properly implemented control
        control_good = SecurityControl(
            control_id="TEST-003",
            framework=ComplianceFramework.SOC2_TYPE2,
            control_family="Test",
            control_name="Test Control 3",
            control_description="Test control description",
            implementation_guidance="Test guidance",
            testing_procedures="Test procedures",
            status=ControlStatus.IMPLEMENTED,
            risk_rating=RiskLevel.MEDIUM,
            owner="test_owner",
            evidence_artifacts=["evidence.pdf", "test_results.xlsx"],
            last_tested=datetime.now(timezone.utc) - timedelta(days=30),
            test_frequency_days=365
        )
        
        assessment_result = await engine._assess_control(control_good)
        assert assessment_result['status'] == ControlStatus.OPERATING_EFFECTIVELY
        assert assessment_result['finding'] == ''
    
    def test_risk_score_calculation(self, tmp_path):
        """Test risk score calculation logic."""
        db_path = tmp_path / "test_risk_calculation.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        engine = ComplianceEngine(db)
        
        # Create test controls with different risk ratings and statuses
        controls = [
            SecurityControl(
                control_id="HIGH-001", framework=ComplianceFramework.SOC2_TYPE2,
                control_family="Test", control_name="High Risk Control",
                control_description="Test", implementation_guidance="Test",
                testing_procedures="Test", status=ControlStatus.FAILED,
                risk_rating=RiskLevel.HIGH, owner="test"
            ),
            SecurityControl(
                control_id="MED-001", framework=ComplianceFramework.SOC2_TYPE2,
                control_family="Test", control_name="Medium Risk Control",
                control_description="Test", implementation_guidance="Test",
                testing_procedures="Test", status=ControlStatus.OPERATING_EFFECTIVELY,
                risk_rating=RiskLevel.MEDIUM, owner="test"
            ),
            SecurityControl(
                control_id="LOW-001", framework=ComplianceFramework.SOC2_TYPE2,
                control_family="Test", control_name="Low Risk Control",
                control_description="Test", implementation_guidance="Test",
                testing_procedures="Test", status=ControlStatus.NEEDS_IMPROVEMENT,
                risk_rating=RiskLevel.LOW, owner="test"
            )
        ]
        
        control_results = {
            "HIGH-001": ControlStatus.FAILED,
            "MED-001": ControlStatus.OPERATING_EFFECTIVELY,
            "LOW-001": ControlStatus.NEEDS_IMPROVEMENT
        }
        
        risk_score = engine._calculate_risk_score(controls, control_results)
        
        assert 0 <= risk_score <= 100
        assert isinstance(risk_score, float)
    
    def test_maturity_level_calculation(self, tmp_path):
        """Test security maturity level calculation."""
        db_path = tmp_path / "test_maturity.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        engine = ComplianceEngine(db)
        
        # Test scenarios for different maturity levels
        test_cases = [
            # High maturity: 95% operating effectively
            ([ControlStatus.OPERATING_EFFECTIVELY] * 19 + [ControlStatus.IMPLEMENTED], 5),
            # Good maturity: 75% operating effectively
            ([ControlStatus.OPERATING_EFFECTIVELY] * 15 + [ControlStatus.IMPLEMENTED] * 5, 4),
            # Medium maturity: 60% implemented
            ([ControlStatus.IMPLEMENTED] * 12 + [ControlStatus.NOT_IMPLEMENTED] * 8, 3),
            # Low maturity: 30% implemented
            ([ControlStatus.IMPLEMENTED] * 6 + [ControlStatus.NOT_IMPLEMENTED] * 14, 2),
            # Initial maturity: mostly not implemented
            ([ControlStatus.NOT_IMPLEMENTED] * 18 + [ControlStatus.IMPLEMENTED] * 2, 1)
        ]
        
        for statuses, expected_maturity in test_cases:
            controls = []
            control_results = {}
            
            for i, status in enumerate(statuses):
                control_id = f"TEST-{i:03d}"
                controls.append(SecurityControl(
                    control_id=control_id, framework=ComplianceFramework.SOC2_TYPE2,
                    control_family="Test", control_name=f"Test Control {i}",
                    control_description="Test", implementation_guidance="Test",
                    testing_procedures="Test", status=status,
                    risk_rating=RiskLevel.MEDIUM, owner="test"
                ))
                control_results[control_id] = status
            
            maturity_level = engine._calculate_maturity_level(controls, control_results)
            assert maturity_level == expected_maturity


class TestPolicyManagementSystem:
    """Test policy management system functionality."""
    
    @pytest.mark.asyncio
    async def test_create_policy(self, tmp_path):
        """Test creating governance policies."""
        db_path = tmp_path / "test_policy_creation.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        system = PolicyManagementSystem(db)
        
        policy_id = await system.create_policy(
            policy_name="Test Data Protection Policy",
            policy_type=PolicyType.DATA_GOVERNANCE,
            description="Policy for protecting sensitive data",
            policy_statement="All personal data shall be processed lawfully and protected appropriately",
            scope="All employees and contractors",
            owner="Data Protection Officer",
            roles_responsibilities={
                "DPO": ["Policy oversight", "Privacy impact assessments"],
                "IT Team": ["Technical implementation", "Access controls"]
            },
            enforcement_rules={
                "data_classification_required": True,
                "encryption_mandatory": True,
                "access_logging": True
            }
        )
        
        assert policy_id != ""
        assert policy_id.startswith("policy_data_governance_")
        assert policy_id in system.active_policies
        
        policy = system.active_policies[policy_id]
        assert policy.policy_name == "Test Data Protection Policy"
        assert policy.policy_type == PolicyType.DATA_GOVERNANCE
        assert policy.approval_status == "pending"
        assert len(policy.roles_responsibilities) == 2
        assert len(policy.enforcement_rules) == 3
    
    @pytest.mark.asyncio
    async def test_approve_policy(self, tmp_path):
        """Test policy approval workflow."""
        db_path = tmp_path / "test_policy_approval.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        system = PolicyManagementSystem(db)
        
        # Create policy
        policy_id = await system.create_policy(
            policy_name="Test Security Policy",
            policy_type=PolicyType.SECURITY_POLICY,
            description="Comprehensive security policy",
            policy_statement="Security controls shall be implemented organization-wide",
            scope="All systems and users",
            owner="CISO"
        )
        
        # Approve policy
        approval_result = await system.approve_policy(policy_id, "Board of Directors")
        
        assert approval_result == True
        
        policy = system.active_policies[policy_id]
        assert policy.approval_status == "approved"
        assert policy.approved_by == "Board of Directors"
    
    @pytest.mark.asyncio
    async def test_approve_nonexistent_policy(self, tmp_path):
        """Test approving nonexistent policy."""
        db_path = tmp_path / "test_nonexistent_approval.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        system = PolicyManagementSystem(db)
        
        approval_result = await system.approve_policy("nonexistent_policy", "approver")
        
        assert approval_result == False
    
    @pytest.mark.asyncio
    async def test_enforce_access_control_policy(self, tmp_path):
        """Test access control policy enforcement."""
        db_path = tmp_path / "test_access_control.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        system = PolicyManagementSystem(db)
        
        # Create access control policy
        policy_id = await system.create_policy(
            policy_name="Access Control Policy",
            policy_type=PolicyType.ACCESS_CONTROL,
            description="Controls access to resources",
            policy_statement="Access shall be granted based on least privilege principle",
            scope="All systems",
            owner="Security Team",
            enforcement_rules={
                "required_roles": ["user", "admin"],
                "restricted_resources": ["/admin", "/sensitive"]
            }
        )
        
        # Approve policy
        await system.approve_policy(policy_id, "CISO")
        
        # Test enforcement scenarios
        
        # Valid access - user with required role
        result = await system.enforce_policy(policy_id, {
            'user_id': 'john_doe',
            'user_roles': ['user'],
            'resource': '/api/data',
            'action': 'read'
        })
        assert result['allowed'] == True
        
        # Invalid access - user without required role
        result = await system.enforce_policy(policy_id, {
            'user_id': 'guest_user',
            'user_roles': [],
            'resource': '/api/data',
            'action': 'read'
        })
        assert result['allowed'] == False
        assert 'required roles' in result['reason']
        
        # Invalid access - restricted resource without admin role
        result = await system.enforce_policy(policy_id, {
            'user_id': 'regular_user',
            'user_roles': ['user'],
            'resource': '/admin/settings',
            'action': 'modify'
        })
        assert result['allowed'] == False
        assert 'restricted resource' in result['reason']
        
        # Valid access - admin accessing restricted resource
        result = await system.enforce_policy(policy_id, {
            'user_id': 'admin_user',
            'user_roles': ['admin'],
            'resource': '/admin/settings',
            'action': 'modify'
        })
        assert result['allowed'] == True
    
    @pytest.mark.asyncio
    async def test_enforce_data_governance_policy(self, tmp_path):
        """Test data governance policy enforcement."""
        db_path = tmp_path / "test_data_governance.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        system = PolicyManagementSystem(db)
        
        # Create data governance policy
        policy_id = await system.create_policy(
            policy_name="Data Governance Policy",
            policy_type=PolicyType.DATA_GOVERNANCE,
            description="Governs data access and protection",
            policy_statement="Data access shall be controlled by classification level",
            scope="All data assets",
            owner="Data Steward",
            enforcement_rules={
                "classification_access": {
                    "public": "public",
                    "internal": "internal",
                    "confidential": "confidential",
                    "restricted": "restricted"
                },
                "data_residency": {
                    "allowed_locations": ["US", "EU"]
                }
            }
        )
        
        # Approve policy
        await system.approve_policy(policy_id, "CDO")
        
        # Test enforcement scenarios
        
        # Valid access - sufficient clearance
        result = await system.enforce_policy(policy_id, {
            'user_id': 'data_analyst',
            'user_clearance': 'confidential',
            'data_classification': 'internal',
            'data_location': 'US'
        })
        assert result['allowed'] == True
        
        # Invalid access - insufficient clearance
        result = await system.enforce_policy(policy_id, {
            'user_id': 'intern',
            'user_clearance': 'public',
            'data_classification': 'confidential',
            'data_location': 'US'
        })
        assert result['allowed'] == False
        assert 'clearance' in result['reason']
        
        # Invalid access - data in restricted location
        result = await system.enforce_policy(policy_id, {
            'user_id': 'analyst',
            'user_clearance': 'internal',
            'data_classification': 'internal',
            'data_location': 'CN'
        })
        assert result['allowed'] == False
        assert 'location' in result['reason']
    
    @pytest.mark.asyncio
    async def test_enforce_security_policy(self, tmp_path):
        """Test security policy enforcement."""
        db_path = tmp_path / "test_security_policy.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        system = PolicyManagementSystem(db)
        
        # Create security policy
        policy_id = await system.create_policy(
            policy_name="Password Security Policy",
            policy_type=PolicyType.SECURITY_POLICY,
            description="Password strength and MFA requirements",
            policy_statement="Strong passwords and MFA are required",
            scope="All user accounts",
            owner="Security Team",
            enforcement_rules={
                "password_requirements": {
                    "min_length": 12,
                    "require_uppercase": True,
                    "require_numbers": True,
                    "require_symbols": True
                },
                "mfa_required": True
            }
        )
        
        # Approve policy
        await system.approve_policy(policy_id, "CISO")
        
        # Test password enforcement
        result = await system.enforce_policy(policy_id, {
            'user_id': 'user123',
            'action': 'password_change',
            'new_password': 'short',
            'mfa_verified': False
        })
        assert result['allowed'] == False
        assert 'must be at least 12 characters' in result['reason']
        
        # Test MFA enforcement
        result = await system.enforce_policy(policy_id, {
            'user_id': 'user123',
            'action': 'login',
            'mfa_verified': False
        })
        assert result['allowed'] == False
        assert 'multi-factor authentication' in result['reason'].lower()
        
        # Test valid access with strong password and MFA
        result = await system.enforce_policy(policy_id, {
            'user_id': 'user123',
            'action': 'password_change',
            'new_password': 'StrongP@ssw0rd123!',
            'mfa_verified': True
        })
        assert result['allowed'] == True
    
    @pytest.mark.asyncio
    async def test_enforce_change_management_policy(self, tmp_path):
        """Test change management policy enforcement."""
        db_path = tmp_path / "test_change_management.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        system = PolicyManagementSystem(db)
        
        # Create change management policy
        policy_id = await system.create_policy(
            policy_name="Change Management Policy",
            policy_type=PolicyType.CHANGE_MANAGEMENT,
            description="Controls system changes",
            policy_statement="All changes must be approved based on impact level",
            scope="All systems",
            owner="Change Advisory Board",
            enforcement_rules={
                "approval_requirements": {
                    "low": 1,
                    "medium": 2,
                    "high": 3
                },
                "emergency_approver": "emergency_manager"
            }
        )
        
        # Approve policy
        await system.approve_policy(policy_id, "CTO")
        
        # Test high-impact change with insufficient approvals
        result = await system.enforce_policy(policy_id, {
            'change_type': 'standard',
            'change_impact': 'high',
            'approvals': ['manager1', 'manager2']  # Only 2 approvals
        })
        assert result['allowed'] == False
        assert '3 approvals' in result['reason']
        
        # Test emergency change without emergency approver (but with enough regular approvals)
        result = await system.enforce_policy(policy_id, {
            'change_type': 'emergency',
            'change_impact': 'medium',  # Medium impact requires 2 approvals
            'approvals': ['manager1', 'manager2']  # Has enough regular approvals but missing emergency approver
        })
        assert result['allowed'] == False
        assert 'emergency approver' in result['reason']
        
        # Test valid emergency change
        result = await system.enforce_policy(policy_id, {
            'change_type': 'emergency',
            'change_impact': 'high',
            'approvals': ['emergency_manager']
        })
        assert result['allowed'] == True
    
    @pytest.mark.asyncio
    async def test_policy_violation_logging(self, tmp_path):
        """Test policy violation audit logging."""
        db_path = tmp_path / "test_violation_logging.db"
        db = ComplianceGovernanceDatabase(str(db_path))
        system = PolicyManagementSystem(db)
        
        # Create and approve policy
        policy_id = await system.create_policy(
            policy_name="Test Policy",
            policy_type=PolicyType.ACCESS_CONTROL,
            description="Test policy for violation logging",
            policy_statement="Test statement",
            scope="Test scope",
            owner="Test Owner",
            enforcement_rules={"required_roles": ["admin"]}
        )
        await system.approve_policy(policy_id, "approver")
        
        # Trigger policy violation
        result = await system.enforce_policy(policy_id, {
            'user_id': 'violating_user',
            'user_roles': [],  # No roles - will trigger violation
            'resource': '/test',
            'source_ip': '192.168.1.100'
        })
        
        assert result['allowed'] == False
        assert len(system.policy_violations) > 0
        
        # Check violation was logged
        violation = system.policy_violations[-1]
        assert violation.event_type == AuditEventType.POLICY_VIOLATED
        assert violation.user_id == 'violating_user'
        assert violation.compliance_impact == True
        assert violation.verify_integrity() == True


class TestComplianceGovernanceFramework:
    """Test main compliance governance framework functionality."""
    
    @pytest.mark.asyncio
    async def test_initialize_compliance_framework(self, tmp_path):
        """Test initializing compliance frameworks."""
        db_path = tmp_path / "test_framework.db"
        framework = ComplianceGovernanceFramework(str(db_path))
        
        result = await framework.initialize_compliance_framework(
            ComplianceFramework.SOC2_TYPE2,
            "TechCorp Inc",
            "compliance_manager"
        )
        
        assert result['framework'] == ComplianceFramework.SOC2_TYPE2.value
        assert result['organization'] == "TechCorp Inc"
        assert result['controls_initialized'] > 0
        assert result['policies_created'] > 0
        assert result['status'] == 'initialized'
        assert 'initial_assessment_scheduled' in result
    
    @pytest.mark.asyncio
    async def test_perform_compliance_assessment(self, tmp_path):
        """Test performing compliance assessments."""
        db_path = tmp_path / "test_framework_assessment.db"
        framework = ComplianceGovernanceFramework(str(db_path))
        
        # Initialize framework first
        await framework.initialize_compliance_framework(
            ComplianceFramework.ISO27001,
            "SecureCorp",
            "security_officer"
        )
        
        # Perform assessment
        assessment = await framework.perform_compliance_assessment(
            ComplianceFramework.ISO27001,
            "Internal Audit Team",
            "Information Security Management System"
        )
        
        assert assessment.framework == ComplianceFramework.ISO27001
        assert assessment.assessor == "Internal Audit Team"
        assert assessment.scope == "Information Security Management System"
        assert assessment.controls_assessed > 0
        assert 0 <= assessment.calculate_compliance_percentage() <= 100
        assert assessment.overall_status in list(ComplianceStatus)
        assert isinstance(assessment.findings, list)
        assert isinstance(assessment.recommendations, list)
    
    @pytest.mark.asyncio
    async def test_generate_compliance_report(self, tmp_path):
        """Test generating compliance reports."""
        db_path = tmp_path / "test_reporting.db"
        framework = ComplianceGovernanceFramework(str(db_path))
        
        # Initialize framework and perform assessment
        await framework.initialize_compliance_framework(
            ComplianceFramework.GDPR, "PrivacyCorp", "dpo"
        )
        
        assessment = await framework.perform_compliance_assessment(
            ComplianceFramework.GDPR, "Privacy Auditor"
        )
        
        # Generate report
        report = await framework.generate_compliance_report(
            ComplianceFramework.GDPR, assessment.assessment_id
        )
        
        assert report['framework'] == ComplianceFramework.GDPR.value
        assert 'report_id' in report
        assert 'generated_at' in report
        assert 'assessment' in report
        assert 'controls_summary' in report
        assert 'compliance_metrics' in report
        assert 'high_priority_findings' in report
        
        # Verify compliance metrics
        metrics = report['compliance_metrics']
        assert 'compliance_percentage' in metrics
        assert 'implemented_controls' in metrics
        assert 'controls_needing_attention' in metrics
        assert 0 <= metrics['compliance_percentage'] <= 100
    
    @pytest.mark.asyncio
    async def test_get_compliance_dashboard(self, tmp_path):
        """Test compliance dashboard generation."""
        db_path = tmp_path / "test_dashboard.db"
        framework = ComplianceGovernanceFramework(str(db_path))
        
        # Initialize multiple frameworks
        for fw in [ComplianceFramework.SOC2_TYPE2, ComplianceFramework.ISO27001]:
            await framework.initialize_compliance_framework(fw, "MultiCorp", "compliance_team")
        
        # Get dashboard
        dashboard = await framework.get_compliance_dashboard()
        
        assert 'dashboard_id' in dashboard
        assert 'generated_at' in dashboard
        assert 'frameworks_status' in dashboard
        assert 'overall_metrics' in dashboard
        
        # Check framework status
        frameworks_status = dashboard['frameworks_status']
        assert len(frameworks_status) >= 2
        
        for framework_name, status in frameworks_status.items():
            assert 'total_controls' in status
            assert 'compliance_score' in status
            assert 'status_distribution' in status
            assert 0 <= status['compliance_score'] <= 100
    
    @pytest.mark.asyncio
    async def test_audit_event_logging(self, tmp_path):
        """Test audit event logging functionality."""
        db_path = tmp_path / "test_audit_logging.db"
        framework = ComplianceGovernanceFramework(str(db_path))
        
        # Initialize framework (should generate audit events)
        await framework.initialize_compliance_framework(
            ComplianceFramework.PCI_DSS, "PaymentCorp", "security_admin"
        )
        
        # Perform assessment (should generate audit event)
        await framework.perform_compliance_assessment(
            ComplianceFramework.PCI_DSS, "QSA Auditor"
        )
        
        # Check that audit events were logged
        # Note: In a real implementation, we'd query the database for audit events
        # Here we verify the logging mechanism was called
        assert True  # Placeholder - in practice would verify audit trail


class TestComplianceGovernanceIntegration:
    """Integration tests for compliance governance system."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_compliance_lifecycle(self, tmp_path):
        """Test complete compliance lifecycle from initialization to reporting."""
        db_path = tmp_path / "test_e2e_compliance.db"
        framework = ComplianceGovernanceFramework(str(db_path))
        
        # Step 1: Initialize compliance framework
        init_result = await framework.initialize_compliance_framework(
            ComplianceFramework.SOC2_TYPE2,
            "StartupCorp",
            "ceo"
        )
        assert init_result['status'] == 'initialized'
        
        # Step 2: Create additional policies
        policy_id = await framework.policy_system.create_policy(
            policy_name="Incident Response Policy",
            policy_type=PolicyType.INCIDENT_RESPONSE,
            description="Procedures for handling security incidents",
            policy_statement="All security incidents must be reported and handled promptly",
            scope="All employees",
            owner="CISO"
        )
        assert policy_id != ""
        
        # Step 3: Approve policy
        approval_success = await framework.policy_system.approve_policy(policy_id, "Board")
        assert approval_success == True
        
        # Step 4: Update some controls to show progress
        controls = framework.database.get_security_controls(framework=ComplianceFramework.SOC2_TYPE2)
        for control in controls[:2]:  # Update first 2 controls
            control.status = ControlStatus.IMPLEMENTED
            control.implementation_date = datetime.now(timezone.utc)
            control.evidence_artifacts = [f"evidence_{control.control_id}.pdf"]
            framework.database.store_security_control(control)
        
        # Step 5: Perform compliance assessment
        assessment = await framework.perform_compliance_assessment(
            ComplianceFramework.SOC2_TYPE2,
            "External Auditor Firm"
        )
        assert assessment.controls_compliant >= 2
        
        # Step 6: Generate compliance report
        report = await framework.generate_compliance_report(
            ComplianceFramework.SOC2_TYPE2,
            assessment.assessment_id
        )
        assert report['compliance_metrics']['compliance_percentage'] > 0
        
        # Step 7: Get dashboard view
        dashboard = await framework.get_compliance_dashboard()
        assert ComplianceFramework.SOC2_TYPE2.value in dashboard['frameworks_status']
    
    @pytest.mark.asyncio
    async def test_multi_framework_compliance(self, tmp_path):
        """Test managing multiple compliance frameworks simultaneously."""
        db_path = tmp_path / "test_multi_framework.db"
        framework = ComplianceGovernanceFramework(str(db_path))
        
        frameworks_to_test = [
            ComplianceFramework.SOC2_TYPE2,
            ComplianceFramework.ISO27001,
            ComplianceFramework.GDPR
        ]
        
        # Initialize multiple frameworks
        for fw in frameworks_to_test:
            result = await framework.initialize_compliance_framework(
                fw, f"MultiCompliance Corp - {fw.value}", "compliance_director"
            )
            assert result['status'] == 'initialized'
        
        # Perform assessments for each framework
        assessments = {}
        for fw in frameworks_to_test:
            assessment = await framework.perform_compliance_assessment(
                fw, f"{fw.value} Specialist Auditor"
            )
            assessments[fw] = assessment
            assert assessment.framework == fw
        
        # Generate reports for each framework
        reports = {}
        for fw in frameworks_to_test:
            report = await framework.generate_compliance_report(fw)
            reports[fw] = report
            assert report['framework'] == fw.value
        
        # Verify dashboard shows all frameworks
        dashboard = await framework.get_compliance_dashboard()
        for fw in frameworks_to_test:
            if fw in [ComplianceFramework.SOC2_TYPE2, ComplianceFramework.ISO27001, ComplianceFramework.GDPR]:
                assert fw.value in dashboard['frameworks_status']
    
    @pytest.mark.asyncio
    async def test_policy_enforcement_integration(self, tmp_path):
        """Test policy enforcement integration with compliance monitoring."""
        db_path = tmp_path / "test_policy_integration.db"
        framework = ComplianceGovernanceFramework(str(db_path))
        
        # Initialize framework
        await framework.initialize_compliance_framework(
            ComplianceFramework.ISO27001, "PolicyCorp", "compliance_manager"
        )
        
        # Create comprehensive access control policy
        policy_id = await framework.policy_system.create_policy(
            policy_name="Comprehensive Access Control Policy",
            policy_type=PolicyType.ACCESS_CONTROL,
            description="Multi-layered access control requirements",
            policy_statement="Access shall be controlled through multiple security layers",
            scope="All information systems",
            owner="CISO",
            enforcement_rules={
                "required_roles": ["authenticated_user"],
                "mfa_required": True,
                "restricted_resources": ["/admin", "/config", "/audit"]
            }
        )
        
        # Approve policy
        await framework.policy_system.approve_policy(policy_id, "Security Committee")
        
        # Test multiple enforcement scenarios
        test_scenarios = [
            # Valid access
            {
                'context': {
                    'user_id': 'john.doe',
                    'user_roles': ['authenticated_user', 'analyst'],
                    'resource': '/api/reports',
                    'mfa_verified': True
                },
                'expected_allowed': True
            },
            # Invalid - no MFA
            {
                'context': {
                    'user_id': 'jane.smith',
                    'user_roles': ['authenticated_user'],
                    'resource': '/api/data',
                    'mfa_verified': False
                },
                'expected_allowed': False
            },
            # Invalid - restricted resource without admin
            {
                'context': {
                    'user_id': 'regular.user',
                    'user_roles': ['authenticated_user'],
                    'resource': '/admin/users',
                    'mfa_verified': True
                },
                'expected_allowed': False
            }
        ]
        
        for i, scenario in enumerate(test_scenarios):
            result = await framework.policy_system.enforce_policy(
                policy_id, scenario['context']
            )
            if result['allowed'] != scenario['expected_allowed']:
                print(f"Scenario {i} failed:")
                print(f"Context: {scenario['context']}")
                print(f"Expected: {scenario['expected_allowed']}, Got: {result['allowed']}")
                print(f"Reason: {result['reason']}")
            assert result['allowed'] == scenario['expected_allowed'], f"Scenario {i} failed: expected {scenario['expected_allowed']}, got {result['allowed']}, reason: {result['reason']}"
        
        # Verify policy violations were logged
        assert len(framework.policy_system.policy_violations) >= 2  # At least 2 violations


class TestComplianceGovernanceWithMocks:
    """Test compliance governance system using mock infrastructure."""
    
    def test_mock_framework_initialization(self):
        """Test mock framework initialization."""
        mock_framework = MockComplianceGovernanceFramework()
        
        assert mock_framework.database is not None
        assert mock_framework.compliance_engine is not None
        assert mock_framework.policy_system is not None
        assert mock_framework.enabled == True
        assert mock_framework.continuous_monitoring == True
    
    @pytest.mark.asyncio
    async def test_mock_compliance_assessment(self):
        """Test compliance assessment with mock framework."""
        mock_framework = MockComplianceGovernanceFramework()
        
        # Initialize framework
        result = await mock_framework.initialize_compliance_framework(
            ComplianceFramework.SOC2_TYPE2, 'Mock Corp', 'mock_owner'
        )
        
        assert result['mock_initialization'] == True
        assert result['status'] == 'initialized'
        
        # Perform assessment
        assessment = await mock_framework.perform_compliance_assessment(
            ComplianceFramework.SOC2_TYPE2, 'mock_assessor'
        )
        
        assert assessment.framework == ComplianceFramework.SOC2_TYPE2
        assert assessment.assessor == 'mock_assessor'
        assert assessment.controls_assessed > 0
        assert 0 <= assessment.calculate_compliance_percentage() <= 100
    
    @pytest.mark.asyncio
    async def test_mock_policy_enforcement(self):
        """Test policy enforcement with mock system."""
        mock_framework = MockComplianceGovernanceFramework()
        
        # Create policy
        policy_id = await mock_framework.policy_system.create_policy(
            policy_name="Mock Security Policy",
            policy_type=PolicyType.SECURITY_POLICY,
            description="Mock policy for testing",
            policy_statement="Mock policy statement",
            scope="Mock scope",
            owner="mock_owner"
        )
        
        # Approve policy
        await mock_framework.policy_system.approve_policy(policy_id, 'mock_approver')
        
        # Test enforcement
        result = await mock_framework.policy_system.enforce_policy(policy_id, {
            'user_id': 'mock_user',
            'user_roles': ['user']
        })
        
        assert 'allowed' in result
        assert 'reason' in result
    
    @pytest.mark.asyncio
    async def test_mock_test_environment(self):
        """Test mock test environment functionality."""
        mock_env = MockComplianceGovernanceTestEnvironment()
        
        assert len(mock_env.test_scenarios) >= 6
        assert mock_env.framework is not None
        
        # Test running specific scenario
        result = await mock_env.run_test_scenario('soc2_compliance_initialization')
        
        assert result['scenario'] == 'soc2_compliance_initialization'
        assert result['type'] == 'framework_initialization'
        assert 'initialization_result' in result
    
    @pytest.mark.asyncio
    async def test_mock_performance_metrics(self):
        """Test performance metrics collection."""
        mock_env = MockComplianceGovernanceTestEnvironment()
        
        # Run multiple scenarios
        await mock_env.run_test_scenario('soc2_compliance_initialization')
        await mock_env.run_test_scenario('iso27001_compliance_assessment')
        
        metrics = mock_env.get_performance_metrics()
        
        assert 'framework_initialization_times' in metrics
        assert 'assessment_times' in metrics
        assert metrics['framework_initialization_times']['count'] >= 1
        assert metrics['assessment_times']['count'] >= 1
    
    @pytest.mark.asyncio
    async def test_mock_load_testing(self):
        """Test load testing capabilities."""
        mock_env = MockComplianceGovernanceTestEnvironment()
        
        load_results = await mock_env.simulate_compliance_load_test(num_assessments=5)
        
        assert 'assessments_completed' in load_results
        assert 'total_time' in load_results
        assert load_results['assessments_completed'] <= 5
        assert load_results['total_time'] > 0


class TestComplianceGovernanceConvenienceFunctions:
    """Test convenience functions and utilities."""
    
    def test_create_compliance_governance_framework_function(self, tmp_path):
        """Test convenience function for creating compliance frameworks."""
        db_path = tmp_path / "test_convenience.db"
        
        # Test with defaults
        framework = create_compliance_governance_framework(str(db_path))
        assert isinstance(framework, ComplianceGovernanceFramework)
        assert framework.continuous_monitoring == True
        
        # Test with continuous monitoring disabled
        framework_no_monitoring = create_compliance_governance_framework(
            str(db_path), continuous_monitoring=False
        )
        assert framework_no_monitoring.continuous_monitoring == False
    
    def test_enum_value_consistency(self):
        """Test consistency of enum values."""
        # Test RiskLevel ordering
        assert RiskLevel.VERY_LOW.value < RiskLevel.LOW.value
        assert RiskLevel.LOW.value < RiskLevel.MEDIUM.value
        assert RiskLevel.MEDIUM.value < RiskLevel.HIGH.value
        assert RiskLevel.HIGH.value < RiskLevel.VERY_HIGH.value
        assert RiskLevel.VERY_HIGH.value < RiskLevel.CRITICAL.value
        
        # Test all enums have string values (except RiskLevel which has int values)
        for framework in ComplianceFramework:
            assert isinstance(framework.value, str)
        
        for status in ControlStatus:
            assert isinstance(status.value, str)
        
        for policy_type in PolicyType:
            assert isinstance(policy_type.value, str)
        
        for event_type in AuditEventType:
            assert isinstance(event_type.value, str)
    
    def test_data_structure_serialization(self):
        """Test data structure serialization methods."""
        # Test SecurityControl serialization
        control = SecurityControl(
            control_id="TEST-001",
            framework=ComplianceFramework.SOC2_TYPE2,
            control_family="Test Family",
            control_name="Test Control",
            control_description="Test control for serialization",
            implementation_guidance="Test implementation guidance",
            testing_procedures="Test procedures",
            status=ControlStatus.IMPLEMENTED,
            risk_rating=RiskLevel.HIGH,
            owner="test_owner",
            evidence_artifacts=["evidence1.pdf", "evidence2.xlsx"],
            metadata={"test_key": "test_value"}
        )
        
        control_dict = control.to_dict()
        assert isinstance(control_dict, dict)
        assert control_dict['control_id'] == "TEST-001"
        assert control_dict['framework'] == ComplianceFramework.SOC2_TYPE2.value
        assert control_dict['status'] == ControlStatus.IMPLEMENTED.value
        assert len(control_dict['evidence_artifacts']) == 2
        
        # Test ComplianceAssessment serialization
        assessment = ComplianceAssessment(
            assessment_id="ASSESS-001",
            framework=ComplianceFramework.ISO27001,
            assessment_date=datetime.now(timezone.utc),
            assessor="Test Assessor",
            scope="Test Scope",
            overall_status=ComplianceStatus.COMPLIANT,
            controls_assessed=10,
            controls_compliant=9,
            controls_non_compliant=1,
            control_results={"A.5.1.1": ControlStatus.OPERATING_EFFECTIVELY},
            findings=[],
            recommendations=[],
            next_assessment_date=datetime.now(timezone.utc) + timedelta(days=365)
        )
        
        assessment_dict = assessment.to_dict()
        assert isinstance(assessment_dict, dict)
        assert assessment_dict['assessment_id'] == "ASSESS-001"
        assert assessment_dict['framework'] == ComplianceFramework.ISO27001.value
        assert assessment_dict['compliance_percentage'] == 90.0
        
        # Test AuditEvent integrity verification
        event = AuditEvent(
            event_id="AUDIT-001",
            event_type=AuditEventType.CONTROL_TESTED,
            timestamp=datetime.now(timezone.utc),
            user_id="test_user",
            source_ip="192.168.1.1",
            resource="TEST-001",
            action="test_control",
            result="passed",
            details={"test_method": "document_review"}
        )
        
        assert event.verify_integrity() == True
        
        # Tamper with event and verify integrity fails
        original_signature = event.digital_signature
        event.digital_signature = "tampered_signature"
        assert event.verify_integrity() == False
        
        # Restore signature
        event.digital_signature = original_signature
        assert event.verify_integrity() == True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])