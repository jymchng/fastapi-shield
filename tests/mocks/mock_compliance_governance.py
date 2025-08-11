"""Mock infrastructure for Compliance and Governance framework testing."""

import asyncio
import json
import secrets
import time
import hashlib
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, AsyncMock

from src.fastapi_shield.compliance_governance import (
    ComplianceFramework, ControlStatus, RiskLevel, PolicyType, AuditEventType, ComplianceStatus,
    SecurityControl, GovernancePolicy, RiskAssessment, AuditEvent, ComplianceAssessment
)


class MockComplianceGovernanceDatabase:
    """Mock compliance governance database for testing."""
    
    def __init__(self):
        self.security_controls = {}
        self.governance_policies = {}
        self.risk_assessments = {}
        self.audit_events = []
        self.compliance_assessments = {}
        self.framework_mappings = {}
        self.compliance_metrics = []
        self.regulatory_updates = []
        self.third_party_assessments = {}
        self.storage_calls = []
        self.query_calls = []
    
    def store_security_control(self, control: SecurityControl) -> bool:
        """Mock store security control."""
        self.storage_calls.append(('security_control', control.control_id))
        self.security_controls[control.control_id] = control
        return True
    
    def store_governance_policy(self, policy: GovernancePolicy) -> bool:
        """Mock store governance policy."""
        self.storage_calls.append(('governance_policy', policy.policy_id))
        self.governance_policies[policy.policy_id] = policy
        return True
    
    def store_risk_assessment(self, risk: RiskAssessment) -> bool:
        """Mock store risk assessment."""
        self.storage_calls.append(('risk_assessment', risk.risk_id))
        self.risk_assessments[risk.risk_id] = risk
        return True
    
    def store_audit_event(self, event: AuditEvent) -> bool:
        """Mock store audit event."""
        self.storage_calls.append(('audit_event', event.event_id))
        self.audit_events.append(event)
        return True
    
    def store_compliance_assessment(self, assessment: ComplianceAssessment) -> bool:
        """Mock store compliance assessment."""
        self.storage_calls.append(('compliance_assessment', assessment.assessment_id))
        self.compliance_assessments[assessment.assessment_id] = assessment
        return True
    
    def get_security_controls(self, framework: Optional[ComplianceFramework] = None, 
                             status: Optional[ControlStatus] = None, limit: int = 1000) -> List[SecurityControl]:
        """Mock get security controls."""
        self.query_calls.append(('security_controls', framework, status, limit))
        
        controls = list(self.security_controls.values())
        
        if framework:
            controls = [c for c in controls if c.framework == framework]
        
        if status:
            controls = [c for c in controls if c.status == status]
        
        return controls[:limit]
    
    def get_compliance_assessment(self, assessment_id: str) -> Optional[ComplianceAssessment]:
        """Mock get compliance assessment."""
        self.query_calls.append(('compliance_assessment', assessment_id))
        return self.compliance_assessments.get(assessment_id)


class MockComplianceEngine:
    """Mock compliance monitoring and assessment engine."""
    
    def __init__(self, database):
        self.database = database
        self.framework_controls = {}
        self.compliance_rules = {}
        self.assessment_schedules = {}
        
        # Mock data for testing
        self.framework_initialization_calls = []
        self.assessment_calls = []
        self.control_assessment_calls = []
        
        # Initialize mock framework controls
        self._initialize_mock_framework_controls()
    
    def _initialize_mock_framework_controls(self):
        """Initialize mock framework controls for testing."""
        self.framework_controls = {
            ComplianceFramework.SOC2_TYPE2: [
                {
                    'control_id': 'CC1.1',
                    'control_family': 'Control Environment',
                    'control_name': 'Mock Integrity and Ethical Values',
                    'description': 'Mock SOC 2 control description',
                    'risk_rating': RiskLevel.HIGH,
                    'test_frequency_days': 365
                },
                {
                    'control_id': 'CC6.1',
                    'control_family': 'Logical Access Controls',
                    'control_name': 'Mock Access Control',
                    'description': 'Mock access control description',
                    'risk_rating': RiskLevel.CRITICAL,
                    'test_frequency_days': 90
                }
            ],
            ComplianceFramework.ISO27001: [
                {
                    'control_id': 'A.5.1.1',
                    'control_family': 'Information Security Policies',
                    'control_name': 'Mock Policies for Information Security',
                    'description': 'Mock ISO 27001 control description',
                    'risk_rating': RiskLevel.HIGH,
                    'test_frequency_days': 365
                }
            ],
            ComplianceFramework.GDPR: [
                {
                    'control_id': 'GDPR.7',
                    'control_family': 'Lawful Basis',
                    'control_name': 'Mock Consent Management',
                    'description': 'Mock GDPR control description',
                    'risk_rating': RiskLevel.CRITICAL,
                    'test_frequency_days': 180
                }
            ]
        }
    
    async def initialize_framework_controls(self, framework: ComplianceFramework, owner: str) -> List[str]:
        """Mock initialize framework controls."""
        self.framework_initialization_calls.append({
            'framework': framework.value,
            'owner': owner,
            'timestamp': datetime.now(timezone.utc)
        })
        
        if framework not in self.framework_controls:
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
                implementation_guidance=f"Mock implementation guidance for {control_data['control_name']}",
                testing_procedures=f"Mock testing procedures for {control_data['control_name']}",
                status=ControlStatus.NOT_IMPLEMENTED,
                risk_rating=control_data['risk_rating'],
                owner=owner,
                test_frequency_days=control_data['test_frequency_days']
            )
            
            if self.database.store_security_control(control):
                control_ids.append(control.control_id)
        
        return control_ids
    
    async def assess_compliance(self, framework: ComplianceFramework, assessor: str, 
                               scope: str = "Full Organization") -> ComplianceAssessment:
        """Mock compliance assessment."""
        self.assessment_calls.append({
            'framework': framework.value,
            'assessor': assessor,
            'scope': scope,
            'timestamp': datetime.now(timezone.utc)
        })
        
        assessment_id = f"mock_assessment_{framework.value}_{uuid.uuid4().hex[:12]}"
        
        # Get mock controls for assessment
        controls = self.database.get_security_controls(framework=framework)
        
        # Mock assessment results
        controls_assessed = len(controls)
        controls_compliant = max(0, int(controls_assessed * 0.75))  # 75% compliance
        controls_non_compliant = controls_assessed - controls_compliant
        
        control_results = {}
        findings = []
        recommendations = []
        
        for i, control in enumerate(controls):
            if i < controls_compliant:
                control_results[control.control_id] = ControlStatus.OPERATING_EFFECTIVELY
            else:
                control_results[control.control_id] = ControlStatus.NEEDS_IMPROVEMENT
                findings.append({
                    'control_id': control.control_id,
                    'finding': f'Mock finding for {control.control_name}',
                    'risk_level': control.risk_rating.value,
                    'remediation': 'Mock remediation recommendation'
                })
                
                recommendations.append({
                    'control_id': control.control_id,
                    'recommendation': f'Improve implementation of {control.control_name}',
                    'priority': control.risk_rating.value,
                    'timeline': '30 days'
                })
        
        # Determine overall status
        compliance_percentage = (controls_compliant / controls_assessed) * 100 if controls_assessed > 0 else 0
        
        if compliance_percentage >= 95:
            overall_status = ComplianceStatus.COMPLIANT
        elif compliance_percentage >= 80:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.REMEDIATION_REQUIRED
        
        # Create mock assessment
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
            risk_score=25.0 + (25 * (controls_non_compliant / controls_assessed)) if controls_assessed > 0 else 0,
            maturity_level=4 if compliance_percentage >= 90 else 3 if compliance_percentage >= 70 else 2
        )
        
        # Store assessment
        self.database.store_compliance_assessment(assessment)
        
        return assessment
    
    def _calculate_mock_risk_score(self, controls: List[SecurityControl], results: Dict[str, ControlStatus]) -> float:
        """Calculate mock risk score."""
        if not controls:
            return 0.0
        
        total_risk = 0.0
        for control in controls:
            status = results.get(control.control_id, ControlStatus.NOT_IMPLEMENTED)
            if status in [ControlStatus.OPERATING_EFFECTIVELY, ControlStatus.IMPLEMENTED]:
                risk_contribution = 0.2
            elif status == ControlStatus.NEEDS_IMPROVEMENT:
                risk_contribution = 0.5
            else:
                risk_contribution = 1.0
            
            total_risk += risk_contribution * (control.risk_rating.value + 1)
        
        # Normalize to 0-100
        max_possible_risk = len(controls) * (RiskLevel.CRITICAL.value + 1)
        normalized_risk = (total_risk / max_possible_risk) * 100 if max_possible_risk > 0 else 0
        
        return round(normalized_risk, 2)


class MockPolicyManagementSystem:
    """Mock policy management system."""
    
    def __init__(self, database):
        self.database = database
        self.active_policies = {}
        self.policy_violations = []
        self.enforcement_rules = {}
        
        # Mock data for testing
        self.policy_creation_calls = []
        self.policy_approval_calls = []
        self.policy_enforcement_calls = []
    
    async def create_policy(self, policy_name: str, policy_type: PolicyType, description: str,
                           policy_statement: str, scope: str, owner: str,
                           roles_responsibilities: Dict[str, List[str]] = None,
                           enforcement_rules: Dict[str, Any] = None) -> str:
        """Mock create policy."""
        self.policy_creation_calls.append({
            'policy_name': policy_name,
            'policy_type': policy_type.value,
            'description': description,
            'owner': owner,
            'timestamp': datetime.now(timezone.utc)
        })
        
        policy_id = f"mock_policy_{policy_type.value}_{uuid.uuid4().hex[:12]}"
        
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
            return policy_id
        
        return ""
    
    async def approve_policy(self, policy_id: str, approved_by: str) -> bool:
        """Mock approve policy."""
        self.policy_approval_calls.append({
            'policy_id': policy_id,
            'approved_by': approved_by,
            'timestamp': datetime.now(timezone.utc)
        })
        
        if policy_id in self.active_policies:
            policy = self.active_policies[policy_id]
            policy.approval_status = "approved"
            policy.approved_by = approved_by
            policy.last_modified = datetime.now(timezone.utc)
            
            self.database.store_governance_policy(policy)
            return True
        
        return False
    
    async def enforce_policy(self, policy_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Mock enforce policy."""
        self.policy_enforcement_calls.append({
            'policy_id': policy_id,
            'context_keys': list(context.keys()),
            'timestamp': datetime.now(timezone.utc)
        })
        
        if policy_id not in self.active_policies:
            return {'allowed': False, 'reason': 'Policy not found'}
        
        policy = self.active_policies[policy_id]
        
        if policy.approval_status != "approved":
            return {'allowed': True, 'reason': 'Policy not yet approved'}
        
        # Mock enforcement logic
        user_roles = context.get('user_roles', [])
        
        # Simple mock enforcement - deny if user has no roles and policy requires them
        if policy.policy_type == PolicyType.ACCESS_CONTROL:
            if not user_roles:
                return {'allowed': False, 'reason': 'Access control policy requires user roles'}
        
        # Mock additional enforcement based on policy type
        if policy.policy_type == PolicyType.DATA_GOVERNANCE:
            data_classification = context.get('data_classification', 'public')
            if data_classification == 'restricted' and 'admin' not in user_roles:
                return {'allowed': False, 'reason': 'Restricted data requires admin access'}
        
        return {'allowed': True, 'reason': f'Mock {policy.policy_type.value} policy satisfied'}


class MockComplianceGovernanceFramework:
    """Mock compliance governance framework."""
    
    def __init__(self, db_path: str = "mock_compliance_governance.db"):
        self.database = MockComplianceGovernanceDatabase()
        self.compliance_engine = MockComplianceEngine(self.database)
        self.policy_system = MockPolicyManagementSystem(self.database)
        
        self.enabled = True
        self.continuous_monitoring = True
        self.audit_retention_days = 2557
        self.supported_frameworks = list(ComplianceFramework)
        
        # Mock data for testing
        self.framework_initialization_calls = []
        self.assessment_calls = []
        self.report_generation_calls = []
        self.dashboard_calls = []
    
    async def initialize_compliance_framework(self, framework: ComplianceFramework, 
                                            organization: str, owner: str) -> Dict[str, Any]:
        """Mock initialize compliance framework."""
        self.framework_initialization_calls.append({
            'framework': framework.value,
            'organization': organization,
            'owner': owner,
            'timestamp': datetime.now(timezone.utc)
        })
        
        # Mock initialization process
        control_ids = await self.compliance_engine.initialize_framework_controls(framework, owner)
        policy_ids = await self._mock_create_framework_policies(framework, organization, owner)
        
        result = {
            'framework': framework.value,
            'organization': organization,
            'controls_initialized': len(control_ids),
            'policies_created': len(policy_ids),
            'initial_assessment_scheduled': (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            'status': 'initialized',
            'mock_initialization': True
        }
        
        return result
    
    async def _mock_create_framework_policies(self, framework: ComplianceFramework, 
                                            organization: str, owner: str) -> List[str]:
        """Mock create framework policies."""
        policy_ids = []
        
        # Create 2-3 mock policies per framework
        mock_policies = [
            {
                'name': f'{organization} Mock Security Policy',
                'type': PolicyType.SECURITY_POLICY,
                'description': f'Mock security policy for {framework.value}',
                'statement': f'{organization} mock security policy statement.'
            },
            {
                'name': f'{organization} Mock Access Control Policy',
                'type': PolicyType.ACCESS_CONTROL,
                'description': 'Mock access control policy',
                'statement': 'Mock access control statement.'
            }
        ]
        
        # Add framework-specific mock policies
        if framework == ComplianceFramework.GDPR:
            mock_policies.append({
                'name': f'{organization} Mock Privacy Policy',
                'type': PolicyType.DATA_GOVERNANCE,
                'description': 'Mock GDPR privacy policy',
                'statement': 'Mock privacy policy statement.'
            })
        
        for policy_data in mock_policies:
            policy_id = await self.policy_system.create_policy(
                policy_name=policy_data['name'],
                policy_type=policy_data['type'],
                description=policy_data['description'],
                policy_statement=policy_data['statement'],
                scope=f'{organization} - Mock scope',
                owner=owner
            )
            
            if policy_id:
                policy_ids.append(policy_id)
        
        return policy_ids
    
    async def perform_compliance_assessment(self, framework: ComplianceFramework, 
                                          assessor: str, scope: str = None) -> ComplianceAssessment:
        """Mock perform compliance assessment."""
        self.assessment_calls.append({
            'framework': framework.value,
            'assessor': assessor,
            'scope': scope or "Full Organization Assessment",
            'timestamp': datetime.now(timezone.utc)
        })
        
        if scope is None:
            scope = "Full Organization Assessment"
        
        assessment = await self.compliance_engine.assess_compliance(framework, assessor, scope)
        
        return assessment
    
    async def generate_compliance_report(self, framework: ComplianceFramework, 
                                       assessment_id: Optional[str] = None) -> Dict[str, Any]:
        """Mock generate compliance report."""
        self.report_generation_calls.append({
            'framework': framework.value,
            'assessment_id': assessment_id,
            'timestamp': datetime.now(timezone.utc)
        })
        
        report_data = {
            'report_id': f'mock_report_{framework.value}_{uuid.uuid4().hex[:12]}',
            'framework': framework.value,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'report_type': 'compliance_status',
            'mock_report': True
        }
        
        # Mock assessment data
        if assessment_id:
            assessment = self.database.get_compliance_assessment(assessment_id)
            if assessment:
                report_data['assessment'] = assessment.to_dict()
        
        # Mock controls summary
        controls = self.database.get_security_controls(framework=framework)
        status_summary = defaultdict(int)
        for control in controls:
            status_summary[control.status.value] += 1
        
        report_data['controls_summary'] = dict(status_summary)
        report_data['total_controls'] = len(controls)
        
        # Mock compliance metrics
        implemented_controls = (
            status_summary.get('implemented', 0) + 
            status_summary.get('operating_effectively', 0)
        )
        compliance_percentage = (implemented_controls / len(controls)) * 100 if controls else 75.0  # Mock 75%
        
        report_data['compliance_metrics'] = {
            'compliance_percentage': round(compliance_percentage, 2),
            'implemented_controls': implemented_controls,
            'controls_needing_attention': len(controls) - implemented_controls
        }
        
        # Mock high-priority findings
        report_data['high_priority_findings'] = [
            {
                'control_id': 'MOCK-001',
                'control_name': 'Mock High Priority Control',
                'status': 'needs_improvement',
                'risk_rating': RiskLevel.HIGH.value
            }
        ]
        
        return report_data
    
    async def get_compliance_dashboard(self) -> Dict[str, Any]:
        """Mock get compliance dashboard."""
        self.dashboard_calls.append({
            'timestamp': datetime.now(timezone.utc)
        })
        
        dashboard_data = {
            'dashboard_id': f'mock_dashboard_{uuid.uuid4().hex[:8]}',
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'frameworks_status': {},
            'overall_metrics': {},
            'recent_activities': [],
            'risk_indicators': {},
            'mock_dashboard': True
        }
        
        # Mock framework status for each supported framework
        for framework in [ComplianceFramework.SOC2_TYPE2, ComplianceFramework.ISO27001, ComplianceFramework.GDPR]:
            controls = self.database.get_security_controls(framework=framework)
            if controls:
                compliance_score = 78.5  # Mock compliance score
                dashboard_data['frameworks_status'][framework.value] = {
                    'total_controls': len(controls),
                    'compliance_score': compliance_score,
                    'status_distribution': {
                        'operating_effectively': len(controls) // 2,
                        'implemented': len(controls) // 4,
                        'needs_improvement': len(controls) // 4
                    }
                }
        
        # Mock overall metrics
        all_controls = self.database.get_security_controls()
        dashboard_data['overall_metrics'] = {
            'total_controls': len(all_controls),
            'overall_compliance': 76.3,
            'critical_findings': 2,
            'overdue_assessments': 1
        }
        
        return dashboard_data


class MockComplianceGovernanceTestEnvironment:
    """Comprehensive mock environment for compliance governance testing."""
    
    def __init__(self):
        self.framework = MockComplianceGovernanceFramework()
        self.test_scenarios = self._generate_test_scenarios()
        self.performance_metrics = {
            'framework_initialization_times': [],
            'assessment_times': [],
            'policy_enforcement_times': [],
            'report_generation_times': []
        }
    
    def _generate_test_scenarios(self) -> List[Dict[str, Any]]:
        """Generate test scenarios for comprehensive testing."""
        scenarios = []
        
        # Scenario 1: SOC 2 Type II compliance initialization
        scenarios.append({
            'name': 'soc2_compliance_initialization',
            'type': 'framework_initialization',
            'data': {
                'framework': ComplianceFramework.SOC2_TYPE2,
                'organization': 'Test Corp',
                'owner': 'compliance_manager'
            }
        })
        
        # Scenario 2: ISO 27001 compliance assessment
        scenarios.append({
            'name': 'iso27001_compliance_assessment',
            'type': 'compliance_assessment',
            'data': {
                'framework': ComplianceFramework.ISO27001,
                'assessor': 'external_auditor',
                'scope': 'Full Organization Assessment'
            }
        })
        
        # Scenario 3: GDPR privacy compliance
        scenarios.append({
            'name': 'gdpr_privacy_compliance',
            'type': 'framework_initialization',
            'data': {
                'framework': ComplianceFramework.GDPR,
                'organization': 'Privacy Corp',
                'owner': 'privacy_officer'
            }
        })
        
        # Scenario 4: Access control policy enforcement
        scenarios.append({
            'name': 'access_control_policy_enforcement',
            'type': 'policy_enforcement',
            'data': {
                'policy_type': PolicyType.ACCESS_CONTROL,
                'context': {
                    'user_id': 'test_user',
                    'user_roles': ['user'],
                    'resource': '/api/sensitive',
                    'action': 'read'
                }
            }
        })
        
        # Scenario 5: Data governance policy creation
        scenarios.append({
            'name': 'data_governance_policy_creation',
            'type': 'policy_creation',
            'data': {
                'policy_name': 'Test Data Classification Policy',
                'policy_type': PolicyType.DATA_GOVERNANCE,
                'description': 'Test policy for data classification and protection',
                'policy_statement': 'All data shall be classified according to sensitivity levels',
                'scope': 'Organization-wide',
                'owner': 'data_steward'
            }
        })
        
        # Scenario 6: Compliance reporting
        scenarios.append({
            'name': 'compliance_reporting',
            'type': 'compliance_report',
            'data': {
                'framework': ComplianceFramework.SOC2_TYPE2
            }
        })
        
        return scenarios
    
    async def run_test_scenario(self, scenario_name: str) -> Dict[str, Any]:
        """Run a specific test scenario."""
        scenario = next((s for s in self.test_scenarios if s['name'] == scenario_name), None)
        if not scenario:
            return {'error': 'Scenario not found'}
        
        start_time = time.time()
        result = {'scenario': scenario_name}
        
        try:
            if scenario['type'] == 'framework_initialization':
                data = scenario['data']
                init_result = await self.framework.initialize_compliance_framework(**data)
                result.update({
                    'initialization_result': init_result,
                    'type': 'framework_initialization'
                })
                
                # Track performance
                init_time = (time.time() - start_time) * 1000
                self.performance_metrics['framework_initialization_times'].append(init_time)
                result['initialization_time_ms'] = init_time
                
            elif scenario['type'] == 'compliance_assessment':
                data = scenario['data']
                assessment_start = time.time()
                assessment = await self.framework.perform_compliance_assessment(**data)
                assessment_time = (time.time() - assessment_start) * 1000
                
                result.update({
                    'assessment': assessment.to_dict(),
                    'type': 'compliance_assessment',
                    'assessment_time_ms': assessment_time
                })
                self.performance_metrics['assessment_times'].append(assessment_time)
                
            elif scenario['type'] == 'policy_enforcement':
                # First create a policy
                policy_data = scenario['data']
                policy_id = await self.framework.policy_system.create_policy(
                    policy_name='Test Access Control Policy',
                    policy_type=policy_data['policy_type'],
                    description='Test policy for enforcement',
                    policy_statement='Test policy statement',
                    scope='Test scope',
                    owner='test_owner'
                )
                
                # Approve the policy
                await self.framework.policy_system.approve_policy(policy_id, 'test_approver')
                
                # Enforce the policy
                enforce_start = time.time()
                enforcement_result = await self.framework.policy_system.enforce_policy(
                    policy_id, policy_data['context']
                )
                enforce_time = (time.time() - enforce_start) * 1000
                
                result.update({
                    'policy_id': policy_id,
                    'enforcement_result': enforcement_result,
                    'type': 'policy_enforcement',
                    'enforcement_time_ms': enforce_time
                })
                self.performance_metrics['policy_enforcement_times'].append(enforce_time)
                
            elif scenario['type'] == 'policy_creation':
                data = scenario['data']
                policy_id = await self.framework.policy_system.create_policy(**data)
                result.update({
                    'policy_id': policy_id,
                    'type': 'policy_creation'
                })
                
            elif scenario['type'] == 'compliance_report':
                data = scenario['data']
                report_start = time.time()
                report = await self.framework.generate_compliance_report(**data)
                report_time = (time.time() - report_start) * 1000
                
                result.update({
                    'report': report,
                    'type': 'compliance_report',
                    'report_time_ms': report_time
                })
                self.performance_metrics['report_generation_times'].append(report_time)
            
            total_time = (time.time() - start_time) * 1000
            result['total_time_ms'] = total_time
            
        except Exception as e:
            result.update({
                'error': str(e),
                'status': 'failed'
            })
        
        return result
    
    async def run_all_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Run all test scenarios."""
        results = {}
        
        for scenario in self.test_scenarios:
            scenario_name = scenario['name']
            results[scenario_name] = await self.run_test_scenario(scenario_name)
        
        return results
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        metrics = {}
        
        for metric_type, values in self.performance_metrics.items():
            if values:
                metrics[metric_type] = {
                    'count': len(values),
                    'avg_ms': sum(values) / len(values),
                    'min_ms': min(values),
                    'max_ms': max(values)
                }
            else:
                metrics[metric_type] = {
                    'count': 0,
                    'avg_ms': 0,
                    'min_ms': 0,
                    'max_ms': 0
                }
        
        return metrics
    
    async def simulate_compliance_load_test(self, num_assessments: int = 20) -> Dict[str, Any]:
        """Simulate load testing with multiple compliance assessments."""
        load_results = {
            'assessments_completed': 0,
            'policies_created': 0,
            'total_time': 0,
            'avg_assessment_time': 0,
            'errors': 0
        }
        
        start_time = time.time()
        
        # Initialize a framework first
        await self.framework.initialize_compliance_framework(
            ComplianceFramework.SOC2_TYPE2, 'Load Test Corp', 'load_test_owner'
        )
        
        # Create multiple assessments concurrently
        tasks = []
        for i in range(num_assessments):
            # Alternate between different frameworks
            frameworks = [ComplianceFramework.SOC2_TYPE2, ComplianceFramework.ISO27001, ComplianceFramework.GDPR]
            framework = frameworks[i % len(frameworks)]
            
            task = self.framework.perform_compliance_assessment(
                framework=framework,
                assessor=f'load_test_assessor_{i}',
                scope=f'Load test assessment {i}'
            )
            tasks.append(task)
        
        # Wait for all assessments to complete
        try:
            assessments = await asyncio.gather(*tasks, return_exceptions=True)
            for assessment in assessments:
                if isinstance(assessment, Exception):
                    load_results['errors'] += 1
                else:
                    load_results['assessments_completed'] += 1
        except Exception as e:
            load_results['errors'] += 1
        
        total_time = time.time() - start_time
        load_results['total_time'] = total_time
        
        if load_results['assessments_completed'] > 0:
            load_results['avg_assessment_time'] = (total_time / load_results['assessments_completed']) * 1000
        
        return load_results
    
    def cleanup(self):
        """Cleanup test environment."""
        self.performance_metrics = {
            'framework_initialization_times': [],
            'assessment_times': [],
            'policy_enforcement_times': [],
            'report_generation_times': []
        }


# Export all mock classes
__all__ = [
    'MockComplianceGovernanceDatabase',
    'MockComplianceEngine',
    'MockPolicyManagementSystem',
    'MockComplianceGovernanceFramework',
    'MockComplianceGovernanceTestEnvironment'
]