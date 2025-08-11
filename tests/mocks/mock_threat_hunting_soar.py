"""Mock infrastructure for Threat Hunting and SOAR platform testing."""

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

from src.fastapi_shield.threat_hunting_soar import (
    ThreatLevel, ThreatType, IncidentStatus, PlaybookStatus, ResponseAction,
    IntegrationType, EvidenceType,
    ThreatIndicator, SecurityIncident, SecurityPlaybook, PlaybookExecution,
    ThreatHuntingHypothesis, EvidenceArtifact
)


class MockThreatHuntingDatabase:
    """Mock threat hunting database for testing."""
    
    def __init__(self):
        self.threat_indicators = {}
        self.security_incidents = {}
        self.security_playbooks = {}
        self.playbook_executions = {}
        self.hunting_hypotheses = {}
        self.evidence_artifacts = {}
        self.integrations = {}
        self.threat_intel_feeds = {}
        self.security_metrics = []
        self.storage_calls = []
        self.query_calls = []
    
    def store_threat_indicator(self, indicator: ThreatIndicator) -> bool:
        """Mock store threat indicator."""
        self.storage_calls.append(('threat_indicator', indicator.indicator_id))
        self.threat_indicators[indicator.indicator_id] = indicator
        return True
    
    def store_security_incident(self, incident: SecurityIncident) -> bool:
        """Mock store security incident."""
        self.storage_calls.append(('security_incident', incident.incident_id))
        self.security_incidents[incident.incident_id] = incident
        return True
    
    def store_security_playbook(self, playbook: SecurityPlaybook) -> bool:
        """Mock store security playbook."""
        self.storage_calls.append(('security_playbook', playbook.playbook_id))
        self.security_playbooks[playbook.playbook_id] = playbook
        return True
    
    def store_playbook_execution(self, execution: PlaybookExecution) -> bool:
        """Mock store playbook execution."""
        self.storage_calls.append(('playbook_execution', execution.execution_id))
        self.playbook_executions[execution.execution_id] = execution
        return True
    
    def get_threat_indicators(self, indicator_type: Optional[str] = None, limit: int = 1000) -> List[ThreatIndicator]:
        """Mock get threat indicators."""
        self.query_calls.append(('threat_indicators', indicator_type, limit))
        
        indicators = list(self.threat_indicators.values())
        
        if indicator_type:
            indicators = [i for i in indicators if i.indicator_type == indicator_type]
        
        # Sort by last_seen desc and limit
        indicators.sort(key=lambda x: x.last_seen, reverse=True)
        return indicators[:limit]
    
    def get_security_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        """Mock get security incident."""
        self.query_calls.append(('security_incident', incident_id))
        return self.security_incidents.get(incident_id)


class MockThreatHuntingEngine:
    """Mock threat hunting engine for testing."""
    
    def __init__(self, database):
        self.database = database
        self.active_hypotheses = {}
        self.threat_patterns = {}
        self.behavioral_baselines = {}
        self.detection_rules = {
            'lateral_movement': {
                'pattern': r'(psexec|wmic|net use|runas)',
                'threshold': 5,
                'time_window': 3600,
                'mitre_techniques': ['T1021', 'T1047']
            },
            'credential_dumping': {
                'pattern': r'(mimikatz|lsadump|secretsdump|procdump)',
                'threshold': 1,
                'time_window': 300,
                'mitre_techniques': ['T1003', 'T1558']
            }
        }
        
        # Mock data for testing
        self.hypothesis_creation_calls = []
        self.threat_hunt_calls = []
        self.mock_findings = []
    
    async def create_hunting_hypothesis(self, title: str, description: str, threat_types: List[ThreatType], 
                                       mitre_techniques: List[str], data_sources: List[str],
                                       query_logic: Dict[str, Any], created_by: str) -> str:
        """Mock create hunting hypothesis."""
        self.hypothesis_creation_calls.append({
            'title': title,
            'threat_types': [t.value for t in threat_types],
            'mitre_techniques': mitre_techniques,
            'data_sources': data_sources,
            'created_by': created_by
        })
        
        hypothesis_id = f"mock_hypothesis_{uuid.uuid4().hex[:12]}"
        
        hypothesis = ThreatHuntingHypothesis(
            hypothesis_id=hypothesis_id,
            title=title,
            description=description,
            threat_types=threat_types,
            mitre_techniques=mitre_techniques,
            data_sources=data_sources,
            query_logic=query_logic,
            created_by=created_by,
            created_at=datetime.now(timezone.utc)
        )
        
        self.active_hypotheses[hypothesis_id] = hypothesis
        return hypothesis_id
    
    async def execute_threat_hunt(self, hypothesis_id: str, data_sources: Dict[str, Any]) -> Dict[str, Any]:
        """Mock execute threat hunt."""
        self.threat_hunt_calls.append({
            'hypothesis_id': hypothesis_id,
            'data_sources': list(data_sources.keys())
        })
        
        if hypothesis_id not in self.active_hypotheses:
            return {'error': 'Hypothesis not found'}
        
        # Generate mock findings
        findings = self._generate_mock_findings(data_sources)
        pattern_matches = self._generate_mock_pattern_matches(findings)
        
        return {
            'hypothesis_id': hypothesis_id,
            'findings_count': len(findings),
            'findings': findings,
            'pattern_matches': pattern_matches,
            'indicators_generated': len(findings) // 2,  # Mock indicator generation
            'confidence_score': 0.75,
            'recommendations': self._generate_mock_recommendations(findings)
        }
    
    def _generate_mock_findings(self, data_sources: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate mock hunting findings."""
        findings = []
        
        for source_name, source_data in data_sources.items():
            if source_name == 'logs':
                findings.extend([
                    {
                        'type': 'pattern_match',
                        'pattern': 'psexec',
                        'count': 3,
                        'threat_score': 7.0,
                        'source': source_name
                    },
                    {
                        'type': 'suspicious_command',
                        'command_line': 'powershell.exe -enc aGVsbG8=',
                        'threat_score': 6.0,
                        'source': source_name
                    }
                ])
            elif source_name == 'network':
                findings.extend([
                    {
                        'type': 'suspicious_domain',
                        'domain': 'malicious-c2.com',
                        'threat_score': 9.0,
                        'source': source_name
                    },
                    {
                        'type': 'port_scanning',
                        'src_ip': '192.168.1.50',
                        'connections_count': 150,
                        'threat_score': 8.0,
                        'source': source_name
                    }
                ])
        
        return findings
    
    def _generate_mock_pattern_matches(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate mock pattern match analysis."""
        return {
            'total_findings': len(findings),
            'threat_types': {
                'pattern_match': 1,
                'suspicious_command': 1,
                'suspicious_domain': 1,
                'port_scanning': 1
            },
            'mitre_coverage': ['T1021', 'T1047', 'T1059'],
            'severity_distribution': {
                'high': 2,
                'medium': 2,
                'low': 0
            }
        }
    
    def _generate_mock_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate mock recommendations."""
        recommendations = []
        
        if any(f['type'] == 'suspicious_domain' for f in findings):
            recommendations.append("Consider blocking identified suspicious domains in DNS security controls")
        
        if any(f['type'] == 'port_scanning' for f in findings):
            recommendations.append("Implement network segmentation to limit lateral movement")
        
        if any(f['type'] == 'suspicious_command' for f in findings):
            recommendations.append("Deploy additional endpoint monitoring and response capabilities")
        
        return recommendations


class MockSecurityOrchestrationEngine:
    """Mock security orchestration engine for testing."""
    
    def __init__(self, database):
        self.database = database
        self.active_executions = {}
        self.playbook_registry = {}
        self.integration_handlers = {}
        self.response_actions = {}
        
        # Mock data for testing
        self.playbook_creation_calls = []
        self.playbook_execution_calls = []
        self.workflow_step_calls = []
        
        # Initialize mock response actions
        self._initialize_mock_response_actions()
    
    def _initialize_mock_response_actions(self):
        """Initialize mock response actions."""
        self.response_actions = {
            ResponseAction.ALERT: self._mock_send_alert,
            ResponseAction.BLOCK_IP: self._mock_block_ip,
            ResponseAction.ISOLATE_HOST: self._mock_isolate_host,
            ResponseAction.QUARANTINE_FILE: self._mock_quarantine_file,
            ResponseAction.RESET_PASSWORD: self._mock_reset_password,
            ResponseAction.DISABLE_ACCOUNT: self._mock_disable_account,
            ResponseAction.COLLECT_EVIDENCE: self._mock_collect_evidence,
            ResponseAction.ESCALATE: self._mock_escalate_incident,
            ResponseAction.NOTIFY_ADMIN: self._mock_notify_admin,
            ResponseAction.CREATE_TICKET: self._mock_create_ticket
        }
    
    async def create_security_playbook(self, name: str, description: str, trigger_conditions: Dict[str, Any],
                                     workflow_steps: List[Dict[str, Any]], approval_required: bool = False,
                                     timeout_minutes: int = 60, tags: List[str] = None) -> str:
        """Mock create security playbook."""
        self.playbook_creation_calls.append({
            'name': name,
            'description': description,
            'trigger_conditions': trigger_conditions,
            'workflow_steps': len(workflow_steps),
            'approval_required': approval_required,
            'timeout_minutes': timeout_minutes,
            'tags': tags or []
        })
        
        playbook_id = f"mock_playbook_{uuid.uuid4().hex[:12]}"
        
        playbook = SecurityPlaybook(
            playbook_id=playbook_id,
            name=name,
            description=description,
            trigger_conditions=trigger_conditions,
            workflow_steps=workflow_steps,
            approval_required=approval_required,
            timeout_minutes=timeout_minutes,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            tags=tags or []
        )
        
        self.playbook_registry[playbook_id] = playbook
        self.database.store_security_playbook(playbook)
        
        return playbook_id
    
    async def execute_playbook(self, playbook_id: str, incident_id: str, executed_by: str,
                             execution_context: Dict[str, Any] = None) -> str:
        """Mock execute playbook."""
        self.playbook_execution_calls.append({
            'playbook_id': playbook_id,
            'incident_id': incident_id,
            'executed_by': executed_by,
            'execution_context': execution_context or {}
        })
        
        if playbook_id not in self.playbook_registry:
            return ""
        
        execution_id = f"mock_exec_{uuid.uuid4().hex[:12]}"
        playbook = self.playbook_registry[playbook_id]
        
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_id=playbook_id,
            incident_id=incident_id,
            status=PlaybookStatus.PENDING,
            started_at=datetime.now(timezone.utc),
            completed_at=None,
            current_step=0,
            total_steps=len(playbook.workflow_steps),
            executed_by=executed_by
        )
        
        self.active_executions[execution_id] = execution
        self.database.store_playbook_execution(execution)
        
        # Simulate quick execution for testing
        asyncio.create_task(self._mock_execute_playbook_workflow(execution_id, execution_context or {}))
        
        return execution_id
    
    async def _mock_execute_playbook_workflow(self, execution_id: str, context: Dict[str, Any]):
        """Mock playbook workflow execution."""
        try:
            execution = self.active_executions.get(execution_id)
            if not execution:
                return
            
            playbook = self.playbook_registry.get(execution.playbook_id)
            if not playbook:
                return
            
            # Simulate execution
            execution.status = PlaybookStatus.RUNNING
            
            for step_index, step in enumerate(playbook.workflow_steps):
                execution.current_step = step_index + 1
                
                # Mock step execution
                step_result = await self._mock_execute_workflow_step(step, context)
                execution.results[f'step_{step_index + 1}'] = step_result
                
                # Add to execution log
                execution.execution_log.append({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'step': step_index + 1,
                    'action': 'step_completed',
                    'result': step_result
                })
                
                # Brief delay to simulate processing
                await asyncio.sleep(0.1)
            
            # Mark as completed
            execution.status = PlaybookStatus.COMPLETED
            execution.completed_at = datetime.now(timezone.utc)
            self.database.store_playbook_execution(execution)
            
        except Exception as e:
            execution.status = PlaybookStatus.FAILED
            execution.errors.append(str(e))
            execution.completed_at = datetime.now(timezone.utc)
            self.database.store_playbook_execution(execution)
    
    async def _mock_execute_workflow_step(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Mock execute workflow step."""
        self.workflow_step_calls.append({
            'step_type': step.get('type'),
            'step_name': step.get('name'),
            'parameters': step.get('parameters', {})
        })
        
        step_type = step.get('type', '')
        
        if step_type == 'response_action':
            action_type = ResponseAction(step['parameters'].get('action'))
            if action_type in self.response_actions:
                result = await self.response_actions[action_type](context)
                return {'success': True, 'result': result}
        
        elif step_type == 'delay':
            await asyncio.sleep(0.01)  # Very short delay for testing
            return {'success': True, 'delayed': 0.01}
        
        elif step_type == 'conditional':
            # Mock conditional execution
            return {'success': True, 'condition_evaluated': True}
        
        # Default success response
        return {'success': True, 'mock_execution': True}
    
    # Mock response action implementations
    async def _mock_send_alert(self, params: Dict[str, Any]) -> str:
        """Mock send alert."""
        message = params.get('message', 'Mock security alert')
        return f"Mock alert sent: {message}"
    
    async def _mock_block_ip(self, params: Dict[str, Any]) -> str:
        """Mock block IP."""
        ip = params.get('ip_address', '192.168.1.1')
        return f"Mock IP blocked: {ip}"
    
    async def _mock_isolate_host(self, params: Dict[str, Any]) -> str:
        """Mock isolate host."""
        hostname = params.get('hostname', 'test-host')
        return f"Mock host isolated: {hostname}"
    
    async def _mock_quarantine_file(self, params: Dict[str, Any]) -> str:
        """Mock quarantine file."""
        file_path = params.get('file_path', '/tmp/malware.exe')
        return f"Mock file quarantined: {file_path}"
    
    async def _mock_reset_password(self, params: Dict[str, Any]) -> str:
        """Mock reset password."""
        username = params.get('username', 'testuser')
        return f"Mock password reset for: {username}"
    
    async def _mock_disable_account(self, params: Dict[str, Any]) -> str:
        """Mock disable account."""
        username = params.get('username', 'testuser')
        return f"Mock account disabled: {username}"
    
    async def _mock_collect_evidence(self, params: Dict[str, Any]) -> str:
        """Mock collect evidence."""
        hostname = params.get('hostname', 'test-host')
        return f"Mock evidence collected from: {hostname}"
    
    async def _mock_escalate_incident(self, params: Dict[str, Any]) -> str:
        """Mock escalate incident."""
        incident_id = params.get('incident_id', 'incident_123')
        return f"Mock incident escalated: {incident_id}"
    
    async def _mock_notify_admin(self, params: Dict[str, Any]) -> str:
        """Mock notify admin."""
        message = params.get('message', 'Mock notification')
        return f"Mock admin notified: {message}"
    
    async def _mock_create_ticket(self, params: Dict[str, Any]) -> str:
        """Mock create ticket."""
        title = params.get('title', 'Mock Security Ticket')
        ticket_id = f"MOCK-{uuid.uuid4().hex[:8].upper()}"
        return f"Mock ticket created: {ticket_id} - {title}"


class MockThreatHuntingPlatform:
    """Mock threat hunting platform for testing."""
    
    def __init__(self, db_path: str = "mock_threat_hunting.db"):
        self.database = MockThreatHuntingDatabase()
        self.hunting_engine = MockThreatHuntingEngine(self.database)
        self.orchestration_engine = MockSecurityOrchestrationEngine(self.database)
        
        self.enabled = True
        self.auto_response_enabled = True
        self.threat_intelligence_feeds = {}
        self.integration_config = {}
        
        # Mock data for testing
        self.incident_creation_calls = []
        self.intelligence_processing_calls = []
    
    async def create_security_incident(self, title: str, description: str, threat_type: ThreatType,
                                     threat_level: ThreatLevel, source_ip: Optional[str] = None,
                                     target_assets: List[str] = None, indicators: List[str] = None,
                                     mitre_techniques: List[str] = None) -> str:
        """Mock create security incident."""
        self.incident_creation_calls.append({
            'title': title,
            'threat_type': threat_type.value,
            'threat_level': threat_level.value,
            'source_ip': source_ip,
            'target_assets': target_assets or [],
            'indicators': indicators or [],
            'mitre_techniques': mitre_techniques or []
        })
        
        incident_id = f"mock_incident_{uuid.uuid4().hex[:12]}"
        
        incident = SecurityIncident(
            incident_id=incident_id,
            title=title,
            description=description,
            threat_type=threat_type,
            threat_level=threat_level,
            status=IncidentStatus.NEW,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            source_ip=source_ip,
            target_assets=target_assets or [],
            indicators=indicators or [],
            mitre_techniques=mitre_techniques or []
        )
        
        self.database.store_security_incident(incident)
        
        # Trigger automated response if enabled
        if self.auto_response_enabled:
            await self._mock_trigger_automated_response(incident)
        
        return incident_id
    
    async def _mock_trigger_automated_response(self, incident: SecurityIncident):
        """Mock trigger automated response."""
        # Find mock matching playbooks
        matching_playbooks = []
        
        for playbook_id, playbook in self.orchestration_engine.playbook_registry.items():
            triggers = playbook.trigger_conditions
            
            # Simple mock matching logic
            if 'threat_types' in triggers:
                if incident.threat_type.value in triggers['threat_types']:
                    matching_playbooks.append(playbook_id)
            else:
                # Default match for testing
                matching_playbooks.append(playbook_id)
        
        # Execute matching playbooks
        for playbook_id in matching_playbooks:
            execution_context = {
                'incident_id': incident.incident_id,
                'threat_type': incident.threat_type.value,
                'threat_level': incident.threat_level.value
            }
            
            await self.orchestration_engine.execute_playbook(
                playbook_id, incident.incident_id, 'system', execution_context
            )
    
    async def process_threat_intelligence(self, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mock process threat intelligence."""
        self.intelligence_processing_calls.append({
            'source': intelligence_data.get('source', 'unknown'),
            'indicators_count': len(intelligence_data.get('indicators', []))
        })
        
        indicators_processed = 0
        new_indicators = []
        
        # Mock processing of indicators
        for ioc_data in intelligence_data.get('indicators', []):
            indicator_id = f"mock_intel_{uuid.uuid4().hex[:12]}"
            
            indicator = ThreatIndicator(
                indicator_id=indicator_id,
                indicator_type=ioc_data.get('type', 'unknown'),
                indicator_value=ioc_data.get('value', ''),
                threat_type=ThreatType(ioc_data.get('threat_type', 'malware')),
                threat_level=ThreatLevel(ioc_data.get('threat_level', 2)),
                confidence_score=float(ioc_data.get('confidence', 0.5)),
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                source=intelligence_data.get('source', 'mock_feed')
            )
            
            self.database.store_threat_indicator(indicator)
            indicators_processed += 1
            new_indicators.append(indicator_id)
        
        return {
            'indicators_processed': indicators_processed,
            'new_indicators': new_indicators,
            'processing_timestamp': datetime.now(timezone.utc).isoformat(),
            'mock_processing': True
        }
    
    async def get_platform_metrics(self) -> Dict[str, Any]:
        """Mock get platform metrics."""
        return {
            'platform_status': 'operational',
            'incidents': {
                'new': len([i for i in self.database.security_incidents.values() if i.status == IncidentStatus.NEW]),
                'investigating': len([i for i in self.database.security_incidents.values() if i.status == IncidentStatus.INVESTIGATING]),
                'closed': len([i for i in self.database.security_incidents.values() if i.status == IncidentStatus.CLOSED])
            },
            'threat_levels': {
                'critical': len([i for i in self.database.security_incidents.values() if i.threat_level == ThreatLevel.CRITICAL]),
                'high': len([i for i in self.database.security_incidents.values() if i.threat_level == ThreatLevel.HIGH]),
                'medium': len([i for i in self.database.security_incidents.values() if i.threat_level == ThreatLevel.MEDIUM]),
                'low': len([i for i in self.database.security_incidents.values() if i.threat_level == ThreatLevel.LOW])
            },
            'playbook_executions': {
                'running': len([e for e in self.database.playbook_executions.values() if e.status == PlaybookStatus.RUNNING]),
                'completed': len([e for e in self.database.playbook_executions.values() if e.status == PlaybookStatus.COMPLETED]),
                'failed': len([e for e in self.database.playbook_executions.values() if e.status == PlaybookStatus.FAILED])
            },
            'total_indicators': len(self.database.threat_indicators),
            'total_hypotheses': len(self.database.hunting_hypotheses),
            'total_evidence': len(self.database.evidence_artifacts),
            'active_executions': len(self.orchestration_engine.active_executions),
            'active_hypotheses': len(self.hunting_engine.active_hypotheses),
            'last_updated': datetime.now(timezone.utc).isoformat(),
            'mock_metrics': True
        }


class MockThreatHuntingTestEnvironment:
    """Comprehensive mock environment for threat hunting and SOAR testing."""
    
    def __init__(self):
        self.platform = MockThreatHuntingPlatform()
        self.test_scenarios = self._generate_test_scenarios()
        self.performance_metrics = {
            'incident_response_times': [],
            'playbook_execution_times': [],
            'threat_hunt_times': [],
            'intelligence_processing_times': []
        }
    
    def _generate_test_scenarios(self) -> List[Dict[str, Any]]:
        """Generate test scenarios for comprehensive testing."""
        scenarios = []
        
        # Scenario 1: High-severity malware incident
        scenarios.append({
            'name': 'malware_incident_high_severity',
            'type': 'incident',
            'data': {
                'title': 'Critical Malware Detection',
                'description': 'Ransomware detected on multiple endpoints',
                'threat_type': ThreatType.RANSOMWARE,
                'threat_level': ThreatLevel.CRITICAL,
                'source_ip': '192.168.1.100',
                'target_assets': ['workstation-01', 'server-db-01'],
                'indicators': ['hash_abc123', 'domain_malicious.com'],
                'mitre_techniques': ['T1486', 'T1055']
            }
        })
        
        # Scenario 2: APT lateral movement
        scenarios.append({
            'name': 'apt_lateral_movement',
            'type': 'incident',
            'data': {
                'title': 'APT Lateral Movement Detected',
                'description': 'Suspicious lateral movement across network segments',
                'threat_type': ThreatType.APT,
                'threat_level': ThreatLevel.HIGH,
                'source_ip': '10.0.1.50',
                'target_assets': ['server-01', 'server-02', 'server-03'],
                'indicators': ['psexec_usage', 'wmi_lateral'],
                'mitre_techniques': ['T1021', 'T1047']
            }
        })
        
        # Scenario 3: Data exfiltration attempt
        scenarios.append({
            'name': 'data_exfiltration',
            'type': 'incident',
            'data': {
                'title': 'Data Exfiltration Attempt',
                'description': 'Unusual data transfer patterns detected',
                'threat_type': ThreatType.DATA_EXFILTRATION,
                'threat_level': ThreatLevel.HIGH,
                'source_ip': '172.16.1.25',
                'target_assets': ['fileserver-01'],
                'indicators': ['large_file_transfer', 'encrypted_channel'],
                'mitre_techniques': ['T1041', 'T1048']
            }
        })
        
        # Scenario 4: Threat hunting hypothesis
        scenarios.append({
            'name': 'hunt_credential_dumping',
            'type': 'hunting_hypothesis',
            'data': {
                'title': 'Credential Dumping Activity Hunt',
                'description': 'Hunt for credential dumping tools and techniques',
                'threat_types': [ThreatType.INSIDER_THREAT, ThreatType.APT],
                'mitre_techniques': ['T1003', 'T1558'],
                'data_sources': ['logs', 'endpoints'],
                'query_logic': {
                    'patterns': ['mimikatz', 'lsadump', 'secretsdump'],
                    'time_window': 3600,
                    'threshold': 1
                },
                'created_by': 'analyst_smith'
            }
        })
        
        # Scenario 5: Security playbook creation
        scenarios.append({
            'name': 'malware_response_playbook',
            'type': 'security_playbook',
            'data': {
                'name': 'Malware Incident Response',
                'description': 'Automated response to malware incidents',
                'trigger_conditions': {
                    'threat_types': ['malware', 'ransomware'],
                    'min_threat_level': 3
                },
                'workflow_steps': [
                    {
                        'name': 'Send Alert',
                        'type': 'response_action',
                        'parameters': {'action': 'alert', 'message': 'Malware detected'}
                    },
                    {
                        'name': 'Isolate Host',
                        'type': 'response_action',
                        'parameters': {'action': 'isolate_host'}
                    },
                    {
                        'name': 'Collect Evidence',
                        'type': 'response_action',
                        'parameters': {'action': 'collect_evidence'}
                    }
                ],
                'approval_required': False,
                'timeout_minutes': 30,
                'tags': ['malware', 'automated']
            }
        })
        
        # Scenario 6: Threat intelligence processing
        scenarios.append({
            'name': 'threat_intel_feed',
            'type': 'threat_intelligence',
            'data': {
                'source': 'test_feed',
                'indicators': [
                    {
                        'type': 'domain',
                        'value': 'malicious-c2.com',
                        'threat_type': 'command_and_control',
                        'threat_level': 4,
                        'confidence': 0.9
                    },
                    {
                        'type': 'ip',
                        'value': '203.0.113.100',
                        'threat_type': 'malware',
                        'threat_level': 3,
                        'confidence': 0.8
                    },
                    {
                        'type': 'file_hash',
                        'value': 'abc123def456',
                        'threat_type': 'ransomware',
                        'threat_level': 4,
                        'confidence': 0.95
                    }
                ]
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
            if scenario['type'] == 'incident':
                data = scenario['data']
                incident_id = await self.platform.create_security_incident(**data)
                result.update({
                    'incident_id': incident_id,
                    'status': 'created',
                    'type': 'incident'
                })
                
                # Track response time
                response_time = (time.time() - start_time) * 1000
                self.performance_metrics['incident_response_times'].append(response_time)
                result['response_time_ms'] = response_time
                
            elif scenario['type'] == 'hunting_hypothesis':
                data = scenario['data']
                hypothesis_id = await self.platform.hunting_engine.create_hunting_hypothesis(**data)
                result.update({
                    'hypothesis_id': hypothesis_id,
                    'status': 'created',
                    'type': 'hunting_hypothesis'
                })
                
                # Execute the hunt with mock data
                mock_data_sources = {
                    'logs': {'entries': [{'message': 'mimikatz detected', 'timestamp': datetime.now(timezone.utc)}]},
                    'endpoints': {'processes': [{'name': 'lsass.exe', 'command_line': 'mimikatz.exe'}]}
                }
                
                hunt_start = time.time()
                hunt_result = await self.platform.hunting_engine.execute_threat_hunt(hypothesis_id, mock_data_sources)
                hunt_time = (time.time() - hunt_start) * 1000
                
                result['hunt_result'] = hunt_result
                result['hunt_time_ms'] = hunt_time
                self.performance_metrics['threat_hunt_times'].append(hunt_time)
                
            elif scenario['type'] == 'security_playbook':
                data = scenario['data']
                playbook_id = await self.platform.orchestration_engine.create_security_playbook(**data)
                result.update({
                    'playbook_id': playbook_id,
                    'status': 'created',
                    'type': 'security_playbook'
                })
                
                # Test playbook execution
                test_incident_id = 'test_incident_123'
                exec_start = time.time()
                execution_id = await self.platform.orchestration_engine.execute_playbook(
                    playbook_id, test_incident_id, 'test_user'
                )
                exec_time = (time.time() - exec_start) * 1000
                
                result['execution_id'] = execution_id
                result['execution_time_ms'] = exec_time
                self.performance_metrics['playbook_execution_times'].append(exec_time)
                
            elif scenario['type'] == 'threat_intelligence':
                data = scenario['data']
                intel_start = time.time()
                intel_result = await self.platform.process_threat_intelligence(data)
                intel_time = (time.time() - intel_start) * 1000
                
                result.update({
                    'intelligence_result': intel_result,
                    'intel_time_ms': intel_time,
                    'type': 'threat_intelligence'
                })
                self.performance_metrics['intelligence_processing_times'].append(intel_time)
            
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
    
    async def simulate_load_test(self, num_incidents: int = 50) -> Dict[str, Any]:
        """Simulate load testing with multiple incidents."""
        load_results = {
            'incidents_created': 0,
            'playbooks_executed': 0,
            'total_time': 0,
            'avg_incident_time': 0,
            'errors': 0
        }
        
        start_time = time.time()
        
        # Create multiple incidents concurrently
        tasks = []
        for i in range(num_incidents):
            task = self.platform.create_security_incident(
                title=f"Load Test Incident {i}",
                description=f"Automated load test incident {i}",
                threat_type=ThreatType.MALWARE,
                threat_level=ThreatLevel.MEDIUM,
                source_ip=f"192.168.1.{100 + (i % 155)}"
            )
            tasks.append(task)
        
        # Wait for all incidents to be created
        try:
            incident_ids = await asyncio.gather(*tasks)
            load_results['incidents_created'] = len([id for id in incident_ids if id])
        except Exception as e:
            load_results['errors'] += 1
        
        total_time = time.time() - start_time
        load_results['total_time'] = total_time
        
        if load_results['incidents_created'] > 0:
            load_results['avg_incident_time'] = (total_time / load_results['incidents_created']) * 1000
        
        return load_results
    
    def cleanup(self):
        """Cleanup test environment."""
        self.performance_metrics = {
            'incident_response_times': [],
            'playbook_execution_times': [],
            'threat_hunt_times': [],
            'intelligence_processing_times': []
        }


# Export all mock classes
__all__ = [
    'MockThreatHuntingDatabase',
    'MockThreatHuntingEngine',
    'MockSecurityOrchestrationEngine',
    'MockThreatHuntingPlatform',
    'MockThreatHuntingTestEnvironment'
]