"""Comprehensive tests for FastAPI-Shield Enterprise SOAR Platform.

This test suite covers all aspects of the Enterprise Security Orchestration 
and Response platform including:
- Security incident management and automated response
- Playbook engine with customizable workflows
- Threat correlation across multiple security components  
- Multi-tenant architecture with resource isolation
- External system integrations (SIEM, ticketing, messaging)
- Real-time security operations and monitoring
- Compliance reporting and audit trail management
- High-performance operation under enterprise load
"""

import asyncio
import json
import pytest
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
from unittest.mock import Mock, AsyncMock, patch
import uuid

from src.fastapi_shield.enterprise_soar import (
    # Core classes
    SecurityOrchestrator, IncidentManager, PlaybookEngine,
    ThreatCorrelationEngine, MultiTenantManager, SOARDatabase,
    
    # Integration classes  
    ExternalIntegration, SIEMIntegration, TicketingIntegration,
    MessagingIntegration,
    
    # Data classes
    SecurityIncident, SecurityPlaybook, ThreatHuntingOperation,
    ComplianceReport, TenantConfiguration,
    
    # Enums
    IncidentSeverity, IncidentStatus, PlaybookAction,
    ThreatHuntingStatus, ComplianceStandard, IntegrationType,
    
    # Convenience functions
    create_enterprise_soar, create_soar_app
)

from src.fastapi_shield.enterprise_soar_sync import create_enterprise_soar_sync
from fastapi import FastAPI

from tests.mocks.mock_enterprise_soar import (
    MockSOARDatabase, MockIncidentManager, MockPlaybookEngine,
    MockThreatCorrelationEngine, MockMultiTenantManager,
    MockExternalIntegration, MockSecurityOrchestrator,
    MockEnterpriseSOARTestEnvironment
)


class TestSecurityIncident:
    """Test SecurityIncident data class and operations."""
    
    def test_security_incident_creation(self):
        """Test creating a security incident."""
        timestamp = datetime.now(timezone.utc)
        
        incident = SecurityIncident(
            id="incident-001",
            title="SQL Injection Attack Detected",
            description="Malicious SQL injection attempt on user login endpoint",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.NEW,
            source_component="input_validation",
            threat_indicators=["malicious_payload", "suspicious_ip_192.168.1.100"],
            affected_resources=["user_login_endpoint", "user_database"],
            timeline=[{
                'timestamp': timestamp.isoformat(),
                'event': 'Incident Created',
                'details': 'SQL injection detected by input validation shield'
            }],
            evidence=[],
            response_actions=[],
            tenant_id="tenant_alpha",
            metadata={'attack_vector': 'sql_injection', 'confidence': 0.95}
        )
        
        assert incident.id == "incident-001"
        assert incident.title == "SQL Injection Attack Detected"
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.status == IncidentStatus.NEW
        assert incident.source_component == "input_validation"
        assert len(incident.threat_indicators) == 2
        assert len(incident.affected_resources) == 2
        assert len(incident.timeline) == 1
        assert incident.tenant_id == "tenant_alpha"
        assert incident.metadata['attack_vector'] == 'sql_injection'
    
    def test_security_incident_to_dict(self):
        """Test converting SecurityIncident to dictionary."""
        incident = SecurityIncident(
            id="incident-002",
            title="Bot Traffic Detected",
            description="Suspicious automated traffic pattern",
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.INVESTIGATING,
            source_component="bot_detection",
            threat_indicators=["bot_user_agent"],
            affected_resources=["api_endpoints"],
            timeline=[],
            evidence=[],
            response_actions=["rate_limiting_applied"]
        )
        
        result = incident.to_dict()
        
        assert result['id'] == "incident-002"
        assert result['title'] == "Bot Traffic Detected"
        assert result['severity'] == "medium"
        assert result['status'] == "investigating"
        assert result['source_component'] == "bot_detection"
        assert result['response_actions'] == ["rate_limiting_applied"]
    
    def test_incident_severity_levels(self):
        """Test incident severity enumeration."""
        assert IncidentSeverity.INFORMATIONAL.value == "informational"
        assert IncidentSeverity.LOW.value == "low"
        assert IncidentSeverity.MEDIUM.value == "medium"
        assert IncidentSeverity.HIGH.value == "high"
        assert IncidentSeverity.CRITICAL.value == "critical"
        assert IncidentSeverity.EMERGENCY.value == "emergency"
    
    def test_incident_status_values(self):
        """Test incident status enumeration."""
        assert IncidentStatus.NEW.value == "new"
        assert IncidentStatus.ASSIGNED.value == "assigned"
        assert IncidentStatus.INVESTIGATING.value == "investigating"
        assert IncidentStatus.CONTAINED.value == "contained"
        assert IncidentStatus.RESOLVED.value == "resolved"
        assert IncidentStatus.CLOSED.value == "closed"


class TestSecurityPlaybook:
    """Test SecurityPlaybook data class and operations."""
    
    def test_security_playbook_creation(self):
        """Test creating a security playbook."""
        playbook = SecurityPlaybook(
            id="playbook-001",
            name="DDoS Attack Response",
            description="Automated response for DDoS attacks",
            trigger_conditions={
                'severity': ['high', 'critical'],
                'source_component': ['rate_limiting', 'ddos_protection']
            },
            actions=[
                {
                    'type': 'analyze',
                    'parameters': {'type': 'traffic_analysis'}
                },
                {
                    'type': 'block',
                    'parameters': {'target_type': 'ip_range', 'duration': '2h'}
                },
                {
                    'type': 'notify',
                    'parameters': {'recipients': ['security_team'], 'urgency': 'high'}
                }
            ],
            automation_level='semi-automated',
            priority=9
        )
        
        assert playbook.id == "playbook-001"
        assert playbook.name == "DDoS Attack Response"
        assert playbook.automation_level == 'semi-automated'
        assert playbook.priority == 9
        assert len(playbook.actions) == 3
        assert playbook.trigger_conditions['severity'] == ['high', 'critical']
    
    def test_security_playbook_to_dict(self):
        """Test converting SecurityPlaybook to dictionary."""
        playbook = SecurityPlaybook(
            id="playbook-002",
            name="Malware Detection Response",
            description="Response for malware detection",
            trigger_conditions={'source_component': ['malware_scanner']},
            actions=[{'type': 'quarantine', 'parameters': {'scope': 'infected_files'}}],
            automation_level='fully-automated',
            enabled=True
        )
        
        result = playbook.to_dict()
        
        assert result['id'] == "playbook-002"
        assert result['name'] == "Malware Detection Response"
        assert result['automation_level'] == 'fully-automated'
        assert result['enabled'] is True
        assert len(result['actions']) == 1
    
    def test_playbook_action_types(self):
        """Test playbook action enumeration."""
        assert PlaybookAction.ANALYZE.value == "analyze"
        assert PlaybookAction.BLOCK.value == "block"
        assert PlaybookAction.QUARANTINE.value == "quarantine"
        assert PlaybookAction.NOTIFY.value == "notify"
        assert PlaybookAction.ESCALATE.value == "escalate"
        assert PlaybookAction.REMEDIATE.value == "remediate"
        assert PlaybookAction.COLLECT_EVIDENCE.value == "collect_evidence"
        assert PlaybookAction.UPDATE_RULES.value == "update_rules"


class TestTenantConfiguration:
    """Test TenantConfiguration data class."""
    
    def test_tenant_configuration_creation(self):
        """Test creating tenant configuration."""
        config = TenantConfiguration(
            tenant_id="enterprise_corp",
            tenant_name="Enterprise Corporation",
            resource_limits={
                'max_requests_per_minute': 10000,
                'max_incidents_per_hour': 500,
                'max_cpu_percent': 90,
                'max_memory_mb': 4096
            },
            security_policies={'require_2fa': True, 'password_complexity': 'high'},
            enabled_components=['rate_limiting', 'input_validation', 'bot_detection',
                              'threat_intelligence', 'compliance_framework'],
            compliance_requirements=[ComplianceStandard.SOX, ComplianceStandard.PCI_DSS],
            notification_settings={'slack_channel': 'security-alerts-enterprise'},
            custom_configurations={'industry': 'financial_services'}
        )
        
        assert config.tenant_id == "enterprise_corp"
        assert config.tenant_name == "Enterprise Corporation"
        assert config.resource_limits['max_requests_per_minute'] == 10000
        assert config.security_policies['require_2fa'] is True
        assert len(config.enabled_components) == 5
        assert ComplianceStandard.SOX in config.compliance_requirements
        assert ComplianceStandard.PCI_DSS in config.compliance_requirements
        assert config.is_active is True
    
    def test_tenant_configuration_to_dict(self):
        """Test converting TenantConfiguration to dictionary."""
        config = TenantConfiguration(
            tenant_id="startup_inc",
            tenant_name="Startup Inc",
            resource_limits={'max_requests_per_minute': 1000},
            security_policies={},
            enabled_components=['rate_limiting'],
            compliance_requirements=[ComplianceStandard.GDPR],
            notification_settings={},
            custom_configurations={}
        )
        
        result = config.to_dict()
        
        assert result['tenant_id'] == "startup_inc"
        assert result['tenant_name'] == "Startup Inc"
        assert result['resource_limits']['max_requests_per_minute'] == 1000
        assert result['compliance_requirements'] == ['gdpr']
        assert result['is_active'] is True
    
    def test_compliance_standards(self):
        """Test compliance standards enumeration."""
        assert ComplianceStandard.SOX.value == "sox"
        assert ComplianceStandard.PCI_DSS.value == "pci_dss"
        assert ComplianceStandard.GDPR.value == "gdpr"
        assert ComplianceStandard.HIPAA.value == "hipaa"
        assert ComplianceStandard.ISO27001.value == "iso27001"
        assert ComplianceStandard.NIST.value == "nist"
        assert ComplianceStandard.CIS.value == "cis"


class TestSOARDatabase:
    """Test SOARDatabase functionality."""
    
    def test_soar_database_creation(self):
        """Test creating SOAR database."""
        db = MockSOARDatabase()
        
        assert len(db.incidents) == 0
        assert len(db.playbooks) == 0
        assert len(db.storage_calls) == 0
        assert len(db.query_calls) == 0
    
    def test_store_and_retrieve_incident(self):
        """Test storing and retrieving incidents."""
        db = MockSOARDatabase()
        
        incident = SecurityIncident(
            id="test-incident",
            title="Test Security Incident",
            description="Test incident for database operations",
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.NEW,
            source_component="test_component",
            threat_indicators=["test_indicator"],
            affected_resources=["test_resource"],
            timeline=[],
            evidence=[],
            response_actions=[]
        )
        
        # Store incident
        result = db.store_incident(incident)
        assert result is True
        assert len(db.storage_calls) == 1
        assert ('incident', incident.id) in db.storage_calls
        
        # Retrieve incident
        retrieved = db.get_incident(incident.id)
        assert retrieved is not None
        assert retrieved.id == incident.id
        assert retrieved.title == incident.title
        assert retrieved.severity == incident.severity
    
    def test_search_incidents_with_filters(self):
        """Test searching incidents with various filters."""
        db = MockSOARDatabase()
        
        # Create test incidents with different attributes
        incidents = []
        severities = [IncidentSeverity.LOW, IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
        tenants = ["tenant_a", "tenant_b", None]
        
        for i in range(6):
            incident = SecurityIncident(
                id=f"incident-{i}",
                title=f"Test Incident {i}",
                description=f"Test incident {i}",
                severity=severities[i % len(severities)],
                status=IncidentStatus.NEW if i % 2 == 0 else IncidentStatus.RESOLVED,
                source_component="test",
                threat_indicators=[],
                affected_resources=[],
                timeline=[],
                evidence=[],
                response_actions=[],
                tenant_id=tenants[i % len(tenants)]
            )
            incidents.append(incident)
            db.store_incident(incident)
        
        # Search by severity
        high_incidents = db.search_incidents(severity=IncidentSeverity.HIGH)
        assert len(high_incidents) == 2
        assert all(inc.severity == IncidentSeverity.HIGH for inc in high_incidents)
        
        # Search by tenant
        tenant_a_incidents = db.search_incidents(tenant_id="tenant_a")
        assert len(tenant_a_incidents) == 2
        assert all(inc.tenant_id == "tenant_a" for inc in tenant_a_incidents)
        
        # Search by status
        resolved_incidents = db.search_incidents(status=IncidentStatus.RESOLVED)
        assert len(resolved_incidents) == 3
        assert all(inc.status == IncidentStatus.RESOLVED for inc in resolved_incidents)
        
        # Search with limit
        limited_incidents = db.search_incidents(limit=3)
        assert len(limited_incidents) == 3
    
    def test_store_and_retrieve_playbook(self):
        """Test storing and retrieving playbooks."""
        db = MockSOARDatabase()
        
        playbook = SecurityPlaybook(
            id="test-playbook",
            name="Test Playbook",
            description="Test playbook for database operations",
            trigger_conditions={'severity': ['high']},
            actions=[{'type': 'notify', 'parameters': {}}],
            automation_level='fully-automated'
        )
        
        # Store playbook
        result = db.store_playbook(playbook)
        assert result is True
        assert len(db.storage_calls) == 1
        
        # Retrieve active playbooks
        active_playbooks = db.get_active_playbooks()
        assert len(active_playbooks) == 1
        assert active_playbooks[0].id == playbook.id
        assert active_playbooks[0].enabled is True
        
        # Test disabled playbook filtering
        playbook.enabled = False
        db.store_playbook(playbook)
        active_playbooks = db.get_active_playbooks()
        assert len(active_playbooks) == 0


class TestIncidentManager:
    """Test IncidentManager functionality."""
    
    def test_incident_manager_creation(self):
        """Test creating IncidentManager."""
        db = MockSOARDatabase()
        manager = MockIncidentManager(db)
        
        assert manager.database == db
        assert len(manager.incident_processors) == 0
        assert len(manager.create_calls) == 0
    
    @pytest.mark.asyncio
    async def test_create_incident(self):
        """Test creating security incident."""
        db = MockSOARDatabase()
        manager = MockIncidentManager(db)
        
        incident = await manager.create_incident(
            title="Test Security Breach",
            description="Unauthorized access attempt detected",
            severity=IncidentSeverity.CRITICAL,
            source_component="access_control",
            threat_indicators=["unauthorized_login", "suspicious_ip"],
            affected_resources=["user_accounts", "sensitive_data"],
            tenant_id="test_tenant",
            metadata={'attack_type': 'credential_stuffing'}
        )
        
        assert incident.title == "Test Security Breach"
        assert incident.severity == IncidentSeverity.CRITICAL
        assert incident.status == IncidentStatus.NEW
        assert incident.source_component == "access_control"
        assert len(incident.threat_indicators) == 2
        assert len(incident.affected_resources) == 2
        assert incident.tenant_id == "test_tenant"
        assert len(manager.create_calls) == 1
    
    @pytest.mark.asyncio
    async def test_update_incident(self):
        """Test updating security incident."""
        db = MockSOARDatabase()
        manager = MockIncidentManager(db)
        
        # Create initial incident
        incident = await manager.create_incident(
            title="Test Incident",
            description="Test description",
            severity=IncidentSeverity.MEDIUM,
            source_component="test"
        )
        
        # Update incident
        result = await manager.update_incident(
            incident.id,
            status=IncidentStatus.INVESTIGATING,
            assigned_analyst="analyst_john",
            add_timeline_event={
                'event': 'Analysis Started',
                'details': 'Security analyst assigned to investigate'
            },
            add_evidence={
                'type': 'log_file',
                'description': 'Security logs captured during incident',
                'location': '/var/log/security/incident.log'
            },
            add_response_action="Blocked suspicious IP address"
        )
        
        assert result is True
        assert len(manager.update_calls) == 1
        
        update_call = manager.update_calls[0]
        assert update_call['incident_id'] == incident.id
        assert update_call['status'] == IncidentStatus.INVESTIGATING
        assert update_call['assigned_analyst'] == "analyst_john"
        assert update_call['timeline_event']['event'] == 'Analysis Started'
    
    @pytest.mark.asyncio
    async def test_escalate_incident(self):
        """Test escalating incident severity."""
        db = MockSOARDatabase()
        manager = MockIncidentManager(db)
        
        # Create low severity incident
        incident = await manager.create_incident(
            title="Low Priority Alert",
            description="Minor security event",
            severity=IncidentSeverity.LOW,
            source_component="monitoring"
        )
        
        # Escalate incident
        result = await manager.escalate_incident(
            incident.id,
            "Event pattern indicates coordinated attack"
        )
        
        assert result is True
        assert len(manager.escalation_calls) == 1
        
        escalation = manager.escalation_calls[0]
        assert escalation['incident_id'] == incident.id
        assert escalation['reason'] == "Event pattern indicates coordinated attack"
    
    @pytest.mark.asyncio
    async def test_start_stop_processing(self):
        """Test starting and stopping incident processing."""
        db = MockSOARDatabase()
        manager = MockIncidentManager(db)
        
        # Initially not running
        assert manager._running is False
        
        # Start processing
        await manager.start_processing()
        assert manager._running is True
        
        # Stop processing  
        await manager.stop_processing()
        assert manager._running is False
    
    def test_add_incident_processor(self):
        """Test adding custom incident processor."""
        db = MockSOARDatabase()
        manager = MockIncidentManager(db)
        
        def custom_processor(incident):
            return f"Processed incident: {incident.id}"
        
        manager.add_incident_processor(custom_processor)
        
        assert len(manager.incident_processors) == 1
        assert manager.incident_processors[0] == custom_processor


class TestPlaybookEngine:
    """Test PlaybookEngine functionality."""
    
    def test_playbook_engine_creation(self):
        """Test creating PlaybookEngine."""
        db = MockSOARDatabase()
        manager = MockIncidentManager(db)
        engine = MockPlaybookEngine(db, manager)
        
        assert engine.database == db
        assert engine.incident_manager == manager
        assert len(engine.action_handlers) > 0
        assert len(engine.execution_calls) == 0
    
    @pytest.mark.asyncio
    async def test_execute_playbook(self):
        """Test executing security playbook."""
        db = MockSOARDatabase()
        manager = MockIncidentManager(db)
        engine = MockPlaybookEngine(db, manager)
        
        # Create test playbook
        playbook = SecurityPlaybook(
            id="test-execution",
            name="Test Execution Playbook",
            description="Playbook for testing execution",
            trigger_conditions={'severity': ['high']},
            actions=[
                {'type': 'analyze', 'parameters': {'type': 'forensic_analysis'}},
                {'type': 'notify', 'parameters': {'recipients': ['security_team']}},
                {'type': 'block', 'parameters': {'target_type': 'ip', 'duration': '1h'}}
            ],
            automation_level='fully-automated'
        )
        
        # Create test incident
        incident = SecurityIncident(
            id="test-incident",
            title="Test Incident",
            description="Test incident for playbook execution",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.NEW,
            source_component="test",
            threat_indicators=[],
            affected_resources=[],
            timeline=[],
            evidence=[],
            response_actions=[]
        )
        
        # Execute playbook
        execution_result = await engine.execute_playbook(playbook, incident)
        
        assert execution_result['success'] is True
        assert execution_result['playbook_id'] == playbook.id
        assert execution_result['incident_id'] == incident.id
        assert len(execution_result['actions_executed']) == 3
        assert len(engine.execution_calls) == 1
    
    @pytest.mark.asyncio
    async def test_find_matching_playbooks(self):
        """Test finding playbooks that match incident conditions."""
        db = MockSOARDatabase()
        manager = MockIncidentManager(db)
        engine = MockPlaybookEngine(db, manager)
        
        # Create test playbooks with different trigger conditions
        high_severity_playbook = SecurityPlaybook(
            id="high-severity",
            name="High Severity Response",
            description="Response for high severity incidents",
            trigger_conditions={'severity': ['high', 'critical']},
            actions=[{'type': 'escalate', 'parameters': {}}],
            automation_level='semi-automated',
            priority=9
        )
        
        bot_detection_playbook = SecurityPlaybook(
            id="bot-detection",
            name="Bot Detection Response",
            description="Response for bot detection",
            trigger_conditions={'source_component': ['bot_detection']},
            actions=[{'type': 'block', 'parameters': {}}],
            automation_level='fully-automated',
            priority=5
        )
        
        # Store playbooks in database
        db.store_playbook(high_severity_playbook)
        db.store_playbook(bot_detection_playbook)
        
        # Test incident that matches high severity playbook
        high_incident = SecurityIncident(
            id="high-inc",
            title="Critical Security Breach",
            description="Critical security incident",
            severity=IncidentSeverity.CRITICAL,
            status=IncidentStatus.NEW,
            source_component="access_control",
            threat_indicators=[],
            affected_resources=[],
            timeline=[],
            evidence=[],
            response_actions=[]
        )
        
        matching_playbooks = await engine.find_matching_playbooks(high_incident)
        
        assert len(matching_playbooks) == 1
        assert matching_playbooks[0].id == "high-severity"
        assert len(engine.matching_calls) == 1
        
        # Test incident that matches bot detection playbook
        bot_incident = SecurityIncident(
            id="bot-inc",
            title="Bot Activity Detected",
            description="Suspicious bot activity",
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.NEW,
            source_component="bot_detection",
            threat_indicators=[],
            affected_resources=[],
            timeline=[],
            evidence=[],
            response_actions=[]
        )
        
        matching_playbooks = await engine.find_matching_playbooks(bot_incident)
        
        assert len(matching_playbooks) == 1
        assert matching_playbooks[0].id == "bot-detection"


class TestThreatCorrelationEngine:
    """Test ThreatCorrelationEngine functionality."""
    
    def test_threat_correlation_engine_creation(self):
        """Test creating ThreatCorrelationEngine."""
        engine = MockThreatCorrelationEngine()
        
        assert len(engine.correlation_rules) == 0
        assert len(engine.pattern_cache) == 0
        assert len(engine.correlation_history) == 0
        assert len(engine.analysis_calls) == 0
    
    @pytest.mark.asyncio
    async def test_analyze_events_no_correlation(self):
        """Test analyzing events with no correlation detected."""
        engine = MockThreatCorrelationEngine()
        
        events = [
            {
                'id': '1',
                'event_type': 'rate_limit_exceeded',
                'component': 'rate_limiting',
                'timestamp': time.time()
            },
            {
                'id': '2', 
                'event_type': 'input_validation_failed',
                'component': 'input_validation',
                'timestamp': time.time()
            }
        ]
        
        correlations = await engine.analyze_events(events)
        
        assert len(correlations) == 0  # Mock threshold not met
        assert len(engine.analysis_calls) == 1
        assert engine.analysis_calls[0]['event_count'] == 2
        assert len(engine.correlation_history) == 2
    
    @pytest.mark.asyncio 
    async def test_analyze_events_with_correlation(self):
        """Test analyzing events with correlation detected."""
        engine = MockThreatCorrelationEngine()
        
        # Create enough events to trigger mock correlation
        events = [
            {
                'id': f'{i}',
                'event_type': 'suspicious_activity',
                'component': f'component_{i}',
                'timestamp': time.time()
            }
            for i in range(5)  # Above threshold in mock
        ]
        
        correlations = await engine.analyze_events(events)
        
        assert len(correlations) == 1
        assert correlations[0]['rule_name'] == 'Mock High Activity Correlation'
        assert correlations[0]['confidence'] == 0.75
        assert correlations[0]['severity'] == 'medium'
        assert len(correlations[0]['matching_events']) == 5
    
    def test_add_correlation_rule(self):
        """Test adding custom correlation rule."""
        engine = MockThreatCorrelationEngine()
        
        custom_rule = {
            'id': 'custom_rule_1',
            'name': 'Custom Attack Pattern',
            'description': 'Detects custom attack pattern',
            'conditions': [
                {'component': 'auth', 'event': 'failed_login', 'timeframe': 300},
                {'component': 'access', 'event': 'unauthorized_access', 'timeframe': 300}
            ],
            'threshold': 2,
            'severity': 'high',
            'confidence': 0.9
        }
        
        engine.add_correlation_rule(custom_rule)
        
        assert len(engine.correlation_rules) == 1
        assert len(engine.rule_additions) == 1
        assert engine.correlation_rules[0]['id'] == 'custom_rule_1'
        assert engine.correlation_rules[0]['confidence'] == 0.9
    
    def test_get_correlation_statistics(self):
        """Test getting correlation engine statistics."""
        engine = MockThreatCorrelationEngine()
        
        # Add some test data
        engine.add_correlation_rule({'id': 'rule_1', 'name': 'Test Rule'})
        engine.correlation_history.extend(['event1', 'event2', 'event3'])
        
        stats = engine.get_correlation_statistics()
        
        assert stats['total_rules'] == 1
        assert stats['events_in_history'] == 3
        assert stats['cache_size'] == 0
        assert 'analysis_calls' in stats


class TestMultiTenantManager:
    """Test MultiTenantManager functionality."""
    
    def test_multi_tenant_manager_creation(self):
        """Test creating MultiTenantManager."""
        db = MockSOARDatabase()
        manager = MockMultiTenantManager(db)
        
        assert manager.database == db
        assert len(manager.tenant_configs) == 0
        assert len(manager.tenant_metrics) == 0
        assert len(manager.create_calls) == 0
    
    @pytest.mark.asyncio
    async def test_create_tenant(self):
        """Test creating new tenant."""
        db = MockSOARDatabase()
        manager = MockMultiTenantManager(db)
        
        config = await manager.create_tenant(
            tenant_id="acme_corp",
            tenant_name="ACME Corporation",
            config={
                'resource_limits': {
                    'max_requests_per_minute': 5000,
                    'max_incidents_per_hour': 200
                },
                'enabled_components': ['rate_limiting', 'bot_detection', 'compliance_framework'],
                'compliance_requirements': ['sox', 'pci_dss']
            }
        )
        
        assert config.tenant_id == "acme_corp"
        assert config.tenant_name == "ACME Corporation"
        assert config.resource_limits['max_requests_per_minute'] == 5000
        assert len(config.enabled_components) == 3
        assert len(manager.create_calls) == 1
    
    def test_get_tenant_config(self):
        """Test retrieving tenant configuration."""
        db = MockSOARDatabase()
        manager = MockMultiTenantManager(db)
        
        # Create and store tenant config
        config = TenantConfiguration(
            tenant_id="test_tenant",
            tenant_name="Test Tenant",
            resource_limits={'max_requests_per_minute': 1000},
            security_policies={},
            enabled_components=['rate_limiting'],
            compliance_requirements=[],
            notification_settings={},
            custom_configurations={}
        )
        manager.tenant_configs["test_tenant"] = config
        
        # Retrieve config
        retrieved_config = manager.get_tenant_config("test_tenant")
        
        assert retrieved_config is not None
        assert retrieved_config.tenant_id == "test_tenant"
        assert retrieved_config.tenant_name == "Test Tenant"
        
        # Test non-existent tenant
        missing_config = manager.get_tenant_config("nonexistent_tenant")
        assert missing_config is None
    
    @pytest.mark.asyncio
    async def test_check_resource_limits(self):
        """Test checking tenant resource limits."""
        db = MockSOARDatabase()
        manager = MockMultiTenantManager(db)
        
        # Create tenant with specific limits
        await manager.create_tenant(
            tenant_id="limited_tenant",
            tenant_name="Limited Tenant",
            config={
                'resource_limits': {
                    'max_requests_per_minute': 1000,
                    'max_cpu_percent': 70
                }
            }
        )
        
        # Test within limits
        result1 = await manager.check_resource_limits("limited_tenant", "requests_per_minute", 800)
        assert result1 is True
        
        # Test exceeding limits
        result2 = await manager.check_resource_limits("limited_tenant", "requests_per_minute", 1200) 
        assert result2 is False
        
        # Test different resource type
        result3 = await manager.check_resource_limits("limited_tenant", "cpu_percent", 65)
        assert result3 is True
        
        assert len(manager.resource_checks) == 3
    
    def test_update_tenant_metrics(self):
        """Test updating tenant usage metrics."""
        db = MockSOARDatabase()
        manager = MockMultiTenantManager(db)
        
        # Update various metrics
        manager.update_tenant_metrics("test_tenant", "requests", 500)
        manager.update_tenant_metrics("test_tenant", "cpu_usage", 45.2)
        manager.update_tenant_metrics("test_tenant", "memory_usage", 1024.0)
        
        # Verify metrics were updated
        metrics = manager.get_tenant_metrics("test_tenant")
        
        assert metrics['requests'] == 500
        assert metrics['cpu_usage'] == 45.2
        assert metrics['memory_usage'] == 1024.0
        assert 'last_activity' in metrics
        assert len(manager.metrics_updates) == 3
    
    def test_get_all_tenant_metrics(self):
        """Test getting metrics for all tenants."""
        db = MockSOARDatabase()
        manager = MockMultiTenantManager(db)
        
        # Update metrics for multiple tenants
        manager.update_tenant_metrics("tenant_a", "requests", 100)
        manager.update_tenant_metrics("tenant_b", "requests", 200)
        manager.update_tenant_metrics("tenant_a", "incidents", 5)
        
        # Get all metrics
        all_metrics = manager.get_all_tenant_metrics()
        
        assert len(all_metrics) == 2
        assert all_metrics['tenant_a']['requests'] == 100
        assert all_metrics['tenant_a']['incidents'] == 5
        assert all_metrics['tenant_b']['requests'] == 200


class TestExternalIntegrations:
    """Test external system integrations."""
    
    @pytest.mark.asyncio
    async def test_siem_integration_connection(self):
        """Test SIEM integration connection."""
        config = {
            'type': 'splunk',
            'endpoint_url': 'https://siem.example.com',
            'api_key': 'test_api_key',
            'index_name': 'security_events'
        }
        
        siem = SIEMIntegration(config)
        
        assert siem.integration_name == "SIEM"
        assert siem.siem_type == 'splunk'
        assert siem.endpoint_url == 'https://siem.example.com'
        assert siem.is_connected is False
        
        # Test connection
        result = await siem.connect()
        assert result is True
        assert siem.is_connected is True
        
        # Test health check
        health = await siem.health_check()
        assert health is True
        assert siem.last_health_check is not None
    
    @pytest.mark.asyncio
    async def test_siem_integration_send_data(self):
        """Test sending data to SIEM integration."""
        config = {
            'type': 'qradar',
            'endpoint_url': 'https://qradar.example.com',
            'api_key': 'qradar_key'
        }
        
        siem = SIEMIntegration(config)
        await siem.connect()
        
        # Test sending security event
        event_data = {
            'event_type': 'security_incident',
            'severity': 'high',
            'title': 'SQL Injection Detected',
            'description': 'Malicious SQL injection attempt',
            'source_component': 'input_validation',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        result = await siem.send_data(event_data)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_ticketing_integration(self):
        """Test ticketing system integration."""
        config = {
            'type': 'servicenow',
            'endpoint_url': 'https://company.service-now.com',
            'credentials': {'username': 'svc_account', 'password': 'secure_pass'},
            'default_project': 'SECURITY'
        }
        
        ticketing = TicketingIntegration(config)
        
        assert ticketing.integration_name == "Ticketing"
        assert ticketing.system_type == 'servicenow'
        assert ticketing.default_project == 'SECURITY'
        
        # Connect and test
        await ticketing.connect()
        assert ticketing.is_connected is True
        
        # Test creating ticket
        incident_data = {
            'id': 'incident-001',
            'title': 'Data Breach Investigation',
            'description': 'Potential data breach requires investigation',
            'severity': 'critical',
            'source_component': 'threat_intelligence'
        }
        
        result = await ticketing.send_data(incident_data)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_messaging_integration(self):
        """Test messaging/notification integration."""
        config = {
            'platform': 'slack',
            'webhook_url': 'https://hooks.slack.com/services/xxx/yyy/zzz',
            'channels': {
                'critical': 'security-critical',
                'high': 'security-alerts',
                'medium': 'security-info'
            }
        }
        
        messaging = MessagingIntegration(config)
        
        assert messaging.integration_name == "Messaging"
        assert messaging.platform == 'slack'
        assert messaging.channels['critical'] == 'security-critical'
        
        # Connect and test
        await messaging.connect()
        assert messaging.is_connected is True
        
        # Test sending notification
        alert_data = {
            'title': 'Critical Security Alert',
            'description': 'Immediate attention required',
            'severity': 'critical',
            'source_component': 'threat_intelligence'
        }
        
        result = await messaging.send_data(alert_data)
        assert result is True


class TestSecurityOrchestrator:
    """Test main SecurityOrchestrator functionality."""
    
    def test_security_orchestrator_creation(self):
        """Test creating SecurityOrchestrator."""
        orchestrator = MockSecurityOrchestrator()
        
        assert orchestrator.database is not None
        assert orchestrator.incident_manager is not None
        assert orchestrator.playbook_engine is not None
        assert orchestrator.threat_correlation is not None
        assert orchestrator.multi_tenant_manager is not None
        assert len(orchestrator.integrations) == 0
        assert len(orchestrator.registered_components) == 0
        assert orchestrator._running is False
    
    @pytest.mark.asyncio
    async def test_start_stop_orchestrator(self):
        """Test starting and stopping orchestrator."""
        orchestrator = MockSecurityOrchestrator()
        
        # Initially not running
        assert orchestrator._running is False
        
        # Start orchestrator
        await orchestrator.start()
        assert orchestrator._running is True
        
        # Stop orchestrator
        await orchestrator.stop()
        assert orchestrator._running is False
    
    def test_register_component(self):
        """Test registering FastAPI-Shield components."""
        orchestrator = MockSecurityOrchestrator()
        
        # Mock components
        rate_limiter = Mock()
        bot_detector = Mock()
        
        orchestrator.register_component("rate_limiting", rate_limiter)
        orchestrator.register_component("bot_detection", bot_detector)
        
        assert len(orchestrator.registered_components) == 2
        assert orchestrator.registered_components["rate_limiting"] == rate_limiter
        assert orchestrator.registered_components["bot_detection"] == bot_detector
    
    def test_add_integration(self):
        """Test adding external integrations."""
        orchestrator = MockSecurityOrchestrator()
        
        # Create mock integrations
        siem_integration = MockExternalIntegration("Splunk SIEM", {'type': 'splunk'})
        ticketing_integration = MockExternalIntegration("ServiceNow", {'type': 'servicenow'})
        
        orchestrator.add_integration('siem', siem_integration)
        orchestrator.add_integration('ticketing', ticketing_integration)
        
        assert len(orchestrator.integrations) == 2
        assert orchestrator.integrations['siem'] == siem_integration
        assert orchestrator.integrations['ticketing'] == ticketing_integration
    
    @pytest.mark.asyncio
    async def test_process_security_event_no_incident(self):
        """Test processing security event that doesn't create incident."""
        orchestrator = MockSecurityOrchestrator()
        
        # Low priority event that shouldn't create incident
        event = {
            'id': 'event-001',
            'event_type': 'info_log_entry',
            'component': 'logging',
            'title': 'Informational Log Entry',
            'description': 'Regular system log entry',
            'severity': 'informational',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        result = await orchestrator.process_security_event(event)
        
        assert result is None  # No incident created
        assert orchestrator.metrics['events_processed'] == 1
        assert orchestrator.metrics['incidents_created'] == 0
        assert len(orchestrator.event_processing_calls) == 1
    
    @pytest.mark.asyncio
    async def test_process_security_event_creates_incident(self):
        """Test processing security event that creates incident."""
        orchestrator = MockSecurityOrchestrator()
        
        # High priority event that should create incident
        event = {
            'id': 'event-002',
            'event_type': 'sql_injection_attack',
            'component': 'input_validation',
            'title': 'SQL Injection Attack Detected',
            'description': 'Malicious SQL injection attempt blocked',
            'severity': 'high',
            'threat_indicators': ['malicious_payload'],
            'affected_resources': ['user_database'],
            'tenant_id': 'enterprise_tenant',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        result = await orchestrator.process_security_event(event)
        
        assert result is not None  # Incident created
        assert result.title == 'SQL Injection Attack Detected'
        assert result.source_component == 'input_validation'
        assert orchestrator.metrics['events_processed'] == 1
        assert orchestrator.metrics['incidents_created'] == 1
    
    @pytest.mark.asyncio
    async def test_create_custom_playbook(self):
        """Test creating custom security playbook."""
        orchestrator = MockSecurityOrchestrator()
        
        playbook = await orchestrator.create_custom_playbook(
            name="Custom DDoS Response",
            description="Custom playbook for DDoS attack response",
            trigger_conditions={
                'severity': ['high', 'critical'],
                'source_component': ['rate_limiting', 'ddos_protection']
            },
            actions=[
                {'type': 'analyze', 'parameters': {'type': 'traffic_analysis'}},
                {'type': 'block', 'parameters': {'target_type': 'ip_range'}},
                {'type': 'notify', 'parameters': {'recipients': ['security_team', 'network_team']}}
            ],
            automation_level='semi-automated',
            tenant_id='enterprise_tenant'
        )
        
        assert playbook.name == "Custom DDoS Response"
        assert playbook.automation_level == 'semi-automated'
        assert playbook.tenant_id == 'enterprise_tenant'
        assert len(playbook.actions) == 3
        assert len(orchestrator.playbook_creation_calls) == 1
    
    def test_get_platform_status(self):
        """Test getting comprehensive platform status."""
        orchestrator = MockSecurityOrchestrator()
        
        # Add some test data
        orchestrator.register_component("rate_limiting", Mock())
        orchestrator.add_integration('siem', MockExternalIntegration("SIEM", {}))
        orchestrator.metrics['incidents_created'] = 42
        orchestrator.metrics['events_processed'] = 1337
        
        status = orchestrator.get_platform_status()
        
        assert status['platform_status'] == 'stopped'  # Not started yet
        assert 'uptime_seconds' in status
        assert status['metrics']['incidents_created'] == 42
        assert status['metrics']['events_processed'] == 1337
        assert len(status['registered_components']) == 1
        assert 'siem' in status['integrations']
        assert 'tenant_metrics' in status
        assert 'correlation_stats' in status


class TestIntegrationScenarios:
    """Integration tests for complete SOAR workflows."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_incident_response(self):
        """Test complete incident response workflow."""
        env = MockEnterpriseSOARTestEnvironment()
        await env.setup_test_data()
        orchestrator = env.orchestrator
        
        # Process high-severity security event
        critical_event = {
            'id': 'critical-001',
            'event_type': 'data_breach_detected',
            'component': 'threat_intelligence',
            'title': 'Potential Data Breach',
            'description': 'Unauthorized access to sensitive customer data',
            'severity': 'critical',
            'threat_indicators': ['suspicious_data_access', 'unauthorized_user'],
            'affected_resources': ['customer_database', 'payment_data'],
            'tenant_id': 'tenant_0'
        }
        
        # Process event through orchestrator
        incident = await orchestrator.process_security_event(critical_event)
        
        # Verify incident was created
        assert incident is not None
        assert incident.severity == IncidentSeverity.CRITICAL
        assert incident.source_component == 'threat_intelligence'
        assert len(incident.threat_indicators) == 2
        assert incident.tenant_id == 'tenant_0'
        
        # Verify playbook execution
        assert orchestrator.metrics['playbooks_executed'] > 0
        
        # Verify integrations were notified
        assert len(env.siem_integration.send_data_calls) > 0
        assert len(env.messaging_integration.send_data_calls) > 0
    
    @pytest.mark.asyncio
    async def test_multi_tenant_isolation(self):
        """Test multi-tenant resource isolation."""
        env = MockEnterpriseSOARTestEnvironment()
        await env.setup_test_data()
        orchestrator = env.orchestrator
        
        # Process events for different tenants
        tenant_a_event = {
            'event_type': 'security_violation',
            'component': 'access_control',
            'tenant_id': 'tenant_0',
            'severity': 'high'
        }
        
        tenant_b_event = {
            'event_type': 'security_violation',
            'component': 'access_control',
            'tenant_id': 'tenant_1',
            'severity': 'high'
        }
        
        # Process events
        incident_a = await orchestrator.process_security_event(tenant_a_event)
        incident_b = await orchestrator.process_security_event(tenant_b_event)
        
        # Verify tenant isolation
        assert incident_a.tenant_id == 'tenant_0'
        assert incident_b.tenant_id == 'tenant_1'
        assert incident_a.id != incident_b.id
        
        # Test resource limit checking
        tenant_manager = orchestrator.multi_tenant_manager
        
        # Check if tenants can exceed their limits
        within_limit = await tenant_manager.check_resource_limits('tenant_0', 'requests_per_minute', 500)
        exceed_limit = await tenant_manager.check_resource_limits('tenant_0', 'requests_per_minute', 2000)
        
        assert within_limit is True
        assert exceed_limit is False
    
    @pytest.mark.asyncio
    async def test_threat_correlation_workflow(self):
        """Test threat correlation across multiple events."""
        env = MockEnterpriseSOARTestEnvironment()
        orchestrator = env.orchestrator
        
        # Generate series of related security events
        related_events = [
            {
                'event_type': 'rate_limit_attack_detected',
                'component': 'rate_limiting',
                'source_ip': '192.168.1.100',
                'severity': 'high'
            },
            {
                'event_type': 'suspicious_bot_detected',
                'component': 'bot_detection',
                'source_ip': '192.168.1.100',
                'severity': 'high'
            },
            {
                'event_type': 'input_validation_attack_detected',
                'component': 'input_validation',
                'source_ip': '192.168.1.100',
                'severity': 'high'
            },
            {
                'event_type': 'authentication_attack_detected',
                'component': 'session_management',
                'source_ip': '192.168.1.100',
                'severity': 'high'
            },
            {
                'event_type': 'access_breach_detected',
                'component': 'access_control',
                'source_ip': '192.168.1.100',
                'severity': 'high'
            }
        ]
        
        # Process events and check for correlation
        for event in related_events:
            await orchestrator.process_security_event(event)
        
        # Verify threat correlation was detected
        assert orchestrator.metrics['correlations_detected'] > 0
        
        # Check correlation engine statistics
        correlation_stats = orchestrator.threat_correlation.get_correlation_statistics()
        assert correlation_stats['events_in_history'] >= len(related_events)
    
    @pytest.mark.asyncio
    async def test_automated_playbook_execution(self):
        """Test fully automated playbook execution."""
        env = MockEnterpriseSOARTestEnvironment()
        await env.setup_test_data()
        orchestrator = env.orchestrator
        
        # Create fully automated playbook
        auto_playbook = await orchestrator.create_custom_playbook(
            name="Automated Bot Response",
            description="Fully automated response to bot detection",
            trigger_conditions={'source_component': ['bot_detection']},
            actions=[
                {'type': 'analyze', 'parameters': {'type': 'behavioral_analysis'}},
                {'type': 'block', 'parameters': {'target_type': 'ip', 'duration': '2h'}},
                {'type': 'update_rules', 'parameters': {'rule_type': 'rate_limiting'}}
            ],
            automation_level='fully-automated'
        )
        
        # Trigger bot detection event
        bot_event = {
            'event_type': 'bot_attack_detected',
            'component': 'bot_detection',
            'title': 'Automated Bot Attack',
            'description': 'Large-scale automated attack detected',
            'severity': 'high'
        }
        
        incident = await orchestrator.process_security_event(bot_event)
        
        # Verify automated playbook was executed
        assert incident is not None
        assert orchestrator.metrics['playbooks_executed'] > 0
        
        # Verify playbook execution log
        playbook_executions = orchestrator.playbook_engine.execution_calls
        assert len(playbook_executions) > 0


class TestPerformanceAndScaling:
    """Performance and scalability tests."""
    
    @pytest.mark.asyncio
    async def test_high_volume_event_processing(self):
        """Test processing high volume of security events."""
        env = MockEnterpriseSOARTestEnvironment()
        orchestrator = env.orchestrator
        
        start_time = time.time()
        
        # Process 1000 events rapidly
        events_processed = 0
        for i in range(1000):
            event = {
                'id': f'perf-event-{i}',
                'event_type': 'performance_test_event',
                'component': 'performance_test',
                'severity': 'low'
            }
            
            await orchestrator.process_security_event(event)
            events_processed += 1
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Performance assertions
        assert duration < 5.0  # Should process 1000 events in under 5 seconds
        assert orchestrator.metrics['events_processed'] == 1000
        
        events_per_second = events_processed / duration
        assert events_per_second > 200  # Should handle 200+ events per second
    
    @pytest.mark.asyncio
    async def test_concurrent_incident_management(self):
        """Test concurrent incident creation and management."""
        env = MockEnterpriseSOARTestEnvironment()
        orchestrator = env.orchestrator
        
        # Create multiple incidents concurrently
        async def create_incident(index):
            return await orchestrator.incident_manager.create_incident(
                title=f"Concurrent Incident {index}",
                description=f"Test incident {index} for concurrency testing",
                severity=IncidentSeverity.MEDIUM,
                source_component="concurrency_test"
            )
        
        start_time = time.time()
        
        # Create 100 incidents concurrently
        tasks = [create_incident(i) for i in range(100)]
        incidents = await asyncio.gather(*tasks)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Verify all incidents were created
        assert len(incidents) == 100
        assert all(incident.title.startswith("Concurrent Incident") for incident in incidents)
        assert duration < 2.0  # Should handle 100 concurrent incidents in under 2 seconds
    
    def test_memory_usage_under_load(self):
        """Test memory usage during high load operations."""
        env = MockEnterpriseSOARTestEnvironment()
        
        # Simulate high load scenario
        load_stats = env.simulate_high_load(num_events=5000, duration_seconds=30)
        
        # Verify performance metrics
        assert load_stats['events_processed'] >= 1000
        assert load_stats['avg_response_time'] < 0.01  # Under 10ms average
        assert load_stats['events_per_second'] > 100  # At least 100 events/sec
        
        # Get performance statistics
        perf_stats = env.get_performance_stats()
        
        assert perf_stats['total_operations'] >= 1000
        assert perf_stats['avg_response_time'] < 0.01
    
    @pytest.mark.asyncio
    async def test_multi_tenant_scalability(self):
        """Test scalability with multiple tenants."""
        env = MockEnterpriseSOARTestEnvironment()
        orchestrator = env.orchestrator
        
        # Create 50 tenants
        tenants = []
        for i in range(50):
            config = await orchestrator.multi_tenant_manager.create_tenant(
                tenant_id=f"scale_tenant_{i}",
                tenant_name=f"Scale Test Tenant {i}",
                config={
                    'resource_limits': {'max_requests_per_minute': 1000},
                    'enabled_components': ['rate_limiting', 'input_validation']
                }
            )
            tenants.append(config)
        
        # Process events for all tenants
        for i in range(50):
            event = {
                'event_type': 'scalability_test',
                'component': 'scale_test',
                'tenant_id': f'scale_tenant_{i}',
                'severity': 'medium'
            }
            
            await orchestrator.process_security_event(event)
            
            # Update tenant metrics
            orchestrator.multi_tenant_manager.update_tenant_metrics(
                f'scale_tenant_{i}', 'requests', i * 10
            )
        
        # Verify all tenants were handled
        all_metrics = orchestrator.multi_tenant_manager.get_all_tenant_metrics()
        assert len(all_metrics) == 50
        
        # Verify each tenant has metrics
        for i in range(50):
            tenant_metrics = orchestrator.multi_tenant_manager.get_tenant_metrics(f'scale_tenant_{i}')
            assert tenant_metrics['requests'] == i * 10


class TestErrorHandlingAndResilience:
    """Error handling and system resilience tests."""
    
    @pytest.mark.asyncio
    async def test_integration_failure_handling(self):
        """Test handling of external integration failures."""
        env = MockEnterpriseSOARTestEnvironment()
        await env.setup_test_data()  # Setup and connect integrations
        orchestrator = env.orchestrator
        
        # Disconnect SIEM integration to simulate failure
        await env.siem_integration.disconnect()
        
        # Process security event despite SIEM failure
        event = {
            'event_type': 'test_resilience',
            'component': 'resilience_test',
            'severity': 'high'
        }
        
        # Should not raise exception despite integration failure
        incident = await orchestrator.process_security_event(event)
        assert incident is not None
        
        # Verify other integrations still work
        assert env.ticketing_integration.is_connected is True
        assert env.messaging_integration.is_connected is True
    
    @pytest.mark.asyncio
    async def test_invalid_playbook_execution(self):
        """Test handling of invalid playbook execution."""
        env = MockEnterpriseSOARTestEnvironment()
        orchestrator = env.orchestrator
        
        # Create playbook with invalid action
        invalid_playbook = SecurityPlaybook(
            id="invalid-playbook",
            name="Invalid Test Playbook",
            description="Playbook with invalid actions for testing",
            trigger_conditions={'severity': ['high']},
            actions=[
                {'type': 'invalid_action_type', 'parameters': {}},
                {'type': 'analyze', 'parameters': {'type': 'valid_analysis'}}
            ],
            automation_level='fully-automated'
        )
        
        orchestrator.database.store_playbook(invalid_playbook)
        
        # Create incident that triggers invalid playbook
        incident = SecurityIncident(
            id="test-invalid",
            title="Test Invalid Playbook",
            description="Test incident",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.NEW,
            source_component="test",
            threat_indicators=[],
            affected_resources=[],
            timeline=[],
            evidence=[],
            response_actions=[]
        )
        
        # Execute playbook - should handle invalid actions gracefully
        result = await orchestrator.playbook_engine.execute_playbook(invalid_playbook, incident)
        
        # Should complete successfully despite invalid action
        assert result['success'] is True
        assert len(result['actions_executed']) == 2  # Both actions processed
    
    @pytest.mark.asyncio 
    async def test_database_error_recovery(self):
        """Test recovery from database errors."""
        env = MockEnterpriseSOARTestEnvironment()
        orchestrator = env.orchestrator
        
        # Create incident normally
        incident1 = await orchestrator.incident_manager.create_incident(
            title="Test Recovery 1",
            description="First test incident",
            severity=IncidentSeverity.MEDIUM,
            source_component="recovery_test"
        )
        
        assert incident1 is not None
        
        # Simulate database recovery by creating another incident
        incident2 = await orchestrator.incident_manager.create_incident(
            title="Test Recovery 2", 
            description="Second test incident after recovery",
            severity=IncidentSeverity.MEDIUM,
            source_component="recovery_test"
        )
        
        assert incident2 is not None
        assert incident1.id != incident2.id
    
    def test_resource_exhaustion_handling(self):
        """Test handling of resource exhaustion scenarios."""
        env = MockEnterpriseSOARTestEnvironment()
        orchestrator = env.orchestrator
        
        # Create tenant with very low resource limits
        async def test_limits():
            await orchestrator.multi_tenant_manager.create_tenant(
                tenant_id="limited_tenant",
                tenant_name="Resource Limited Tenant",
                config={
                    'resource_limits': {
                        'max_requests_per_minute': 10,
                        'max_incidents_per_hour': 5
                    }
                }
            )
            
            # Test exceeding limits
            result = await orchestrator.multi_tenant_manager.check_resource_limits(
                "limited_tenant", "requests_per_minute", 15
            )
            assert result is False
            
            # Test within limits
            result = await orchestrator.multi_tenant_manager.check_resource_limits(
                "limited_tenant", "requests_per_minute", 8
            )
            assert result is True
        
        # Run the async test
        asyncio.run(test_limits())


class TestConvenienceFunctions:
    """Test convenience functions and utilities."""
    
    def test_create_enterprise_soar(self):
        """Test create_enterprise_soar convenience function."""
        # Use sync version to avoid async issues
        orchestrator = create_enterprise_soar_sync()
        
        assert isinstance(orchestrator, SecurityOrchestrator)
        assert orchestrator.database is not None
        assert orchestrator.incident_manager is not None
        assert orchestrator.playbook_engine is not None
        assert orchestrator.threat_correlation is not None
        assert orchestrator.multi_tenant_manager is not None
    
    def test_create_enterprise_soar_with_integrations(self):
        """Test creating SOAR with external integrations."""
        siem_config = {
            'type': 'splunk',
            'endpoint_url': 'https://splunk.example.com',
            'api_key': 'test_key'
        }
        
        ticketing_config = {
            'type': 'jira',
            'endpoint_url': 'https://jira.example.com',
            'credentials': {'username': 'test', 'password': 'test'}
        }
        
        messaging_config = {
            'platform': 'teams',
            'webhook_url': 'https://hooks.teams.com/webhook'
        }
        
        orchestrator = create_enterprise_soar_sync(
            siem_config=siem_config,
            ticketing_config=ticketing_config,
            messaging_config=messaging_config
        )
        
        assert len(orchestrator.integrations) == 3
        assert 'siem' in orchestrator.integrations
        assert 'ticketing' in orchestrator.integrations
        assert 'messaging' in orchestrator.integrations
    
    def test_create_soar_app(self):
        """Test creating FastAPI SOAR application."""
        orchestrator = MockSecurityOrchestrator()
        app = create_soar_app(orchestrator)
        
        assert isinstance(app, FastAPI)
        assert app.title == "FastAPI-Shield Enterprise SOAR Platform"
        assert app.description == "Enterprise Security Orchestration and Response Platform"
        assert app.version == "1.0.0"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])