"""Mock infrastructure for Enterprise SOAR platform testing."""

import asyncio
import json
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, AsyncMock
import uuid

from src.fastapi_shield.enterprise_soar import (
    SecurityIncident, SecurityPlaybook, ThreatHuntingOperation, 
    ComplianceReport, TenantConfiguration,
    IncidentSeverity, IncidentStatus, PlaybookAction, 
    ThreatHuntingStatus, ComplianceStandard
)


class MockSOARDatabase:
    """Mock SOAR database for testing."""
    
    def __init__(self):
        self.incidents = {}
        self.playbooks = {}
        self.hunting_operations = {}
        self.compliance_reports = {}
        self.tenant_configs = {}
        self.storage_calls = []
        self.query_calls = []
        self.connection_count = 0
    
    def store_incident(self, incident: SecurityIncident) -> bool:
        """Mock store incident."""
        self.storage_calls.append(('incident', incident.id))
        self.incidents[incident.id] = incident
        return True
    
    def get_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        """Mock get incident."""
        self.query_calls.append(('get_incident', incident_id))
        return self.incidents.get(incident_id)
    
    def search_incidents(self,
                        tenant_id: Optional[str] = None,
                        severity: Optional[IncidentSeverity] = None,
                        status: Optional[IncidentStatus] = None,
                        limit: int = 100) -> List[SecurityIncident]:
        """Mock search incidents."""
        self.query_calls.append(('search_incidents', {
            'tenant_id': tenant_id,
            'severity': severity,
            'status': status,
            'limit': limit
        }))
        
        results = []
        for incident in self.incidents.values():
            if tenant_id and incident.tenant_id != tenant_id:
                continue
            if severity and incident.severity != severity:
                continue
            if status and incident.status != status:
                continue
            results.append(incident)
            if len(results) >= limit:
                break
        
        return results
    
    def store_playbook(self, playbook: SecurityPlaybook) -> bool:
        """Mock store playbook."""
        self.storage_calls.append(('playbook', playbook.id))
        self.playbooks[playbook.id] = playbook
        return True
    
    def get_active_playbooks(self, tenant_id: Optional[str] = None) -> List[SecurityPlaybook]:
        """Mock get active playbooks."""
        self.query_calls.append(('get_active_playbooks', tenant_id))
        
        results = []
        for playbook in self.playbooks.values():
            if not playbook.enabled:
                continue
            if tenant_id and playbook.tenant_id and playbook.tenant_id != tenant_id:
                continue
            results.append(playbook)
        
        return sorted(results, key=lambda p: p.priority, reverse=True)


class MockIncidentManager:
    """Mock incident manager for testing."""
    
    def __init__(self, database):
        self.database = database
        self.incident_processors = []
        self.escalation_calls = []
        self.update_calls = []
        self.create_calls = []
        self._running = False
    
    async def start_processing(self):
        """Mock start processing."""
        self._running = True
    
    async def stop_processing(self):
        """Mock stop processing."""
        self._running = False
    
    async def create_incident(self, 
                             title: str,
                             description: str,
                             severity: IncidentSeverity,
                             source_component: str,
                             threat_indicators: List[str] = None,
                             affected_resources: List[str] = None,
                             tenant_id: Optional[str] = None,
                             metadata: Dict[str, Any] = None) -> SecurityIncident:
        """Mock create incident."""
        
        self.create_calls.append({
            'title': title,
            'description': description,
            'severity': severity,
            'source_component': source_component,
            'threat_indicators': threat_indicators or [],
            'affected_resources': affected_resources or [],
            'tenant_id': tenant_id,
            'metadata': metadata or {}
        })
        
        incident = SecurityIncident(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.NEW,
            source_component=source_component,
            threat_indicators=threat_indicators or [],
            affected_resources=affected_resources or [],
            timeline=[{
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event': 'Incident Created',
                'details': f'Created by {source_component}'
            }],
            evidence=[],
            response_actions=[],
            tenant_id=tenant_id,
            metadata=metadata or {}
        )
        
        self.database.store_incident(incident)
        return incident
    
    async def update_incident(self, 
                             incident_id: str,
                             status: Optional[IncidentStatus] = None,
                             assigned_analyst: Optional[str] = None,
                             add_timeline_event: Optional[Dict[str, Any]] = None,
                             add_evidence: Optional[Dict[str, Any]] = None,
                             add_response_action: Optional[str] = None) -> bool:
        """Mock update incident."""
        
        self.update_calls.append({
            'incident_id': incident_id,
            'status': status,
            'assigned_analyst': assigned_analyst,
            'timeline_event': add_timeline_event,
            'evidence': add_evidence,
            'response_action': add_response_action
        })
        
        incident = self.database.get_incident(incident_id)
        if not incident:
            return False
        
        if status:
            incident.status = status
            if status == IncidentStatus.RESOLVED:
                incident.resolved_at = datetime.now(timezone.utc)
        
        if assigned_analyst:
            incident.assigned_analyst = assigned_analyst
        
        if add_timeline_event:
            incident.timeline.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                **add_timeline_event
            })
        
        if add_evidence:
            incident.evidence.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                **add_evidence
            })
        
        if add_response_action:
            incident.response_actions.append(add_response_action)
        
        incident.updated_at = datetime.now(timezone.utc)
        self.database.store_incident(incident)
        return True
    
    async def escalate_incident(self, incident_id: str, reason: str) -> bool:
        """Mock escalate incident."""
        
        self.escalation_calls.append({'incident_id': incident_id, 'reason': reason})
        
        incident = self.database.get_incident(incident_id)
        if not incident:
            return False
        
        # Mock escalation logic
        severity_escalation = {
            IncidentSeverity.INFORMATIONAL: IncidentSeverity.LOW,
            IncidentSeverity.LOW: IncidentSeverity.MEDIUM,
            IncidentSeverity.MEDIUM: IncidentSeverity.HIGH,
            IncidentSeverity.HIGH: IncidentSeverity.CRITICAL,
            IncidentSeverity.CRITICAL: IncidentSeverity.EMERGENCY
        }
        
        new_severity = severity_escalation.get(incident.severity, incident.severity)
        if new_severity != incident.severity:
            incident.severity = new_severity
            await self.update_incident(
                incident_id,
                add_timeline_event={
                    'event': 'Incident Escalated',
                    'details': f'Escalated to {new_severity.value}: {reason}'
                }
            )
            return True
        
        return False
    
    def add_incident_processor(self, processor):
        """Mock add processor."""
        self.incident_processors.append(processor)


class MockPlaybookEngine:
    """Mock playbook engine for testing."""
    
    def __init__(self, database, incident_manager):
        self.database = database
        self.incident_manager = incident_manager
        self.action_handlers = {}
        self.execution_calls = []
        self.matching_calls = []
        
        # Setup mock handlers
        for action in PlaybookAction:
            self.action_handlers[action.value] = self._mock_action_handler
    
    async def execute_playbook(self, playbook: SecurityPlaybook, 
                              incident: SecurityIncident) -> Dict[str, Any]:
        """Mock execute playbook."""
        
        self.execution_calls.append({
            'playbook_id': playbook.id,
            'incident_id': incident.id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        execution_log = {
            'execution_id': str(uuid.uuid4()),
            'playbook_id': playbook.id,
            'incident_id': incident.id,
            'start_time': datetime.now(timezone.utc),
            'actions_executed': [],
            'success': True,
            'error_message': None
        }
        
        # Mock action execution
        for action_config in playbook.actions:
            action_type = action_config.get('type')
            action_params = action_config.get('parameters', {})
            
            action_result = await self._mock_action_handler(incident, action_params)
            
            execution_log['actions_executed'].append({
                'action_type': action_type,
                'parameters': action_params,
                'result': action_result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        
        execution_log['end_time'] = datetime.now(timezone.utc)
        
        # Update playbook stats
        playbook.execution_count += 1
        playbook.last_executed = datetime.now(timezone.utc)
        playbook.success_rate = 1.0
        
        return execution_log
    
    async def find_matching_playbooks(self, incident: SecurityIncident,
                                     tenant_id: Optional[str] = None) -> List[SecurityPlaybook]:
        """Mock find matching playbooks."""
        
        self.matching_calls.append({
            'incident_id': incident.id,
            'tenant_id': tenant_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        playbooks = self.database.get_active_playbooks(tenant_id)
        matching_playbooks = []
        
        for playbook in playbooks:
            # Simple mock matching logic
            trigger_conditions = playbook.trigger_conditions
            
            if 'severity' in trigger_conditions:
                required_severities = trigger_conditions['severity']
                if isinstance(required_severities, str):
                    required_severities = [required_severities]
                
                if incident.severity.value in required_severities:
                    matching_playbooks.append(playbook)
            
            elif 'source_component' in trigger_conditions:
                required_components = trigger_conditions['source_component']
                if isinstance(required_components, str):
                    required_components = [required_components]
                
                if incident.source_component in required_components:
                    matching_playbooks.append(playbook)
        
        return sorted(matching_playbooks, key=lambda p: p.priority, reverse=True)
    
    async def _mock_action_handler(self, incident: SecurityIncident, 
                                  params: Dict[str, Any]) -> Dict[str, Any]:
        """Mock action handler."""
        return {
            'status': 'success',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'mock_execution': True
        }


class MockThreatCorrelationEngine:
    """Mock threat correlation engine for testing."""
    
    def __init__(self):
        self.correlation_rules = []
        self.pattern_cache = {}
        self.correlation_history = deque(maxlen=10000)
        self.analysis_calls = []
        self.rule_additions = []
    
    async def analyze_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Mock analyze events."""
        
        self.analysis_calls.append({
            'event_count': len(events),
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        correlations = []
        current_time = time.time()
        
        # Add events to history
        for event in events:
            event['timestamp'] = current_time
            self.correlation_history.append(event)
        
        # Mock correlation detection
        if len(events) > 3:  # Arbitrary threshold for demo
            correlations.append({
                'correlation_id': str(uuid.uuid4()),
                'rule_id': 'mock_correlation_rule',
                'rule_name': 'Mock High Activity Correlation',
                'description': 'Detected high activity pattern',
                'severity': 'medium',
                'confidence': 0.75,
                'satisfied_conditions': 2,
                'total_conditions': 3,
                'matching_events': events,
                'detection_time': datetime.now(timezone.utc).isoformat(),
                'timeframe_seconds': 300
            })
        # Also check historical events for correlation  
        elif len(self.correlation_history) >= 5:
            # Create correlation based on recent events
            recent_events = list(self.correlation_history)[-5:]
            correlations.append({
                'correlation_id': str(uuid.uuid4()),
                'rule_id': 'mock_historical_correlation_rule',
                'rule_name': 'Mock Multi-Event Correlation',
                'description': 'Detected correlation across recent events',
                'severity': 'high',
                'confidence': 0.85,
                'satisfied_conditions': 3,
                'total_conditions': 3,
                'matching_events': recent_events,
                'detection_time': datetime.now(timezone.utc).isoformat(),
                'timeframe_seconds': 600
            })
        
        return correlations
    
    def add_correlation_rule(self, rule: Dict[str, Any]):
        """Mock add correlation rule."""
        self.rule_additions.append(rule)
        self.correlation_rules.append(rule)
    
    def get_correlation_statistics(self) -> Dict[str, Any]:
        """Mock get statistics."""
        return {
            'total_rules': len(self.correlation_rules),
            'events_in_history': len(self.correlation_history),
            'cache_size': len(self.pattern_cache),
            'analysis_calls': len(self.analysis_calls)
        }


class MockMultiTenantManager:
    """Mock multi-tenant manager for testing."""
    
    def __init__(self, database):
        self.database = database
        self.tenant_configs = {}
        self.tenant_metrics = defaultdict(lambda: {
            'requests': 0,
            'incidents': 0,
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'last_activity': datetime.now(timezone.utc)
        })
        self.create_calls = []
        self.resource_checks = []
        self.metrics_updates = []
    
    async def create_tenant(self, tenant_id: str, tenant_name: str, 
                           config: Dict[str, Any] = None) -> TenantConfiguration:
        """Mock create tenant."""
        
        self.create_calls.append({
            'tenant_id': tenant_id,
            'tenant_name': tenant_name,
            'config': config or {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        tenant_config = TenantConfiguration(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            resource_limits=config.get('resource_limits', {
                'max_requests_per_minute': 1000,
                'max_incidents_per_hour': 100,
                'max_cpu_percent': 80,
                'max_memory_mb': 1024
            }) if config else {
                'max_requests_per_minute': 1000,
                'max_incidents_per_hour': 100,
                'max_cpu_percent': 80,
                'max_memory_mb': 1024
            },
            security_policies=config.get('security_policies', {}) if config else {},
            enabled_components=config.get('enabled_components', [
                'rate_limiting', 'input_validation'
            ]) if config else ['rate_limiting', 'input_validation'],
            compliance_requirements=config.get('compliance_requirements', []) if config else [],
            notification_settings=config.get('notification_settings', {}) if config else {},
            custom_configurations=config.get('custom_configurations', {}) if config else {}
        )
        
        self.tenant_configs[tenant_id] = tenant_config
        return tenant_config
    
    def get_tenant_config(self, tenant_id: str) -> Optional[TenantConfiguration]:
        """Mock get tenant config."""
        return self.tenant_configs.get(tenant_id)
    
    async def check_resource_limits(self, tenant_id: str, 
                                  resource_type: str, current_usage: float) -> bool:
        """Mock check resource limits."""
        
        self.resource_checks.append({
            'tenant_id': tenant_id,
            'resource_type': resource_type,
            'current_usage': current_usage,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        config = self.get_tenant_config(tenant_id)
        if not config:
            return False
        
        limits = config.resource_limits
        limit_key = f"max_{resource_type}"
        
        if limit_key in limits:
            limit = limits[limit_key]
            return current_usage <= limit
        
        return True
    
    def update_tenant_metrics(self, tenant_id: str, metric_type: str, value: float):
        """Mock update tenant metrics."""
        
        self.metrics_updates.append({
            'tenant_id': tenant_id,
            'metric_type': metric_type,
            'value': value,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        self.tenant_metrics[tenant_id][metric_type] = value
        self.tenant_metrics[tenant_id]['last_activity'] = datetime.now(timezone.utc)
    
    def get_tenant_metrics(self, tenant_id: str) -> Dict[str, Any]:
        """Mock get tenant metrics."""
        return dict(self.tenant_metrics.get(tenant_id, {}))
    
    def get_all_tenant_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Mock get all tenant metrics."""
        return {tid: dict(metrics) for tid, metrics in self.tenant_metrics.items()}


class MockExternalIntegration:
    """Mock external integration for testing."""
    
    def __init__(self, integration_name: str, config: Dict[str, Any]):
        self.integration_name = integration_name
        self.config = config
        self.is_connected = False
        self.last_health_check = None
        self.connect_calls = []
        self.disconnect_calls = []
        self.health_check_calls = []
        self.send_data_calls = []
    
    async def connect(self) -> bool:
        """Mock connect."""
        self.connect_calls.append(datetime.now(timezone.utc).isoformat())
        self.is_connected = True
        return True
    
    async def disconnect(self) -> bool:
        """Mock disconnect."""
        self.disconnect_calls.append(datetime.now(timezone.utc).isoformat())
        self.is_connected = False
        return True
    
    async def health_check(self) -> bool:
        """Mock health check."""
        self.health_check_calls.append(datetime.now(timezone.utc).isoformat())
        self.last_health_check = datetime.now(timezone.utc)
        return self.is_connected
    
    async def send_data(self, data: Dict[str, Any]) -> bool:
        """Mock send data."""
        self.send_data_calls.append({
            'data_type': data.get('event_type', 'unknown'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data_size': len(str(data))
        })
        return self.is_connected


class MockSecurityOrchestrator:
    """Mock security orchestrator for testing."""
    
    def __init__(self):
        self.database = MockSOARDatabase()
        self.incident_manager = MockIncidentManager(self.database)
        self.playbook_engine = MockPlaybookEngine(self.database, self.incident_manager)
        self.threat_correlation = MockThreatCorrelationEngine()
        self.multi_tenant_manager = MockMultiTenantManager(self.database)
        
        self.integrations = {}
        self.registered_components = {}
        self.event_subscribers = []
        
        self.metrics = {
            'incidents_created': 0,
            'playbooks_executed': 0,
            'events_processed': 0,
            'correlations_detected': 0,
            'uptime_start': datetime.now(timezone.utc)
        }
        
        self._background_tasks = []
        self._running = False
        
        self.event_processing_calls = []
        self.playbook_creation_calls = []
    
    async def start(self):
        """Mock start."""
        self._running = True
        await self.incident_manager.start_processing()
    
    async def stop(self):
        """Mock stop."""
        self._running = False
        await self.incident_manager.stop_processing()
    
    def register_component(self, component_name: str, component_instance):
        """Mock register component."""
        self.registered_components[component_name] = component_instance
    
    def add_integration(self, integration_type: str, integration):
        """Mock add integration."""
        self.integrations[integration_type] = integration
    
    async def process_security_event(self, event: Dict[str, Any]) -> Optional[SecurityIncident]:
        """Mock process security event."""
        
        self.event_processing_calls.append({
            'event_type': event.get('event_type', 'unknown'),
            'component': event.get('component', 'unknown'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        self.metrics['events_processed'] += 1
        
        # Mock event processing
        correlations = await self.threat_correlation.analyze_events([event])
        
        if correlations:
            self.metrics['correlations_detected'] += len(correlations)
        
        # Create incident for certain event types or high severity
        event_type = event.get('event_type', '').lower()
        severity_str = event.get('severity', '').lower()
        if (any(keyword in event_type for keyword in ['attack', 'threat', 'violation', 'breach', 'detected']) or
            severity_str in ['high', 'critical', 'emergency']):
            incident = await self.incident_manager.create_incident(
                title=event.get('title', f"Security Event: {event.get('event_type', 'Unknown')}"),
                description=event.get('description', ''),
                severity=self._mock_determine_severity(event),
                source_component=event.get('component', 'unknown'),
                threat_indicators=event.get('threat_indicators', []),
                affected_resources=event.get('affected_resources', []),
                tenant_id=event.get('tenant_id'),
                metadata={'original_event': event, 'correlations': correlations}
            )
            
            self.metrics['incidents_created'] += 1
            
            # Find and execute matching playbooks
            playbooks = await self.playbook_engine.find_matching_playbooks(incident)
            for playbook in playbooks:
                if playbook.automation_level == 'fully-automated':
                    await self.playbook_engine.execute_playbook(playbook, incident)
                    self.metrics['playbooks_executed'] += 1
            
            # Mock integration notifications
            incident_data = incident.to_dict()
            for integration in self.integrations.values():
                if integration.is_connected:
                    await integration.send_data(incident_data)
            
            return incident
        
        return None
    
    async def create_custom_playbook(self, 
                                   name: str,
                                   description: str,
                                   trigger_conditions: Dict[str, Any],
                                   actions: List[Dict[str, Any]],
                                   automation_level: str = 'semi-automated',
                                   tenant_id: Optional[str] = None) -> SecurityPlaybook:
        """Mock create custom playbook."""
        
        self.playbook_creation_calls.append({
            'name': name,
            'description': description,
            'trigger_conditions': trigger_conditions,
            'actions': actions,
            'automation_level': automation_level,
            'tenant_id': tenant_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        playbook = SecurityPlaybook(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            trigger_conditions=trigger_conditions,
            actions=actions,
            automation_level=automation_level,
            tenant_id=tenant_id
        )
        
        self.database.store_playbook(playbook)
        return playbook
    
    def get_platform_status(self) -> Dict[str, Any]:
        """Mock get platform status."""
        
        uptime = datetime.now(timezone.utc) - self.metrics['uptime_start']
        
        integration_status = {}
        for int_type, integration in self.integrations.items():
            integration_status[int_type] = {
                'name': integration.integration_name,
                'connected': integration.is_connected,
                'last_health_check': integration.last_health_check
            }
        
        return {
            'platform_status': 'running' if self._running else 'stopped',
            'uptime_seconds': int(uptime.total_seconds()),
            'metrics': dict(self.metrics),
            'registered_components': list(self.registered_components.keys()),
            'integrations': integration_status,
            'tenant_metrics': self.multi_tenant_manager.get_all_tenant_metrics(),
            'correlation_stats': self.threat_correlation.get_correlation_statistics()
        }
    
    def _mock_determine_severity(self, event: Dict[str, Any]) -> IncidentSeverity:
        """Mock determine event severity."""
        event_type = event.get('event_type', '').lower()
        
        if 'critical' in event_type or 'breach' in event_type:
            return IncidentSeverity.CRITICAL
        elif 'attack' in event_type or 'threat' in event_type:
            return IncidentSeverity.HIGH
        elif 'violation' in event_type or 'suspicious' in event_type:
            return IncidentSeverity.MEDIUM
        else:
            return IncidentSeverity.LOW


class MockEnterpriseSOARTestEnvironment:
    """Comprehensive mock environment for Enterprise SOAR testing."""
    
    def __init__(self):
        self.orchestrator = MockSecurityOrchestrator()
        
        # Setup mock integrations
        self.siem_integration = MockExternalIntegration("SIEM", {
            'type': 'splunk',
            'endpoint_url': 'https://mock-siem.example.com',
            'api_key': 'mock_key'
        })
        
        self.ticketing_integration = MockExternalIntegration("Ticketing", {
            'type': 'servicenow',
            'endpoint_url': 'https://mock-ticketing.example.com',
            'credentials': {'username': 'mock_user', 'password': 'mock_pass'}
        })
        
        self.messaging_integration = MockExternalIntegration("Messaging", {
            'platform': 'slack',
            'webhook_url': 'https://hooks.slack.com/mock',
            'channels': {'critical': 'security-critical', 'high': 'security-alerts'}
        })
        
        # Add integrations to orchestrator
        self.orchestrator.add_integration('siem', self.siem_integration)
        self.orchestrator.add_integration('ticketing', self.ticketing_integration)
        self.orchestrator.add_integration('messaging', self.messaging_integration)
        
        # Test data generators
        self.test_incidents = self._generate_test_incidents()
        self.test_playbooks = self._generate_test_playbooks()
        self.test_events = self._generate_test_events()
        
        # Setup default playbooks in the orchestrator
        self._setup_default_playbooks()
        
        # Performance tracking
        self.performance_metrics = {
            'api_calls': [],
            'response_times': [],
            'processing_times': []
        }
    
    def _generate_test_incidents(self) -> List[SecurityIncident]:
        """Generate test security incidents."""
        incidents = []
        severities = [IncidentSeverity.LOW, IncidentSeverity.MEDIUM, 
                     IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
        
        for i in range(10):
            incident = SecurityIncident(
                id=str(uuid.uuid4()),
                title=f"Test Security Incident {i+1}",
                description=f"This is test incident #{i+1} for SOAR testing",
                severity=severities[i % len(severities)],
                status=IncidentStatus.NEW,
                source_component=f"test_component_{i % 3}",
                threat_indicators=[f"indicator_{i}_1", f"indicator_{i}_2"],
                affected_resources=[f"resource_{i}", f"system_{i % 2}"],
                timeline=[{
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'event': 'Incident Created',
                    'details': f'Test incident {i+1} created'
                }],
                evidence=[],
                response_actions=[],
                tenant_id=f"tenant_{i % 3}" if i % 3 else None,
                metadata={'test_data': True, 'incident_index': i}
            )
            incidents.append(incident)
        
        return incidents
    
    def _generate_test_playbooks(self) -> List[SecurityPlaybook]:
        """Generate test security playbooks."""
        playbooks = []
        
        # High severity response playbook
        high_severity_playbook = SecurityPlaybook(
            id=str(uuid.uuid4()),
            name="High Severity Response",
            description="Automated response for high severity incidents",
            trigger_conditions={'severity': ['high', 'critical', 'emergency']},
            actions=[
                {'type': 'analyze', 'parameters': {'type': 'threat_correlation'}},
                {'type': 'notify', 'parameters': {'recipients': ['security-team']}},
                {'type': 'collect_evidence', 'parameters': {'types': ['logs', 'network']}}
            ],
            automation_level='fully-automated'  # Changed to fully-automated for testing
        )
        playbooks.append(high_severity_playbook)
        
        # Bot detection playbook
        bot_playbook = SecurityPlaybook(
            id=str(uuid.uuid4()),
            name="Bot Detection Response",
            description="Automated bot detection response",
            trigger_conditions={'source_component': ['bot_detection']},
            actions=[
                {'type': 'block', 'parameters': {'target_type': 'ip', 'duration': '1h'}},
                {'type': 'update_rules', 'parameters': {'rule_type': 'rate_limiting'}}
            ],
            automation_level='fully-automated'
        )
        playbooks.append(bot_playbook)
        
        # Threat intelligence response playbook
        threat_intel_playbook = SecurityPlaybook(
            id=str(uuid.uuid4()),
            name="Threat Intelligence Response",
            description="Response for threat intelligence events",
            trigger_conditions={'source_component': ['threat_intelligence']},
            actions=[
                {'type': 'analyze', 'parameters': {'type': 'threat_analysis'}},
                {'type': 'escalate', 'parameters': {'reason': 'Threat intelligence detection'}},
                {'type': 'notify', 'parameters': {'recipients': ['threat-team']}}
            ],
            automation_level='fully-automated'
        )
        playbooks.append(threat_intel_playbook)
        
        return playbooks
    
    def _setup_default_playbooks(self):
        """Setup default playbooks in the orchestrator."""
        for playbook in self.test_playbooks:
            self.orchestrator.database.store_playbook(playbook)
    
    def _generate_test_events(self) -> List[Dict[str, Any]]:
        """Generate test security events."""
        events = []
        
        event_types = [
            'sql_injection_attempt', 'xss_attack_detected', 'brute_force_attack',
            'suspicious_file_upload', 'rate_limit_exceeded', 'bot_activity_detected'
        ]
        
        components = ['input_validation', 'bot_detection', 'rate_limiting', 
                     'file_upload', 'threat_intelligence']
        
        for i in range(20):
            event = {
                'id': str(uuid.uuid4()),
                'event_type': event_types[i % len(event_types)],
                'component': components[i % len(components)],
                'title': f"Security Event {i+1}",
                'description': f"Test security event #{i+1}",
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'threat_indicators': [f"test_indicator_{i}"],
                'affected_resources': [f"resource_{i}"],
                'tenant_id': f"tenant_{i % 3}" if i % 2 else None,
                'severity': ['low', 'medium', 'high'][i % 3],
                'metadata': {'test_event': True, 'event_index': i}
            }
            events.append(event)
        
        return events
    
    def track_performance(self, operation: str, duration: float):
        """Track performance metrics."""
        self.performance_metrics['api_calls'].append({
            'operation': operation,
            'timestamp': time.time(),
            'duration': duration
        })
        self.performance_metrics['response_times'].append(duration)
    
    def simulate_high_load(self, num_events: int = 1000, duration_seconds: int = 10):
        """Simulate high-load testing scenario."""
        start_time = time.time()
        events_processed = 0
        
        while time.time() - start_time < duration_seconds and events_processed < num_events:
            # Generate rapid events
            event = {
                'id': str(uuid.uuid4()),
                'event_type': 'high_load_test_event',
                'component': 'load_test',
                'title': f'Load Test Event {events_processed}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'severity': 'medium'
            }
            
            # Mock processing
            processing_start = time.time()
            time.sleep(0.001)  # 1ms processing time
            processing_time = time.time() - processing_start
            
            self.track_performance('process_event', processing_time)
            events_processed += 1
        
        return {
            'events_processed': events_processed,
            'duration': time.time() - start_time,
            'avg_response_time': sum(self.performance_metrics['response_times'][-events_processed:]) / events_processed,
            'max_response_time': max(self.performance_metrics['response_times'][-events_processed:]),
            'events_per_second': events_processed / (time.time() - start_time)
        }
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        if not self.performance_metrics['response_times']:
            return {'status': 'no_data'}
        
        response_times = self.performance_metrics['response_times']
        
        return {
            'total_operations': len(response_times),
            'avg_response_time': sum(response_times) / len(response_times),
            'max_response_time': max(response_times),
            'min_response_time': min(response_times),
            'total_api_calls': len(self.performance_metrics['api_calls'])
        }
    
    async def setup_test_data(self):
        """Setup comprehensive test data."""
        # Create test tenants
        for i in range(3):
            await self.orchestrator.multi_tenant_manager.create_tenant(
                tenant_id=f"tenant_{i}",
                tenant_name=f"Test Tenant {i+1}",
                config={
                    'resource_limits': {
                        'max_requests_per_minute': 1000 * (i + 1),
                        'max_incidents_per_hour': 50 * (i + 1)
                    },
                    'enabled_components': ['rate_limiting', 'input_validation', 'bot_detection']
                }
            )
        
        # Store test incidents
        for incident in self.test_incidents:
            self.orchestrator.database.store_incident(incident)
        
        # Store test playbooks
        for playbook in self.test_playbooks:
            self.orchestrator.database.store_playbook(playbook)
        
        # Connect integrations
        await self.siem_integration.connect()
        await self.ticketing_integration.connect()
        await self.messaging_integration.connect()
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.setup_test_data()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        pass
    
    def reset(self):
        """Reset all mock services and metrics."""
        self.orchestrator = MockSecurityOrchestrator()
        self.performance_metrics = {
            'api_calls': [],
            'response_times': [],
            'processing_times': []
        }
        
        # Reset integrations
        self.siem_integration = MockExternalIntegration("SIEM", {'type': 'splunk'})
        self.ticketing_integration = MockExternalIntegration("Ticketing", {'type': 'servicenow'})
        self.messaging_integration = MockExternalIntegration("Messaging", {'platform': 'slack'})


# Export all mock classes
__all__ = [
    'MockSOARDatabase',
    'MockIncidentManager',
    'MockPlaybookEngine',
    'MockThreatCorrelationEngine',
    'MockMultiTenantManager',
    'MockExternalIntegration',
    'MockSecurityOrchestrator',
    'MockEnterpriseSOARTestEnvironment'
]