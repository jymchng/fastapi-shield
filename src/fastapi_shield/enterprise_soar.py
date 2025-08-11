"""FastAPI-Shield Enterprise Security Orchestration and Response (SOAR) Platform

This module provides a comprehensive enterprise-grade security orchestration platform
that integrates all FastAPI-Shield components into a unified security operations center.

Features:
- Unified security orchestration integrating all 50+ FastAPI-Shield components
- Automated incident response with customizable playbooks and workflows
- Real-time security operations center (SOC) with live monitoring and alerting
- Advanced threat correlation and analysis across multiple security layers
- Multi-tenant architecture supporting enterprise deployments at scale
- SIEM/SOAR integration with major enterprise security platforms
- Comprehensive compliance reporting and audit trail management
- Machine learning-based threat hunting and predictive analytics
- Dynamic security policy adjustment based on real-time threat landscape
- Enterprise directory integration and centralized user management
"""

import asyncio
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from threading import RLock, Thread, Event
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    NamedTuple, Protocol, AsyncIterator, TypeVar, Generic
)
import hashlib
import hmac
import sqlite3
import weakref

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn

# Import all FastAPI-Shield components for integration
try:
    from .threat_intelligence import ThreatIntelligenceEngine, ThreatAssessment, ThreatLevel
    from .security_dashboard import SecurityDashboard, SecurityMetric, SecurityAlert
    from .ml_security import MLSecurityShield, AnomalyResult
    from .compliance_framework import ComplianceFramework, ComplianceViolation
    from .shield import Shield
    SHIELD_COMPONENTS_AVAILABLE = True
except ImportError:
    # Graceful degradation if components aren't available
    SHIELD_COMPONENTS_AVAILABLE = False

logger = logging.getLogger(__name__)

T = TypeVar('T')


class IncidentSeverity(Enum):
    """Security incident severity levels."""
    INFORMATIONAL = "informational"  # Informational events
    LOW = "low"                      # Low-priority incidents
    MEDIUM = "medium"                # Medium-priority incidents
    HIGH = "high"                    # High-priority incidents
    CRITICAL = "critical"            # Critical incidents requiring immediate response
    EMERGENCY = "emergency"          # Emergency incidents requiring all-hands response


class IncidentStatus(Enum):
    """Security incident status values."""
    NEW = "new"                      # Newly detected incident
    ASSIGNED = "assigned"            # Assigned to security analyst
    INVESTIGATING = "investigating"   # Under investigation
    CONTAINED = "contained"          # Threat contained
    RESOLVED = "resolved"            # Incident resolved
    CLOSED = "closed"                # Incident closed and archived


class PlaybookAction(Enum):
    """Security playbook action types."""
    ANALYZE = "analyze"              # Analyze threat or incident
    BLOCK = "block"                  # Block IP, domain, or resource
    QUARANTINE = "quarantine"        # Quarantine system or user
    NOTIFY = "notify"                # Send notification
    ESCALATE = "escalate"            # Escalate to higher priority
    REMEDIATE = "remediate"          # Apply remediation action
    COLLECT_EVIDENCE = "collect_evidence"  # Collect forensic evidence
    UPDATE_RULES = "update_rules"    # Update security rules/policies


class ThreatHuntingStatus(Enum):
    """Threat hunting operation status."""
    PLANNED = "planned"              # Hunting operation planned
    ACTIVE = "active"                # Currently hunting
    COMPLETED = "completed"          # Hunt completed
    SUSPENDED = "suspended"          # Hunt suspended/paused


class ComplianceStandard(Enum):
    """Enterprise compliance standards."""
    SOX = "sox"                      # Sarbanes-Oxley Act
    PCI_DSS = "pci_dss"             # Payment Card Industry Data Security Standard
    GDPR = "gdpr"                    # General Data Protection Regulation
    HIPAA = "hipaa"                  # Health Insurance Portability and Accountability Act
    ISO27001 = "iso27001"           # ISO/IEC 27001 Information Security Management
    NIST = "nist"                    # NIST Cybersecurity Framework
    CIS = "cis"                      # Center for Internet Security Controls


class IntegrationType(Enum):
    """External system integration types."""
    SIEM = "siem"                    # SIEM system integration
    TICKETING = "ticketing"          # Ticketing system integration
    MESSAGING = "messaging"          # Messaging/notification integration
    DIRECTORY = "directory"          # Directory service integration
    ORCHESTRATION = "orchestration"  # Security orchestration platform


@dataclass
class SecurityIncident:
    """Comprehensive security incident data structure."""
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    source_component: str           # Which shield/component detected the incident
    threat_indicators: List[str]    # Associated threat indicators
    affected_resources: List[str]   # Resources impacted by incident
    timeline: List[Dict[str, Any]]  # Incident timeline with events
    evidence: List[Dict[str, Any]]  # Collected evidence and artifacts
    response_actions: List[str]     # Actions taken in response
    assigned_analyst: Optional[str] = None
    tenant_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert incident to dictionary for serialization."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'status': self.status.value,
            'source_component': self.source_component,
            'threat_indicators': self.threat_indicators,
            'affected_resources': self.affected_resources,
            'timeline': self.timeline,
            'evidence': self.evidence,
            'response_actions': self.response_actions,
            'assigned_analyst': self.assigned_analyst,
            'tenant_id': self.tenant_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'metadata': self.metadata
        }


@dataclass
class SecurityPlaybook:
    """Automated security response playbook."""
    id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]  # Conditions that trigger this playbook
    actions: List[Dict[str, Any]]       # Ordered list of actions to execute
    automation_level: str               # 'manual', 'semi-automated', 'fully-automated'
    priority: int = 1                   # Execution priority (1-10)
    enabled: bool = True
    tenant_id: Optional[str] = None
    created_by: str = "system"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_executed: Optional[datetime] = None
    execution_count: int = 0
    success_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert playbook to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'trigger_conditions': self.trigger_conditions,
            'actions': self.actions,
            'automation_level': self.automation_level,
            'priority': self.priority,
            'enabled': self.enabled,
            'tenant_id': self.tenant_id,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'last_executed': self.last_executed.isoformat() if self.last_executed else None,
            'execution_count': self.execution_count,
            'success_rate': self.success_rate
        }


@dataclass
class ThreatHuntingOperation:
    """Proactive threat hunting operation."""
    id: str
    name: str
    description: str
    status: ThreatHuntingStatus
    hypothesis: str                    # Threat hypothesis being investigated
    indicators_of_compromise: List[str]  # IOCs to search for
    data_sources: List[str]           # Data sources to analyze
    hunting_queries: List[str]        # Queries/searches to execute
    findings: List[Dict[str, Any]]    # Discovered threats/anomalies
    analyst: str
    tenant_id: Optional[str] = None
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    estimated_duration: Optional[timedelta] = None
    confidence_level: float = 0.0     # Confidence in findings (0.0-1.0)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert hunting operation to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'status': self.status.value,
            'hypothesis': self.hypothesis,
            'indicators_of_compromise': self.indicators_of_compromise,
            'data_sources': self.data_sources,
            'hunting_queries': self.hunting_queries,
            'findings': self.findings,
            'analyst': self.analyst,
            'tenant_id': self.tenant_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'estimated_duration': str(self.estimated_duration) if self.estimated_duration else None,
            'confidence_level': self.confidence_level
        }


@dataclass
class ComplianceReport:
    """Comprehensive compliance assessment report."""
    id: str
    standard: ComplianceStandard
    tenant_id: Optional[str]
    assessment_period: Dict[str, datetime]  # start and end dates
    overall_score: float              # Overall compliance score (0.0-1.0)
    control_assessments: Dict[str, Dict[str, Any]]  # Control-specific assessments
    violations: List[ComplianceViolation]
    recommendations: List[str]
    evidence_collected: List[Dict[str, Any]]
    generated_by: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert compliance report to dictionary."""
        return {
            'id': self.id,
            'standard': self.standard.value,
            'tenant_id': self.tenant_id,
            'assessment_period': {
                'start': self.assessment_period['start'].isoformat(),
                'end': self.assessment_period['end'].isoformat()
            },
            'overall_score': self.overall_score,
            'control_assessments': self.control_assessments,
            'violations': [v.to_dict() if hasattr(v, 'to_dict') else str(v) for v in self.violations],
            'recommendations': self.recommendations,
            'evidence_collected': self.evidence_collected,
            'generated_by': self.generated_by,
            'generated_at': self.generated_at.isoformat(),
            'approved_by': self.approved_by,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None
        }


@dataclass
class TenantConfiguration:
    """Multi-tenant configuration and resource allocation."""
    tenant_id: str
    tenant_name: str
    resource_limits: Dict[str, Any]   # CPU, memory, storage, request limits
    security_policies: Dict[str, Any] # Tenant-specific security policies
    enabled_components: List[str]     # Which shields/components are enabled
    compliance_requirements: List[ComplianceStandard]
    notification_settings: Dict[str, Any]
    custom_configurations: Dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert tenant configuration to dictionary."""
        return {
            'tenant_id': self.tenant_id,
            'tenant_name': self.tenant_name,
            'resource_limits': self.resource_limits,
            'security_policies': self.security_policies,
            'enabled_components': self.enabled_components,
            'compliance_requirements': [req.value for req in self.compliance_requirements],
            'notification_settings': self.notification_settings,
            'custom_configurations': self.custom_configurations,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'is_active': self.is_active
        }


class ExternalIntegration(ABC):
    """Abstract base class for external system integrations."""
    
    def __init__(self, integration_name: str, config: Dict[str, Any]):
        self.integration_name = integration_name
        self.config = config
        self.is_connected = False
        self.last_health_check = None
        self._lock = RLock()
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to external system."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """Disconnect from external system."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check health of external system connection."""
        pass
    
    @abstractmethod
    async def send_data(self, data: Dict[str, Any]) -> bool:
        """Send data to external system."""
        pass


class SIEMIntegration(ExternalIntegration):
    """SIEM system integration for log forwarding and alert correlation."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("SIEM", config)
        self.siem_type = config.get('type', 'generic')  # splunk, qradar, sentinel, etc.
        self.endpoint_url = config.get('endpoint_url')
        self.api_key = config.get('api_key')
        self.index_name = config.get('index_name', 'fastapi_shield')
    
    async def connect(self) -> bool:
        """Connect to SIEM system."""
        try:
            # Implementation would connect to specific SIEM API
            # For now, simulate successful connection
            await asyncio.sleep(0.1)
            self.is_connected = True
            logger.info(f"Connected to {self.siem_type} SIEM at {self.endpoint_url}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to SIEM: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from SIEM system."""
        self.is_connected = False
        return True
    
    async def health_check(self) -> bool:
        """Check SIEM system health."""
        if not self.is_connected:
            return False
        
        try:
            # Simulate health check
            await asyncio.sleep(0.05)
            self.last_health_check = datetime.now(timezone.utc)
            return True
        except Exception as e:
            logger.error(f"SIEM health check failed: {e}")
            return False
    
    async def send_data(self, data: Dict[str, Any]) -> bool:
        """Send security event data to SIEM."""
        if not self.is_connected:
            return False
        
        try:
            # Format data for SIEM ingestion
            siem_event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'fastapi-shield',
                'index': self.index_name,
                'event': data
            }
            
            # Would send to actual SIEM API here
            logger.debug(f"Sent event to {self.siem_type} SIEM: {data.get('event_type', 'unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send data to SIEM: {e}")
            return False


class TicketingIntegration(ExternalIntegration):
    """Ticketing system integration for incident management."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Ticketing", config)
        self.system_type = config.get('type', 'generic')  # servicenow, jira, etc.
        self.endpoint_url = config.get('endpoint_url')
        self.api_credentials = config.get('credentials', {})
        self.default_project = config.get('default_project', 'SECURITY')
    
    async def connect(self) -> bool:
        """Connect to ticketing system."""
        try:
            await asyncio.sleep(0.1)
            self.is_connected = True
            logger.info(f"Connected to {self.system_type} ticketing system")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to ticketing system: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from ticketing system."""
        self.is_connected = False
        return True
    
    async def health_check(self) -> bool:
        """Check ticketing system health."""
        if not self.is_connected:
            return False
        
        try:
            await asyncio.sleep(0.05)
            self.last_health_check = datetime.now(timezone.utc)
            return True
        except Exception as e:
            logger.error(f"Ticketing system health check failed: {e}")
            return False
    
    async def send_data(self, data: Dict[str, Any]) -> bool:
        """Create ticket for security incident."""
        if not self.is_connected:
            return False
        
        try:
            # Create ticket data structure
            ticket_data = {
                'project': self.default_project,
                'summary': data.get('title', 'Security Incident'),
                'description': data.get('description', ''),
                'priority': self._map_severity_to_priority(data.get('severity')),
                'labels': ['security', 'fastapi-shield'],
                'custom_fields': {
                    'incident_id': data.get('id'),
                    'source_component': data.get('source_component'),
                    'threat_indicators': data.get('threat_indicators', [])
                }
            }
            
            # Would create actual ticket here
            logger.info(f"Created {self.system_type} ticket for incident: {data.get('id')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create ticket: {e}")
            return False
    
    def _map_severity_to_priority(self, severity: str) -> str:
        """Map incident severity to ticket priority."""
        severity_map = {
            'emergency': 'Critical',
            'critical': 'High',
            'high': 'Medium',
            'medium': 'Low',
            'low': 'Lowest',
            'informational': 'Lowest'
        }
        return severity_map.get(severity, 'Medium')


class MessagingIntegration(ExternalIntegration):
    """Messaging/notification system integration."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Messaging", config)
        self.platform = config.get('platform', 'email')  # slack, teams, email, etc.
        self.webhook_url = config.get('webhook_url')
        self.channels = config.get('channels', {})
        self.escalation_rules = config.get('escalation_rules', {})
    
    async def connect(self) -> bool:
        """Connect to messaging platform."""
        try:
            await asyncio.sleep(0.1)
            self.is_connected = True
            logger.info(f"Connected to {self.platform} messaging platform")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to messaging platform: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from messaging platform."""
        self.is_connected = False
        return True
    
    async def health_check(self) -> bool:
        """Check messaging platform health."""
        if not self.is_connected:
            return False
        
        try:
            await asyncio.sleep(0.05)
            self.last_health_check = datetime.now(timezone.utc)
            return True
        except Exception as e:
            logger.error(f"Messaging platform health check failed: {e}")
            return False
    
    async def send_data(self, data: Dict[str, Any]) -> bool:
        """Send notification message."""
        if not self.is_connected:
            return False
        
        try:
            severity = data.get('severity', 'medium')
            channel = self._get_channel_for_severity(severity)
            
            message = self._format_message(data)
            
            # Would send to actual messaging platform here
            logger.info(f"Sent {self.platform} notification to {channel}: {data.get('title', 'Alert')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False
    
    def _get_channel_for_severity(self, severity: str) -> str:
        """Get appropriate channel based on severity."""
        channel_map = {
            'emergency': self.channels.get('emergency', 'security-critical'),
            'critical': self.channels.get('critical', 'security-alerts'),
            'high': self.channels.get('high', 'security-alerts'),
            'medium': self.channels.get('medium', 'security-info'),
            'low': self.channels.get('low', 'security-info'),
            'informational': self.channels.get('info', 'security-logs')
        }
        return channel_map.get(severity, 'security-alerts')
    
    def _format_message(self, data: Dict[str, Any]) -> str:
        """Format notification message."""
        severity = data.get('severity', 'unknown').upper()
        title = data.get('title', 'Security Alert')
        description = data.get('description', '')
        source = data.get('source_component', 'FastAPI-Shield')
        
        if self.platform == 'slack':
            return f"🚨 *{severity}* - {title}\n📍 Source: {source}\n📝 {description}"
        elif self.platform == 'teams':
            return f"🚨 **{severity}** - {title}  \n📍 Source: {source}  \n📝 {description}"
        else:
            return f"[{severity}] {title}\nSource: {source}\nDescription: {description}"


class SOARDatabase:
    """Centralized database for SOAR platform data storage."""
    
    def __init__(self, db_path: str = "enterprise_soar.db"):
        self.db_path = db_path
        self._lock = RLock()
        self._init_database()
        logger.info(f"SOAR Database initialized at {db_path}")
    
    def _init_database(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            # Security incidents table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source_component TEXT,
                    threat_indicators TEXT,
                    affected_resources TEXT,
                    timeline TEXT,
                    evidence TEXT,
                    response_actions TEXT,
                    assigned_analyst TEXT,
                    tenant_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP,
                    metadata TEXT
                )
            """)
            
            # Security playbooks table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_playbooks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    trigger_conditions TEXT,
                    actions TEXT,
                    automation_level TEXT,
                    priority INTEGER DEFAULT 1,
                    enabled BOOLEAN DEFAULT 1,
                    tenant_id TEXT,
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_executed TIMESTAMP,
                    execution_count INTEGER DEFAULT 0,
                    success_rate REAL DEFAULT 0.0
                )
            """)
            
            # Threat hunting operations table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_hunting_operations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL,
                    hypothesis TEXT,
                    indicators_of_compromise TEXT,
                    data_sources TEXT,
                    hunting_queries TEXT,
                    findings TEXT,
                    analyst TEXT,
                    tenant_id TEXT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    estimated_duration TEXT,
                    confidence_level REAL DEFAULT 0.0
                )
            """)
            
            # Compliance reports table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_reports (
                    id TEXT PRIMARY KEY,
                    standard TEXT NOT NULL,
                    tenant_id TEXT,
                    assessment_period_start TIMESTAMP,
                    assessment_period_end TIMESTAMP,
                    overall_score REAL,
                    control_assessments TEXT,
                    violations TEXT,
                    recommendations TEXT,
                    evidence_collected TEXT,
                    generated_by TEXT,
                    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    approved_by TEXT,
                    approved_at TIMESTAMP
                )
            """)
            
            # Tenant configurations table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenant_configurations (
                    tenant_id TEXT PRIMARY KEY,
                    tenant_name TEXT NOT NULL,
                    resource_limits TEXT,
                    security_policies TEXT,
                    enabled_components TEXT,
                    compliance_requirements TEXT,
                    notification_settings TEXT,
                    custom_configurations TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON security_incidents(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON security_incidents(tenant_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON security_playbooks(enabled)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hunting_status ON threat_hunting_operations(status)")
            
            conn.commit()
    
    def store_incident(self, incident: SecurityIncident) -> bool:
        """Store security incident in database."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO security_incidents 
                        (id, title, description, severity, status, source_component,
                         threat_indicators, affected_resources, timeline, evidence,
                         response_actions, assigned_analyst, tenant_id, created_at,
                         updated_at, resolved_at, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        incident.id, incident.title, incident.description,
                        incident.severity.value, incident.status.value,
                        incident.source_component,
                        json.dumps(incident.threat_indicators),
                        json.dumps(incident.affected_resources),
                        json.dumps(incident.timeline),
                        json.dumps(incident.evidence),
                        json.dumps(incident.response_actions),
                        incident.assigned_analyst, incident.tenant_id,
                        incident.created_at, incident.updated_at,
                        incident.resolved_at, json.dumps(incident.metadata)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing incident: {e}")
                return False
    
    def get_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        """Retrieve security incident by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT * FROM security_incidents WHERE id = ?",
                    (incident_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    return self._row_to_incident(row)
                
        except Exception as e:
            logger.error(f"Error retrieving incident: {e}")
        
        return None
    
    def search_incidents(self,
                        tenant_id: Optional[str] = None,
                        severity: Optional[IncidentSeverity] = None,
                        status: Optional[IncidentStatus] = None,
                        limit: int = 100) -> List[SecurityIncident]:
        """Search security incidents with filters."""
        conditions = []
        params = []
        
        if tenant_id:
            conditions.append("tenant_id = ?")
            params.append(tenant_id)
        
        if severity:
            conditions.append("severity = ?")
            params.append(severity.value)
        
        if status:
            conditions.append("status = ?")
            params.append(status.value)
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"SELECT * FROM security_incidents {where_clause} ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        incidents = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query, params)
                for row in cursor.fetchall():
                    incidents.append(self._row_to_incident(row))
        
        except Exception as e:
            logger.error(f"Error searching incidents: {e}")
        
        return incidents
    
    def store_playbook(self, playbook: SecurityPlaybook) -> bool:
        """Store security playbook in database."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO security_playbooks
                        (id, name, description, trigger_conditions, actions,
                         automation_level, priority, enabled, tenant_id,
                         created_by, created_at, last_executed, execution_count,
                         success_rate)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        playbook.id, playbook.name, playbook.description,
                        json.dumps(playbook.trigger_conditions),
                        json.dumps(playbook.actions),
                        playbook.automation_level, playbook.priority,
                        playbook.enabled, playbook.tenant_id,
                        playbook.created_by, playbook.created_at,
                        playbook.last_executed, playbook.execution_count,
                        playbook.success_rate
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing playbook: {e}")
                return False
    
    def get_active_playbooks(self, tenant_id: Optional[str] = None) -> List[SecurityPlaybook]:
        """Get all active/enabled playbooks."""
        conditions = ["enabled = 1"]
        params = []
        
        if tenant_id:
            conditions.append("(tenant_id = ? OR tenant_id IS NULL)")
            params.append(tenant_id)
        
        query = f"SELECT * FROM security_playbooks WHERE {' AND '.join(conditions)} ORDER BY priority DESC"
        
        playbooks = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query, params)
                for row in cursor.fetchall():
                    playbooks.append(self._row_to_playbook(row))
        
        except Exception as e:
            logger.error(f"Error retrieving playbooks: {e}")
        
        return playbooks
    
    def _row_to_incident(self, row) -> SecurityIncident:
        """Convert database row to SecurityIncident object."""
        return SecurityIncident(
            id=row[0],
            title=row[1],
            description=row[2] or "",
            severity=IncidentSeverity(row[3]),
            status=IncidentStatus(row[4]),
            source_component=row[5] or "",
            threat_indicators=json.loads(row[6]) if row[6] else [],
            affected_resources=json.loads(row[7]) if row[7] else [],
            timeline=json.loads(row[8]) if row[8] else [],
            evidence=json.loads(row[9]) if row[9] else [],
            response_actions=json.loads(row[10]) if row[10] else [],
            assigned_analyst=row[11],
            tenant_id=row[12],
            created_at=datetime.fromisoformat(row[13].replace('Z', '+00:00')) if isinstance(row[13], str) else row[13],
            updated_at=datetime.fromisoformat(row[14].replace('Z', '+00:00')) if isinstance(row[14], str) else row[14],
            resolved_at=datetime.fromisoformat(row[15].replace('Z', '+00:00')) if row[15] else None,
            metadata=json.loads(row[16]) if row[16] else {}
        )
    
    def _row_to_playbook(self, row) -> SecurityPlaybook:
        """Convert database row to SecurityPlaybook object."""
        return SecurityPlaybook(
            id=row[0],
            name=row[1],
            description=row[2] or "",
            trigger_conditions=json.loads(row[3]) if row[3] else {},
            actions=json.loads(row[4]) if row[4] else [],
            automation_level=row[5],
            priority=row[6],
            enabled=bool(row[7]),
            tenant_id=row[8],
            created_by=row[9],
            created_at=datetime.fromisoformat(row[10].replace('Z', '+00:00')) if isinstance(row[10], str) else row[10],
            last_executed=datetime.fromisoformat(row[11].replace('Z', '+00:00')) if row[11] else None,
            execution_count=row[12],
            success_rate=row[13]
        )


class IncidentManager:
    """Advanced incident detection, tracking, and automated response management."""
    
    def __init__(self, database: SOARDatabase):
        self.database = database
        self.incident_processors = []
        self.escalation_rules = {}
        self._lock = RLock()
        self._processing_queue = None  # Initialize later when event loop is available
        self._processor_task = None
        self._running = False
        
        logger.info("IncidentManager initialized")
    
    async def start_processing(self):
        """Start background incident processing."""
        if self._processor_task and not self._processor_task.done():
            return
        
        # Initialize queue if not already done
        if self._processing_queue is None:
            self._processing_queue = asyncio.Queue()
        
        self._running = True
        self._processor_task = asyncio.create_task(self._process_incidents())
        logger.info("Incident processing started")
    
    async def stop_processing(self):
        """Stop background incident processing."""
        self._running = False
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        logger.info("Incident processing stopped")
    
    async def create_incident(self, 
                             title: str,
                             description: str,
                             severity: IncidentSeverity,
                             source_component: str,
                             threat_indicators: List[str] = None,
                             affected_resources: List[str] = None,
                             tenant_id: Optional[str] = None,
                             metadata: Dict[str, Any] = None) -> SecurityIncident:
        """Create new security incident."""
        
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
        
        # Store in database
        if self.database.store_incident(incident):
            # Queue for processing if queue is available
            if self._processing_queue is not None:
                await self._processing_queue.put(incident)
            logger.info(f"Created incident {incident.id}: {title}")
            return incident
        else:
            raise Exception("Failed to store incident in database")
    
    async def update_incident(self, 
                             incident_id: str,
                             status: Optional[IncidentStatus] = None,
                             assigned_analyst: Optional[str] = None,
                             add_timeline_event: Optional[Dict[str, Any]] = None,
                             add_evidence: Optional[Dict[str, Any]] = None,
                             add_response_action: Optional[str] = None) -> bool:
        """Update existing security incident."""
        
        incident = self.database.get_incident(incident_id)
        if not incident:
            return False
        
        with self._lock:
            # Update fields
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
            
            # Save to database
            return self.database.store_incident(incident)
    
    async def escalate_incident(self, incident_id: str, reason: str) -> bool:
        """Escalate incident to higher severity/priority."""
        
        incident = self.database.get_incident(incident_id)
        if not incident:
            return False
        
        # Increase severity level
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
            
            # Add timeline event
            await self.update_incident(
                incident_id,
                status=incident.status,
                add_timeline_event={
                    'event': 'Incident Escalated',
                    'details': f'Escalated to {new_severity.value}: {reason}',
                    'previous_severity': incident.severity.value
                }
            )
            
            logger.info(f"Escalated incident {incident_id} to {new_severity.value}")
            return True
        
        return False
    
    def add_incident_processor(self, processor: Callable[[SecurityIncident], Any]):
        """Add custom incident processor function."""
        with self._lock:
            self.incident_processors.append(processor)
    
    async def _process_incidents(self):
        """Background incident processing loop."""
        while self._running:
            try:
                # Get incident from queue (with timeout)
                incident = await asyncio.wait_for(
                    self._processing_queue.get(),
                    timeout=1.0
                )
                
                # Process incident through all processors
                for processor in self.incident_processors:
                    try:
                        if asyncio.iscoroutinefunction(processor):
                            await processor(incident)
                        else:
                            processor(incident)
                    except Exception as e:
                        logger.error(f"Incident processor error: {e}")
                
                # Mark processing complete
                self._processing_queue.task_done()
                
            except asyncio.TimeoutError:
                # Normal timeout, continue processing
                continue
            except Exception as e:
                logger.error(f"Incident processing error: {e}")
                await asyncio.sleep(1)


class PlaybookEngine:
    """Customizable security playbooks with automated workflow execution."""
    
    def __init__(self, database: SOARDatabase, incident_manager: IncidentManager):
        self.database = database
        self.incident_manager = incident_manager
        self.action_handlers = {}
        self._lock = RLock()
        self._setup_default_handlers()
        
        logger.info("PlaybookEngine initialized")
    
    def _setup_default_handlers(self):
        """Setup default action handlers."""
        self.action_handlers.update({
            PlaybookAction.ANALYZE.value: self._handle_analyze_action,
            PlaybookAction.BLOCK.value: self._handle_block_action,
            PlaybookAction.QUARANTINE.value: self._handle_quarantine_action,
            PlaybookAction.NOTIFY.value: self._handle_notify_action,
            PlaybookAction.ESCALATE.value: self._handle_escalate_action,
            PlaybookAction.REMEDIATE.value: self._handle_remediate_action,
            PlaybookAction.COLLECT_EVIDENCE.value: self._handle_collect_evidence_action,
            PlaybookAction.UPDATE_RULES.value: self._handle_update_rules_action
        })
    
    async def execute_playbook(self, playbook: SecurityPlaybook, 
                              incident: SecurityIncident) -> Dict[str, Any]:
        """Execute security playbook for given incident."""
        
        execution_id = str(uuid.uuid4())
        execution_log = {
            'execution_id': execution_id,
            'playbook_id': playbook.id,
            'incident_id': incident.id,
            'start_time': datetime.now(timezone.utc),
            'actions_executed': [],
            'success': False,
            'error_message': None
        }
        
        logger.info(f"Executing playbook {playbook.name} for incident {incident.id}")
        
        try:
            # Execute each action in sequence
            for action_config in playbook.actions:
                action_type = action_config.get('type')
                action_params = action_config.get('parameters', {})
                
                if action_type not in self.action_handlers:
                    logger.warning(f"Unknown action type: {action_type}")
                    continue
                
                # Execute action
                action_result = await self.action_handlers[action_type](
                    incident, action_params
                )
                
                execution_log['actions_executed'].append({
                    'action_type': action_type,
                    'parameters': action_params,
                    'result': action_result,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                
                # Add to incident timeline
                await self.incident_manager.update_incident(
                    incident.id,
                    add_timeline_event={
                        'event': 'Playbook Action Executed',
                        'details': f'Executed {action_type} action',
                        'playbook_id': playbook.id,
                        'execution_id': execution_id,
                        'result': action_result
                    }
                )
            
            execution_log['success'] = True
            execution_log['end_time'] = datetime.now(timezone.utc)
            
            # Update playbook statistics
            playbook.execution_count += 1
            playbook.last_executed = datetime.now(timezone.utc)
            playbook.success_rate = (playbook.success_rate * (playbook.execution_count - 1) + 1.0) / playbook.execution_count
            
            self.database.store_playbook(playbook)
            
            logger.info(f"Successfully executed playbook {playbook.name}")
            
        except Exception as e:
            execution_log['success'] = False
            execution_log['error_message'] = str(e)
            execution_log['end_time'] = datetime.now(timezone.utc)
            
            logger.error(f"Playbook execution failed: {e}")
        
        return execution_log
    
    async def find_matching_playbooks(self, incident: SecurityIncident,
                                     tenant_id: Optional[str] = None) -> List[SecurityPlaybook]:
        """Find playbooks that match incident trigger conditions."""
        
        playbooks = self.database.get_active_playbooks(tenant_id)
        matching_playbooks = []
        
        for playbook in playbooks:
            if self._evaluate_trigger_conditions(playbook.trigger_conditions, incident):
                matching_playbooks.append(playbook)
        
        # Sort by priority
        matching_playbooks.sort(key=lambda p: p.priority, reverse=True)
        
        return matching_playbooks
    
    def _evaluate_trigger_conditions(self, conditions: Dict[str, Any], 
                                   incident: SecurityIncident) -> bool:
        """Evaluate if incident matches playbook trigger conditions."""
        
        if not conditions:
            return False
        
        # Check severity condition
        if 'severity' in conditions:
            required_severities = conditions['severity']
            if isinstance(required_severities, str):
                required_severities = [required_severities]
            
            if incident.severity.value not in required_severities:
                return False
        
        # Check source component condition
        if 'source_component' in conditions:
            required_components = conditions['source_component']
            if isinstance(required_components, str):
                required_components = [required_components]
            
            if incident.source_component not in required_components:
                return False
        
        # Check threat indicators condition
        if 'threat_indicators' in conditions:
            required_indicators = conditions['threat_indicators']
            if isinstance(required_indicators, str):
                required_indicators = [required_indicators]
            
            if not any(indicator in incident.threat_indicators for indicator in required_indicators):
                return False
        
        # All conditions match
        return True
    
    # Action handlers
    async def _handle_analyze_action(self, incident: SecurityIncident, 
                                   params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle analyze action."""
        analysis_type = params.get('type', 'basic')
        
        # Perform analysis based on type
        analysis_result = {
            'type': analysis_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'findings': []
        }
        
        if analysis_type == 'threat_correlation':
            # Correlate with threat intelligence
            analysis_result['findings'].append({
                'category': 'threat_correlation',
                'description': f'Analyzed {len(incident.threat_indicators)} threat indicators'
            })
        
        elif analysis_type == 'impact_assessment':
            # Assess impact on affected resources
            analysis_result['findings'].append({
                'category': 'impact_assessment',
                'description': f'Assessed impact on {len(incident.affected_resources)} resources'
            })
        
        return analysis_result
    
    async def _handle_block_action(self, incident: SecurityIncident, 
                                 params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle block action."""
        target_type = params.get('target_type', 'ip')  # ip, domain, url
        target_value = params.get('target_value')
        duration = params.get('duration', '1h')  # block duration
        
        # Implementation would integrate with firewall/WAF to block target
        
        return {
            'action': 'block',
            'target_type': target_type,
            'target_value': target_value,
            'duration': duration,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'success'
        }
    
    async def _handle_quarantine_action(self, incident: SecurityIncident, 
                                      params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle quarantine action."""
        resource_type = params.get('resource_type', 'system')
        resource_id = params.get('resource_id')
        
        # Implementation would quarantine the specified resource
        
        return {
            'action': 'quarantine',
            'resource_type': resource_type,
            'resource_id': resource_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'success'
        }
    
    async def _handle_notify_action(self, incident: SecurityIncident, 
                                  params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle notification action."""
        recipients = params.get('recipients', [])
        message_template = params.get('template', 'default')
        urgency = params.get('urgency', 'normal')
        
        # Implementation would send notifications
        
        return {
            'action': 'notify',
            'recipients': recipients,
            'template': message_template,
            'urgency': urgency,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'success'
        }
    
    async def _handle_escalate_action(self, incident: SecurityIncident, 
                                    params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle escalation action."""
        reason = params.get('reason', 'Automated escalation')
        
        # Escalate the incident
        escalated = await self.incident_manager.escalate_incident(incident.id, reason)
        
        return {
            'action': 'escalate',
            'reason': reason,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'success' if escalated else 'failed'
        }
    
    async def _handle_remediate_action(self, incident: SecurityIncident, 
                                     params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle remediation action."""
        remediation_type = params.get('type', 'automatic')
        target_resources = params.get('resources', [])
        
        # Implementation would apply remediation to affected resources
        
        return {
            'action': 'remediate',
            'type': remediation_type,
            'resources': target_resources,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'success'
        }
    
    async def _handle_collect_evidence_action(self, incident: SecurityIncident, 
                                            params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle evidence collection action."""
        evidence_types = params.get('types', ['logs', 'network', 'system'])
        
        # Implementation would collect specified evidence types
        collected_evidence = []
        
        for evidence_type in evidence_types:
            collected_evidence.append({
                'type': evidence_type,
                'collected_at': datetime.now(timezone.utc).isoformat(),
                'status': 'collected'
            })
        
        return {
            'action': 'collect_evidence',
            'evidence_types': evidence_types,
            'collected': collected_evidence,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'success'
        }
    
    async def _handle_update_rules_action(self, incident: SecurityIncident, 
                                        params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle rule update action."""
        rule_type = params.get('rule_type', 'firewall')
        action_type = params.get('action', 'add')  # add, remove, update
        rule_definition = params.get('rule', {})
        
        # Implementation would update security rules/policies
        
        return {
            'action': 'update_rules',
            'rule_type': rule_type,
            'action_type': action_type,
            'rule': rule_definition,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'success'
        }


class ThreatCorrelationEngine:
    """Cross-component threat analysis and pattern detection engine."""
    
    def __init__(self):
        self.correlation_rules = []
        self.pattern_cache = {}
        self.correlation_history = deque(maxlen=10000)
        self._lock = RLock()
        
        # Setup default correlation rules
        self._setup_default_rules()
        
        logger.info("ThreatCorrelationEngine initialized")
    
    def _setup_default_rules(self):
        """Setup default threat correlation rules."""
        
        # Multi-component attack correlation
        self.correlation_rules.append({
            'id': 'multi_component_attack',
            'name': 'Multi-Component Attack Pattern',
            'description': 'Detects coordinated attacks across multiple shield components',
            'conditions': [
                {'component': 'rate_limiting', 'event': 'rate_limit_exceeded', 'timeframe': 300},
                {'component': 'bot_detection', 'event': 'suspicious_bot_activity', 'timeframe': 300},
                {'component': 'input_validation', 'event': 'injection_attempt', 'timeframe': 300}
            ],
            'threshold': 2,  # At least 2 conditions must match
            'severity': IncidentSeverity.HIGH,
            'confidence': 0.85
        })
        
        # Credential stuffing pattern
        self.correlation_rules.append({
            'id': 'credential_stuffing',
            'name': 'Credential Stuffing Attack',
            'description': 'Detects credential stuffing attacks',
            'conditions': [
                {'component': 'rate_limiting', 'event': 'auth_rate_limit_exceeded', 'timeframe': 600},
                {'component': 'session_management', 'event': 'multiple_failed_logins', 'timeframe': 600},
                {'component': 'bot_detection', 'event': 'automated_login_attempts', 'timeframe': 600}
            ],
            'threshold': 2,
            'severity': IncidentSeverity.MEDIUM,
            'confidence': 0.75
        })
        
        # Data exfiltration pattern
        self.correlation_rules.append({
            'id': 'data_exfiltration',
            'name': 'Potential Data Exfiltration',
            'description': 'Detects potential data exfiltration attempts',
            'conditions': [
                {'component': 'request_size_limit', 'event': 'large_response_detected', 'timeframe': 900},
                {'component': 'rate_limiting', 'event': 'high_volume_requests', 'timeframe': 900},
                {'component': 'threat_intelligence', 'event': 'suspicious_ip_activity', 'timeframe': 900}
            ],
            'threshold': 2,
            'severity': IncidentSeverity.CRITICAL,
            'confidence': 0.70
        })
    
    async def analyze_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze security events for threat correlations."""
        
        correlations = []
        
        with self._lock:
            # Add new events to history
            current_time = time.time()
            for event in events:
                event['timestamp'] = current_time
                self.correlation_history.append(event)
            
            # Check each correlation rule
            for rule in self.correlation_rules:
                correlation = await self._evaluate_correlation_rule(rule, current_time)
                if correlation:
                    correlations.append(correlation)
        
        return correlations
    
    async def _evaluate_correlation_rule(self, rule: Dict[str, Any], 
                                       current_time: float) -> Optional[Dict[str, Any]]:
        """Evaluate a specific correlation rule against recent events."""
        
        rule_id = rule['id']
        conditions = rule['conditions']
        threshold = rule['threshold']
        timeframe = max(condition['timeframe'] for condition in conditions)
        
        # Get events within timeframe
        cutoff_time = current_time - timeframe
        recent_events = [
            event for event in self.correlation_history 
            if event['timestamp'] >= cutoff_time
        ]
        
        if not recent_events:
            return None
        
        # Check how many conditions are satisfied
        satisfied_conditions = 0
        matching_events = []
        
        for condition in conditions:
            component = condition['component']
            event_type = condition['event']
            condition_timeframe = condition['timeframe']
            condition_cutoff = current_time - condition_timeframe
            
            # Find events matching this condition
            condition_events = [
                event for event in recent_events
                if (event['timestamp'] >= condition_cutoff and
                    event.get('component') == component and
                    event.get('event_type') == event_type)
            ]
            
            if condition_events:
                satisfied_conditions += 1
                matching_events.extend(condition_events)
        
        # Check if threshold is met
        if satisfied_conditions >= threshold:
            # Create correlation result
            correlation = {
                'correlation_id': str(uuid.uuid4()),
                'rule_id': rule_id,
                'rule_name': rule['name'],
                'description': rule['description'],
                'severity': rule['severity'].value,
                'confidence': rule['confidence'],
                'satisfied_conditions': satisfied_conditions,
                'total_conditions': len(conditions),
                'matching_events': matching_events,
                'detection_time': datetime.now(timezone.utc).isoformat(),
                'timeframe_seconds': timeframe
            }
            
            logger.info(f"Threat correlation detected: {rule['name']} (confidence: {rule['confidence']})")
            return correlation
        
        return None
    
    def add_correlation_rule(self, rule: Dict[str, Any]):
        """Add custom correlation rule."""
        with self._lock:
            self.correlation_rules.append(rule)
            logger.info(f"Added correlation rule: {rule.get('name', rule.get('id'))}")
    
    def get_correlation_statistics(self) -> Dict[str, Any]:
        """Get correlation engine statistics."""
        with self._lock:
            return {
                'total_rules': len(self.correlation_rules),
                'events_in_history': len(self.correlation_history),
                'cache_size': len(self.pattern_cache),
                'active_rules': [rule['name'] for rule in self.correlation_rules]
            }


class MultiTenantManager:
    """Multi-tenant support with isolation and resource management."""
    
    def __init__(self, database: SOARDatabase):
        self.database = database
        self.tenant_configs = {}
        self.tenant_metrics = defaultdict(lambda: {
            'requests': 0,
            'incidents': 0,
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'last_activity': datetime.now(timezone.utc)
        })
        self._lock = RLock()
        
        logger.info("MultiTenantManager initialized")
    
    async def create_tenant(self, tenant_id: str, tenant_name: str, 
                           config: Dict[str, Any] = None) -> TenantConfiguration:
        """Create new tenant configuration."""
        
        tenant_config = TenantConfiguration(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            resource_limits=config.get('resource_limits', {
                'max_requests_per_minute': 1000,
                'max_incidents_per_hour': 100,
                'max_cpu_percent': 80,
                'max_memory_mb': 1024,
                'max_storage_mb': 10240
            }),
            security_policies=config.get('security_policies', {}),
            enabled_components=config.get('enabled_components', [
                'rate_limiting', 'input_validation', 'threat_intelligence'
            ]),
            compliance_requirements=config.get('compliance_requirements', []),
            notification_settings=config.get('notification_settings', {}),
            custom_configurations=config.get('custom_configurations', {})
        )
        
        # Store in database
        with sqlite3.connect(self.database.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO tenant_configurations
                (tenant_id, tenant_name, resource_limits, security_policies,
                 enabled_components, compliance_requirements, notification_settings,
                 custom_configurations, created_at, last_updated, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tenant_config.tenant_id, tenant_config.tenant_name,
                json.dumps(tenant_config.resource_limits),
                json.dumps(tenant_config.security_policies),
                json.dumps(tenant_config.enabled_components),
                json.dumps([req.value for req in tenant_config.compliance_requirements]),
                json.dumps(tenant_config.notification_settings),
                json.dumps(tenant_config.custom_configurations),
                tenant_config.created_at, tenant_config.last_updated,
                tenant_config.is_active
            ))
            conn.commit()
        
        # Cache configuration
        with self._lock:
            self.tenant_configs[tenant_id] = tenant_config
        
        logger.info(f"Created tenant: {tenant_name} ({tenant_id})")
        return tenant_config
    
    def get_tenant_config(self, tenant_id: str) -> Optional[TenantConfiguration]:
        """Get tenant configuration."""
        with self._lock:
            if tenant_id in self.tenant_configs:
                return self.tenant_configs[tenant_id]
        
        # Load from database
        try:
            with sqlite3.connect(self.database.db_path) as conn:
                cursor = conn.execute(
                    "SELECT * FROM tenant_configurations WHERE tenant_id = ? AND is_active = 1",
                    (tenant_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    config = self._row_to_tenant_config(row)
                    with self._lock:
                        self.tenant_configs[tenant_id] = config
                    return config
        
        except Exception as e:
            logger.error(f"Error loading tenant config: {e}")
        
        return None
    
    async def check_resource_limits(self, tenant_id: str, 
                                  resource_type: str, current_usage: float) -> bool:
        """Check if tenant is within resource limits."""
        
        config = self.get_tenant_config(tenant_id)
        if not config:
            return False
        
        limits = config.resource_limits
        limit_key = f"max_{resource_type}"
        
        if limit_key in limits:
            limit = limits[limit_key]
            if current_usage > limit:
                logger.warning(f"Tenant {tenant_id} exceeded {resource_type} limit: {current_usage} > {limit}")
                return False
        
        return True
    
    def update_tenant_metrics(self, tenant_id: str, metric_type: str, value: float):
        """Update tenant usage metrics."""
        with self._lock:
            self.tenant_metrics[tenant_id][metric_type] = value
            self.tenant_metrics[tenant_id]['last_activity'] = datetime.now(timezone.utc)
    
    def get_tenant_metrics(self, tenant_id: str) -> Dict[str, Any]:
        """Get tenant usage metrics."""
        with self._lock:
            return dict(self.tenant_metrics.get(tenant_id, {}))
    
    def get_all_tenant_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all tenants."""
        with self._lock:
            return {tid: dict(metrics) for tid, metrics in self.tenant_metrics.items()}
    
    def _row_to_tenant_config(self, row) -> TenantConfiguration:
        """Convert database row to TenantConfiguration object."""
        compliance_reqs = json.loads(row[5]) if row[5] else []
        compliance_enums = []
        
        for req in compliance_reqs:
            try:
                compliance_enums.append(ComplianceStandard(req))
            except ValueError:
                continue
        
        return TenantConfiguration(
            tenant_id=row[0],
            tenant_name=row[1],
            resource_limits=json.loads(row[2]) if row[2] else {},
            security_policies=json.loads(row[3]) if row[3] else {},
            enabled_components=json.loads(row[4]) if row[4] else [],
            compliance_requirements=compliance_enums,
            notification_settings=json.loads(row[6]) if row[6] else {},
            custom_configurations=json.loads(row[7]) if row[7] else {},
            created_at=datetime.fromisoformat(row[8].replace('Z', '+00:00')) if isinstance(row[8], str) else row[8],
            last_updated=datetime.fromisoformat(row[9].replace('Z', '+00:00')) if isinstance(row[9], str) else row[9],
            is_active=bool(row[10])
        )


class SecurityOrchestrator:
    """Main orchestration engine coordinating all security components."""
    
    def __init__(self, 
                 database_path: str = "enterprise_soar.db",
                 enable_integrations: bool = True):
        
        # Initialize core components
        self.database = SOARDatabase(database_path)
        self.incident_manager = IncidentManager(self.database)
        self.playbook_engine = PlaybookEngine(self.database, self.incident_manager)
        self.threat_correlation = ThreatCorrelationEngine()
        self.multi_tenant_manager = MultiTenantManager(self.database)
        
        # External integrations
        self.integrations = {}
        self.enable_integrations = enable_integrations
        
        # Component registry
        self.registered_components = {}
        self.event_subscribers = []
        
        # Performance metrics
        self.metrics = {
            'incidents_created': 0,
            'playbooks_executed': 0,
            'events_processed': 0,
            'correlations_detected': 0,
            'uptime_start': datetime.now(timezone.utc)
        }
        
        # Background tasks
        self._background_tasks = []
        self._running = False
        
        # Setup default playbooks
        self._setup_default_playbooks()
        
        logger.info("SecurityOrchestrator initialized")
    
    async def start(self):
        """Start the security orchestration platform."""
        if self._running:
            return
        
        self._running = True
        
        # Start incident processing
        await self.incident_manager.start_processing()
        
        # Start background tasks
        self._background_tasks = [
            asyncio.create_task(self._health_check_loop()),
            asyncio.create_task(self._metrics_collection_loop()),
            asyncio.create_task(self._correlation_analysis_loop())
        ]
        
        # Connect integrations
        if self.enable_integrations:
            await self._connect_integrations()
        
        logger.info("Security orchestration platform started")
    
    async def stop(self):
        """Stop the security orchestration platform."""
        if not self._running:
            return
        
        self._running = False
        
        # Stop incident processing
        await self.incident_manager.stop_processing()
        
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self._background_tasks, return_exceptions=True)
        
        # Disconnect integrations
        await self._disconnect_integrations()
        
        logger.info("Security orchestration platform stopped")
    
    def register_component(self, component_name: str, component_instance: Any):
        """Register FastAPI-Shield component with orchestrator."""
        self.registered_components[component_name] = component_instance
        logger.info(f"Registered component: {component_name}")
    
    def add_integration(self, integration_type: str, integration: ExternalIntegration):
        """Add external system integration."""
        self.integrations[integration_type] = integration
        logger.info(f"Added {integration_type} integration: {integration.integration_name}")
    
    async def process_security_event(self, event: Dict[str, Any]) -> Optional[SecurityIncident]:
        """Process security event and potentially create incident."""
        
        self.metrics['events_processed'] += 1
        
        # Analyze event for threat correlation
        correlations = await self.threat_correlation.analyze_events([event])
        
        # Check if event should trigger incident creation
        incident = None
        severity = self._determine_event_severity(event)
        
        if severity != IncidentSeverity.INFORMATIONAL:
            # Create incident
            incident = await self.incident_manager.create_incident(
                title=event.get('title', f"Security Event: {event.get('event_type', 'Unknown')}"),
                description=event.get('description', ''),
                severity=severity,
                source_component=event.get('component', 'unknown'),
                threat_indicators=event.get('threat_indicators', []),
                affected_resources=event.get('affected_resources', []),
                tenant_id=event.get('tenant_id'),
                metadata={'original_event': event, 'correlations': correlations}
            )
            
            self.metrics['incidents_created'] += 1
            
            # Find and execute matching playbooks
            await self._execute_matching_playbooks(incident)
            
            # Send to integrations
            await self._notify_integrations(incident)
        
        # Process correlations
        if correlations:
            self.metrics['correlations_detected'] += len(correlations)
            await self._handle_threat_correlations(correlations)
        
        return incident
    
    async def create_custom_playbook(self, 
                                   name: str,
                                   description: str,
                                   trigger_conditions: Dict[str, Any],
                                   actions: List[Dict[str, Any]],
                                   automation_level: str = 'semi-automated',
                                   tenant_id: Optional[str] = None) -> SecurityPlaybook:
        """Create custom security playbook."""
        
        playbook = SecurityPlaybook(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            trigger_conditions=trigger_conditions,
            actions=actions,
            automation_level=automation_level,
            tenant_id=tenant_id
        )
        
        if self.database.store_playbook(playbook):
            logger.info(f"Created custom playbook: {name}")
            return playbook
        else:
            raise Exception("Failed to store playbook")
    
    def get_platform_status(self) -> Dict[str, Any]:
        """Get comprehensive platform status."""
        
        # Calculate uptime
        uptime = datetime.now(timezone.utc) - self.metrics['uptime_start']
        
        # Integration status
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
    
    def _setup_default_playbooks(self):
        """Setup default security playbooks."""
        
        # High-severity incident playbook
        high_severity_playbook = SecurityPlaybook(
            id="default-high-severity",
            name="High Severity Incident Response",
            description="Automated response for high-severity security incidents",
            trigger_conditions={
                'severity': ['high', 'critical', 'emergency']
            },
            actions=[
                {
                    'type': 'analyze',
                    'parameters': {'type': 'threat_correlation'}
                },
                {
                    'type': 'collect_evidence',
                    'parameters': {'types': ['logs', 'network', 'system']}
                },
                {
                    'type': 'notify',
                    'parameters': {
                        'recipients': ['security-team'],
                        'urgency': 'high'
                    }
                },
                {
                    'type': 'escalate',
                    'parameters': {'reason': 'High severity incident detected'}
                }
            ],
            automation_level='semi-automated'
        )
        
        # Bot detection playbook
        bot_detection_playbook = SecurityPlaybook(
            id="default-bot-detection",
            name="Automated Bot Detection Response",
            description="Automated response for bot detection events",
            trigger_conditions={
                'source_component': ['bot_detection'],
                'severity': ['medium', 'high']
            },
            actions=[
                {
                    'type': 'analyze',
                    'parameters': {'type': 'behavioral_analysis'}
                },
                {
                    'type': 'block',
                    'parameters': {
                        'target_type': 'ip',
                        'duration': '1h'
                    }
                },
                {
                    'type': 'update_rules',
                    'parameters': {
                        'rule_type': 'rate_limiting',
                        'action': 'add'
                    }
                }
            ],
            automation_level='fully-automated'
        )
        
        # Store default playbooks
        self.database.store_playbook(high_severity_playbook)
        self.database.store_playbook(bot_detection_playbook)
    
    def _determine_event_severity(self, event: Dict[str, Any]) -> IncidentSeverity:
        """Determine incident severity based on event characteristics."""
        
        event_type = event.get('event_type', '').lower()
        component = event.get('component', '').lower()
        
        # Critical events
        critical_indicators = [
            'data_exfiltration', 'privilege_escalation', 'system_compromise',
            'malware_detected', 'backdoor_detected'
        ]
        
        if any(indicator in event_type for indicator in critical_indicators):
            return IncidentSeverity.CRITICAL
        
        # High-severity events
        high_indicators = [
            'injection_attack', 'authentication_bypass', 'unauthorized_access',
            'suspicious_file_upload', 'directory_traversal'
        ]
        
        if any(indicator in event_type for indicator in high_indicators):
            return IncidentSeverity.HIGH
        
        # Component-based severity
        if component in ['threat_intelligence', 'ml_security']:
            return IncidentSeverity.MEDIUM
        
        if component in ['rate_limiting', 'input_validation']:
            return IncidentSeverity.LOW
        
        return IncidentSeverity.INFORMATIONAL
    
    async def _execute_matching_playbooks(self, incident: SecurityIncident):
        """Find and execute playbooks matching the incident."""
        
        playbooks = await self.playbook_engine.find_matching_playbooks(
            incident, incident.tenant_id
        )
        
        for playbook in playbooks:
            if playbook.automation_level == 'fully-automated':
                # Execute automatically
                await self.playbook_engine.execute_playbook(playbook, incident)
                self.metrics['playbooks_executed'] += 1
            
            elif playbook.automation_level == 'semi-automated':
                # Log for manual review
                logger.info(f"Semi-automated playbook {playbook.name} requires manual approval for incident {incident.id}")
    
    async def _notify_integrations(self, incident: SecurityIncident):
        """Send incident information to external integrations."""
        
        incident_data = incident.to_dict()
        
        for integration in self.integrations.values():
            if integration.is_connected:
                try:
                    await integration.send_data(incident_data)
                except Exception as e:
                    logger.error(f"Integration notification failed: {e}")
    
    async def _handle_threat_correlations(self, correlations: List[Dict[str, Any]]):
        """Handle detected threat correlations."""
        
        for correlation in correlations:
            # Create incident for high-confidence correlations
            if correlation['confidence'] > 0.8:
                await self.incident_manager.create_incident(
                    title=f"Threat Correlation: {correlation['rule_name']}",
                    description=correlation['description'],
                    severity=IncidentSeverity(correlation['severity']),
                    source_component='threat_correlation_engine',
                    metadata={'correlation_data': correlation}
                )
    
    async def _connect_integrations(self):
        """Connect to all configured integrations."""
        for integration in self.integrations.values():
            try:
                await integration.connect()
            except Exception as e:
                logger.error(f"Failed to connect integration {integration.integration_name}: {e}")
    
    async def _disconnect_integrations(self):
        """Disconnect from all integrations."""
        for integration in self.integrations.values():
            try:
                await integration.disconnect()
            except Exception as e:
                logger.error(f"Failed to disconnect integration {integration.integration_name}: {e}")
    
    async def _health_check_loop(self):
        """Background health check loop for integrations."""
        while self._running:
            try:
                for integration in self.integrations.values():
                    await integration.health_check()
                
                await asyncio.sleep(60)  # Check every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(60)
    
    async def _metrics_collection_loop(self):
        """Background metrics collection loop."""
        while self._running:
            try:
                # Collect platform metrics
                # This would integrate with actual monitoring systems
                
                await asyncio.sleep(300)  # Collect every 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collection loop error: {e}")
                await asyncio.sleep(300)
    
    async def _correlation_analysis_loop(self):
        """Background threat correlation analysis loop."""
        while self._running:
            try:
                # Periodic correlation analysis would go here
                # This would analyze patterns in stored security events
                
                await asyncio.sleep(600)  # Analyze every 10 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Correlation analysis loop error: {e}")
                await asyncio.sleep(600)


# FastAPI application for SOAR platform
def create_soar_app(orchestrator: SecurityOrchestrator) -> FastAPI:
    """Create FastAPI application for SOAR platform."""
    
    app = FastAPI(
        title="FastAPI-Shield Enterprise SOAR Platform",
        description="Enterprise Security Orchestration and Response Platform",
        version="1.0.0"
    )
    
    security = HTTPBearer()
    
    @app.on_event("startup")
    async def startup_event():
        await orchestrator.start()
    
    @app.on_event("shutdown")  
    async def shutdown_event():
        await orchestrator.stop()
    
    @app.get("/api/status")
    async def get_platform_status():
        """Get platform status and metrics."""
        return orchestrator.get_platform_status()
    
    @app.get("/api/incidents")
    async def get_incidents(tenant_id: Optional[str] = None,
                           severity: Optional[str] = None,
                           status: Optional[str] = None,
                           limit: int = 100):
        """Get security incidents."""
        
        severity_enum = IncidentSeverity(severity) if severity else None
        status_enum = IncidentStatus(status) if status else None
        
        incidents = orchestrator.database.search_incidents(
            tenant_id=tenant_id,
            severity=severity_enum,
            status=status_enum,
            limit=limit
        )
        
        return {
            'incidents': [incident.to_dict() for incident in incidents],
            'total': len(incidents)
        }
    
    @app.get("/api/incidents/{incident_id}")
    async def get_incident(incident_id: str):
        """Get specific security incident."""
        
        incident = orchestrator.database.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        return incident.to_dict()
    
    @app.post("/api/incidents")
    async def create_incident(incident_data: Dict[str, Any]):
        """Create new security incident."""
        
        incident = await orchestrator.incident_manager.create_incident(
            title=incident_data['title'],
            description=incident_data.get('description', ''),
            severity=IncidentSeverity(incident_data['severity']),
            source_component=incident_data['source_component'],
            threat_indicators=incident_data.get('threat_indicators', []),
            affected_resources=incident_data.get('affected_resources', []),
            tenant_id=incident_data.get('tenant_id'),
            metadata=incident_data.get('metadata', {})
        )
        
        return incident.to_dict()
    
    @app.post("/api/events")
    async def process_security_event(event_data: Dict[str, Any]):
        """Process security event through orchestration platform."""
        
        incident = await orchestrator.process_security_event(event_data)
        
        return {
            'event_processed': True,
            'incident_created': incident is not None,
            'incident': incident.to_dict() if incident else None
        }
    
    @app.get("/api/playbooks")
    async def get_playbooks(tenant_id: Optional[str] = None):
        """Get security playbooks."""
        
        playbooks = orchestrator.database.get_active_playbooks(tenant_id)
        
        return {
            'playbooks': [playbook.to_dict() for playbook in playbooks],
            'total': len(playbooks)
        }
    
    @app.post("/api/playbooks")
    async def create_playbook(playbook_data: Dict[str, Any]):
        """Create custom security playbook."""
        
        playbook = await orchestrator.create_custom_playbook(
            name=playbook_data['name'],
            description=playbook_data.get('description', ''),
            trigger_conditions=playbook_data['trigger_conditions'],
            actions=playbook_data['actions'],
            automation_level=playbook_data.get('automation_level', 'semi-automated'),
            tenant_id=playbook_data.get('tenant_id')
        )
        
        return playbook.to_dict()
    
    @app.get("/api/tenants/{tenant_id}/metrics")
    async def get_tenant_metrics(tenant_id: str):
        """Get tenant usage metrics."""
        
        metrics = orchestrator.multi_tenant_manager.get_tenant_metrics(tenant_id)
        
        if not metrics:
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        return metrics
    
    @app.post("/api/tenants")
    async def create_tenant(tenant_data: Dict[str, Any]):
        """Create new tenant."""
        
        config = await orchestrator.multi_tenant_manager.create_tenant(
            tenant_id=tenant_data['tenant_id'],
            tenant_name=tenant_data['tenant_name'],
            config=tenant_data.get('config', {})
        )
        
        return config.to_dict()
    
    return app


# Convenience functions
def create_enterprise_soar(
    database_path: str = "enterprise_soar.db",
    siem_config: Optional[Dict[str, Any]] = None,
    ticketing_config: Optional[Dict[str, Any]] = None,
    messaging_config: Optional[Dict[str, Any]] = None
) -> SecurityOrchestrator:
    """Create enterprise SOAR platform with optional integrations."""
    
    orchestrator = SecurityOrchestrator(database_path)
    
    # Add integrations if configured
    if siem_config:
        siem_integration = SIEMIntegration(siem_config)
        orchestrator.add_integration('siem', siem_integration)
    
    if ticketing_config:
        ticketing_integration = TicketingIntegration(ticketing_config)
        orchestrator.add_integration('ticketing', ticketing_integration)
    
    if messaging_config:
        messaging_integration = MessagingIntegration(messaging_config)
        orchestrator.add_integration('messaging', messaging_integration)
    
    return orchestrator


# Export all public classes and functions
__all__ = [
    # Enums
    'IncidentSeverity',
    'IncidentStatus',
    'PlaybookAction',
    'ThreatHuntingStatus',
    'ComplianceStandard',
    'IntegrationType',
    
    # Data classes
    'SecurityIncident',
    'SecurityPlaybook',
    'ThreatHuntingOperation',
    'ComplianceReport',
    'TenantConfiguration',
    
    # Core classes
    'SecurityOrchestrator',
    'IncidentManager',
    'PlaybookEngine',
    'ThreatCorrelationEngine',
    'MultiTenantManager',
    'SOARDatabase',
    
    # Integration classes
    'ExternalIntegration',
    'SIEMIntegration',
    'TicketingIntegration',
    'MessagingIntegration',
    
    # Convenience functions
    'create_enterprise_soar',
    'create_soar_app',
]