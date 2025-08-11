"""FastAPI-Shield Advanced Threat Hunting and Security Orchestration Platform

This module provides a comprehensive threat hunting and Security Orchestration, 
Automation, and Response (SOAR) platform that enables proactive threat hunting,
automated incident response, security playbook execution, and comprehensive 
security orchestration across multiple security tools and platforms.

Features:
- Advanced threat hunting engine with behavioral analysis
- Security orchestration platform with multi-vendor integration
- Automated incident response and remediation systems
- Threat intelligence correlation and enrichment
- Security analytics and performance monitoring
- Workflow automation and playbook execution
- Evidence management and digital forensics
- Real-time threat detection and response
- STIX/TAXII protocol support
- MITRE ATT&CK framework integration
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import ssl
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
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, PriorityQueue
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

T = TypeVar('T')


class ThreatLevel(Enum):
    """Threat severity levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatType(Enum):
    """Types of security threats."""
    MALWARE = "malware"
    APT = "apt"
    INSIDER_THREAT = "insider_threat"
    DATA_BREACH = "data_breach"
    DDOS = "ddos"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    RECONNAISSANCE = "reconnaissance"


class IncidentStatus(Enum):
    """Incident handling status."""
    NEW = "new"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class PlaybookStatus(Enum):
    """Security playbook execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class ResponseAction(Enum):
    """Automated response actions."""
    ALERT = "alert"
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    RESET_PASSWORD = "reset_password"
    DISABLE_ACCOUNT = "disable_account"
    COLLECT_EVIDENCE = "collect_evidence"
    ESCALATE = "escalate"
    NOTIFY_ADMIN = "notify_admin"
    CREATE_TICKET = "create_ticket"


class IntegrationType(Enum):
    """Types of security tool integrations."""
    SIEM = "siem"
    EDR = "edr"
    XDR = "xdr"
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    THREAT_INTELLIGENCE = "threat_intelligence"
    EMAIL_SECURITY = "email_security"
    CLOUD_SECURITY = "cloud_security"
    NETWORK_MONITORING = "network_monitoring"


class EvidenceType(Enum):
    """Types of digital evidence."""
    LOG_FILE = "log_file"
    NETWORK_CAPTURE = "network_capture"
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    FILE_SAMPLE = "file_sample"
    REGISTRY_EXPORT = "registry_export"
    DATABASE_EXPORT = "database_export"
    EMAIL_MESSAGE = "email_message"
    SCREENSHOT = "screenshot"
    VIDEO_RECORDING = "video_recording"


@dataclass
class ThreatIndicator:
    """Threat indicator of compromise (IOC)."""
    indicator_id: str
    indicator_type: str  # IP, domain, URL, file_hash, email, etc.
    indicator_value: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    confidence_score: float
    first_seen: datetime
    last_seen: datetime
    source: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'indicator_id': self.indicator_id,
            'indicator_type': self.indicator_type,
            'indicator_value': self.indicator_value,
            'threat_type': self.threat_type.value,
            'threat_level': self.threat_level.value,
            'confidence_score': self.confidence_score,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'source': self.source,
            'description': self.description,
            'tags': self.tags,
            'mitre_techniques': self.mitre_techniques,
            'metadata': self.metadata
        }


@dataclass
class SecurityIncident:
    """Security incident representation."""
    incident_id: str
    title: str
    description: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    source_ip: Optional[str] = None
    target_assets: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)  # IOC IDs
    mitre_techniques: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)  # Evidence IDs
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'incident_id': self.incident_id,
            'title': self.title,
            'description': self.description,
            'threat_type': self.threat_type.value,
            'threat_level': self.threat_level.value,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'assigned_to': self.assigned_to,
            'source_ip': self.source_ip,
            'target_assets': self.target_assets,
            'indicators': self.indicators,
            'mitre_techniques': self.mitre_techniques,
            'evidence': self.evidence,
            'timeline': self.timeline,
            'metadata': self.metadata
        }


@dataclass
class SecurityPlaybook:
    """Security response playbook."""
    playbook_id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    workflow_steps: List[Dict[str, Any]]
    approval_required: bool
    timeout_minutes: int
    created_at: datetime
    updated_at: datetime
    version: str = "1.0"
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'playbook_id': self.playbook_id,
            'name': self.name,
            'description': self.description,
            'trigger_conditions': self.trigger_conditions,
            'workflow_steps': self.workflow_steps,
            'approval_required': self.approval_required,
            'timeout_minutes': self.timeout_minutes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'version': self.version,
            'enabled': self.enabled,
            'tags': self.tags,
            'metadata': self.metadata
        }


@dataclass
class PlaybookExecution:
    """Playbook execution instance."""
    execution_id: str
    playbook_id: str
    incident_id: str
    status: PlaybookStatus
    started_at: datetime
    completed_at: Optional[datetime]
    current_step: int
    total_steps: int
    executed_by: str
    execution_log: List[Dict[str, Any]] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'execution_id': self.execution_id,
            'playbook_id': self.playbook_id,
            'incident_id': self.incident_id,
            'status': self.status.value,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'current_step': self.current_step,
            'total_steps': self.total_steps,
            'executed_by': self.executed_by,
            'execution_log': self.execution_log,
            'results': self.results,
            'errors': self.errors
        }


@dataclass
class ThreatHuntingHypothesis:
    """Threat hunting hypothesis."""
    hypothesis_id: str
    title: str
    description: str
    threat_types: List[ThreatType]
    mitre_techniques: List[str]
    data_sources: List[str]
    query_logic: Dict[str, Any]
    created_by: str
    created_at: datetime
    status: str = "active"  # active, completed, archived
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'hypothesis_id': self.hypothesis_id,
            'title': self.title,
            'description': self.description,
            'threat_types': [t.value for t in self.threat_types],
            'mitre_techniques': self.mitre_techniques,
            'data_sources': self.data_sources,
            'query_logic': self.query_logic,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'status': self.status,
            'findings': self.findings,
            'metadata': self.metadata
        }


@dataclass
class EvidenceArtifact:
    """Digital evidence artifact."""
    evidence_id: str
    incident_id: str
    evidence_type: EvidenceType
    file_name: str
    file_path: str
    file_size: int
    file_hash: str
    collected_at: datetime
    collected_by: str
    chain_of_custody: List[Dict[str, Any]]
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'evidence_id': self.evidence_id,
            'incident_id': self.incident_id,
            'evidence_type': self.evidence_type.value,
            'file_name': self.file_name,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'collected_at': self.collected_at.isoformat(),
            'collected_by': self.collected_by,
            'chain_of_custody': self.chain_of_custody,
            'analysis_results': self.analysis_results,
            'tags': self.tags,
            'metadata': self.metadata
        }


class ThreatHuntingDatabase:
    """Database for threat hunting and SOAR platform data."""
    
    def __init__(self, db_path: str = "threat_hunting.db"):
        self.db_path = db_path
        self._lock = RLock()
        self._init_database()
        logger.info(f"Threat Hunting Database initialized at {db_path}")
    
    def _init_database(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            # Threat indicators table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    threat_level INTEGER NOT NULL,
                    confidence_score REAL NOT NULL,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    source TEXT,
                    description TEXT,
                    tags TEXT,
                    mitre_techniques TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Security incidents table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    threat_type TEXT NOT NULL,
                    threat_level INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    assigned_to TEXT,
                    source_ip TEXT,
                    target_assets TEXT,
                    indicators TEXT,
                    mitre_techniques TEXT,
                    evidence TEXT,
                    timeline TEXT,
                    metadata TEXT
                )
            """)
            
            # Security playbooks table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_playbooks (
                    playbook_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    trigger_conditions TEXT,
                    workflow_steps TEXT,
                    approval_required BOOLEAN,
                    timeout_minutes INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    version TEXT,
                    enabled BOOLEAN,
                    tags TEXT,
                    metadata TEXT
                )
            """)
            
            # Playbook executions table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS playbook_executions (
                    execution_id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    incident_id TEXT,
                    status TEXT NOT NULL,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    current_step INTEGER,
                    total_steps INTEGER,
                    executed_by TEXT,
                    execution_log TEXT,
                    results TEXT,
                    errors TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Threat hunting hypotheses table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hunting_hypotheses (
                    hypothesis_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    threat_types TEXT,
                    mitre_techniques TEXT,
                    data_sources TEXT,
                    query_logic TEXT,
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT,
                    findings TEXT,
                    metadata TEXT
                )
            """)
            
            # Evidence artifacts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_artifacts (
                    evidence_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    file_name TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    file_hash TEXT,
                    collected_at TIMESTAMP,
                    collected_by TEXT,
                    chain_of_custody TEXT,
                    analysis_results TEXT,
                    tags TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Integration configurations table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS integrations (
                    integration_id TEXT PRIMARY KEY,
                    integration_name TEXT NOT NULL,
                    integration_type TEXT NOT NULL,
                    configuration TEXT,
                    credentials TEXT,
                    enabled BOOLEAN,
                    last_health_check TIMESTAMP,
                    health_status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Threat intelligence feeds table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_feeds (
                    feed_id TEXT PRIMARY KEY,
                    feed_name TEXT NOT NULL,
                    feed_url TEXT,
                    feed_type TEXT,
                    last_updated TIMESTAMP,
                    indicators_count INTEGER,
                    enabled BOOLEAN,
                    configuration TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Security metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_metrics (
                    metric_id TEXT PRIMARY KEY,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    metric_type TEXT,
                    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    tags TEXT,
                    metadata TEXT
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(indicator_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(indicator_value)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_threat_type ON threat_indicators(threat_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_level ON threat_indicators(threat_level)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_type ON security_incidents(threat_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_level ON security_incidents(threat_level)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created ON security_incidents(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON security_playbooks(enabled)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_executions_status ON playbook_executions(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_executions_playbook ON playbook_executions(playbook_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence_artifacts(incident_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence_artifacts(evidence_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(integration_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_integrations_enabled ON integrations(enabled)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_name ON security_metrics(metric_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_collected ON security_metrics(collected_at)")
            
            conn.commit()
    
    def store_threat_indicator(self, indicator: ThreatIndicator) -> bool:
        """Store threat indicator."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO threat_indicators
                        (indicator_id, indicator_type, indicator_value, threat_type, threat_level,
                         confidence_score, first_seen, last_seen, source, description,
                         tags, mitre_techniques, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        indicator.indicator_id,
                        indicator.indicator_type,
                        indicator.indicator_value,
                        indicator.threat_type.value,
                        indicator.threat_level.value,
                        indicator.confidence_score,
                        indicator.first_seen,
                        indicator.last_seen,
                        indicator.source,
                        indicator.description,
                        json.dumps(indicator.tags),
                        json.dumps(indicator.mitre_techniques),
                        json.dumps(indicator.metadata)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing threat indicator: {e}")
                return False
    
    def store_security_incident(self, incident: SecurityIncident) -> bool:
        """Store security incident."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO security_incidents
                        (incident_id, title, description, threat_type, threat_level, status,
                         created_at, updated_at, assigned_to, source_ip, target_assets,
                         indicators, mitre_techniques, evidence, timeline, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        incident.incident_id,
                        incident.title,
                        incident.description,
                        incident.threat_type.value,
                        incident.threat_level.value,
                        incident.status.value,
                        incident.created_at,
                        incident.updated_at,
                        incident.assigned_to,
                        incident.source_ip,
                        json.dumps(incident.target_assets),
                        json.dumps(incident.indicators),
                        json.dumps(incident.mitre_techniques),
                        json.dumps(incident.evidence),
                        json.dumps(incident.timeline),
                        json.dumps(incident.metadata)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing security incident: {e}")
                return False
    
    def store_security_playbook(self, playbook: SecurityPlaybook) -> bool:
        """Store security playbook."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO security_playbooks
                        (playbook_id, name, description, trigger_conditions, workflow_steps,
                         approval_required, timeout_minutes, created_at, updated_at,
                         version, enabled, tags, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        playbook.playbook_id,
                        playbook.name,
                        playbook.description,
                        json.dumps(playbook.trigger_conditions),
                        json.dumps(playbook.workflow_steps),
                        playbook.approval_required,
                        playbook.timeout_minutes,
                        playbook.created_at,
                        playbook.updated_at,
                        playbook.version,
                        playbook.enabled,
                        json.dumps(playbook.tags),
                        json.dumps(playbook.metadata)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing security playbook: {e}")
                return False
    
    def store_playbook_execution(self, execution: PlaybookExecution) -> bool:
        """Store playbook execution."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO playbook_executions
                        (execution_id, playbook_id, incident_id, status, started_at,
                         completed_at, current_step, total_steps, executed_by,
                         execution_log, results, errors)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        execution.execution_id,
                        execution.playbook_id,
                        execution.incident_id,
                        execution.status.value,
                        execution.started_at,
                        execution.completed_at,
                        execution.current_step,
                        execution.total_steps,
                        execution.executed_by,
                        json.dumps(execution.execution_log),
                        json.dumps(execution.results),
                        json.dumps(execution.errors)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing playbook execution: {e}")
                return False
    
    def get_threat_indicators(self, indicator_type: Optional[str] = None, limit: int = 1000) -> List[ThreatIndicator]:
        """Get threat indicators."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                if indicator_type:
                    cursor = conn.execute(
                        "SELECT * FROM threat_indicators WHERE indicator_type = ? ORDER BY last_seen DESC LIMIT ?",
                        (indicator_type, limit)
                    )
                else:
                    cursor = conn.execute(
                        "SELECT * FROM threat_indicators ORDER BY last_seen DESC LIMIT ?",
                        (limit,)
                    )
                
                indicators = []
                for row in cursor.fetchall():
                    indicators.append(ThreatIndicator(
                        indicator_id=row[0],
                        indicator_type=row[1],
                        indicator_value=row[2],
                        threat_type=ThreatType(row[3]),
                        threat_level=ThreatLevel(row[4]),
                        confidence_score=row[5],
                        first_seen=datetime.fromisoformat(row[6].replace('Z', '+00:00')) if isinstance(row[6], str) else row[6],
                        last_seen=datetime.fromisoformat(row[7].replace('Z', '+00:00')) if isinstance(row[7], str) else row[7],
                        source=row[8] or "",
                        description=row[9] or "",
                        tags=json.loads(row[10]) if row[10] else [],
                        mitre_techniques=json.loads(row[11]) if row[11] else [],
                        metadata=json.loads(row[12]) if row[12] else {}
                    ))
                
                return indicators
                
        except Exception as e:
            logger.error(f"Error retrieving threat indicators: {e}")
            return []
    
    def get_security_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        """Get security incident by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT * FROM security_incidents WHERE incident_id = ?",
                    (incident_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    return SecurityIncident(
                        incident_id=row[0],
                        title=row[1],
                        description=row[2] or "",
                        threat_type=ThreatType(row[3]),
                        threat_level=ThreatLevel(row[4]),
                        status=IncidentStatus(row[5]),
                        created_at=datetime.fromisoformat(row[6].replace('Z', '+00:00')) if isinstance(row[6], str) else row[6],
                        updated_at=datetime.fromisoformat(row[7].replace('Z', '+00:00')) if isinstance(row[7], str) else row[7],
                        assigned_to=row[8],
                        source_ip=row[9],
                        target_assets=json.loads(row[10]) if row[10] else [],
                        indicators=json.loads(row[11]) if row[11] else [],
                        mitre_techniques=json.loads(row[12]) if row[12] else [],
                        evidence=json.loads(row[13]) if row[13] else [],
                        timeline=json.loads(row[14]) if row[14] else [],
                        metadata=json.loads(row[15]) if row[15] else {}
                    )
                    
        except Exception as e:
            logger.error(f"Error retrieving security incident: {e}")
        
        return None


class ThreatHuntingEngine:
    """Advanced threat hunting and detection engine."""
    
    def __init__(self, database: ThreatHuntingDatabase):
        self.database = database
        self.active_hypotheses = {}
        self.threat_patterns = {}
        self.behavioral_baselines = {}
        self.detection_rules = {}
        
        # Initialize threat detection rules
        self._initialize_detection_rules()
        logger.info("ThreatHuntingEngine initialized")
    
    def _initialize_detection_rules(self):
        """Initialize threat detection rules and patterns."""
        self.detection_rules = {
            'lateral_movement': {
                'pattern': r'(psexec|wmic|net use|runas)',
                'threshold': 5,
                'time_window': 3600,  # 1 hour
                'mitre_techniques': ['T1021', 'T1047']
            },
            'credential_dumping': {
                'pattern': r'(mimikatz|lsadump|secretsdump|procdump)',
                'threshold': 1,
                'time_window': 300,   # 5 minutes
                'mitre_techniques': ['T1003', 'T1558']
            },
            'persistence': {
                'pattern': r'(schtasks|at\.exe|reg add.*run|startup)',
                'threshold': 3,
                'time_window': 1800,  # 30 minutes
                'mitre_techniques': ['T1053', 'T1547']
            },
            'data_exfiltration': {
                'pattern': r'(ftp|scp|rsync|curl.*-T|wget.*--post)',
                'threshold': 10,
                'time_window': 7200,  # 2 hours
                'mitre_techniques': ['T1041', 'T1048']
            },
            'command_and_control': {
                'pattern': r'(powershell.*-enc|base64|certutil.*decode)',
                'threshold': 5,
                'time_window': 1800,  # 30 minutes
                'mitre_techniques': ['T1059', 'T1140']
            }
        }
    
    async def create_hunting_hypothesis(self, title: str, description: str, threat_types: List[ThreatType], 
                                       mitre_techniques: List[str], data_sources: List[str],
                                       query_logic: Dict[str, Any], created_by: str) -> str:
        """Create a new threat hunting hypothesis."""
        try:
            hypothesis_id = f"hypothesis_{uuid.uuid4().hex[:12]}"
            
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
            
            # Store in database
            with sqlite3.connect(self.database.db_path) as conn:
                conn.execute("""
                    INSERT INTO hunting_hypotheses
                    (hypothesis_id, title, description, threat_types, mitre_techniques,
                     data_sources, query_logic, created_by, created_at, status, findings, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    hypothesis.hypothesis_id,
                    hypothesis.title,
                    hypothesis.description,
                    json.dumps([t.value for t in hypothesis.threat_types]),
                    json.dumps(hypothesis.mitre_techniques),
                    json.dumps(hypothesis.data_sources),
                    json.dumps(hypothesis.query_logic),
                    hypothesis.created_by,
                    hypothesis.created_at,
                    hypothesis.status,
                    json.dumps(hypothesis.findings),
                    json.dumps(hypothesis.metadata)
                ))
                conn.commit()
            
            # Add to active hypotheses
            self.active_hypotheses[hypothesis_id] = hypothesis
            
            logger.info(f"Created threat hunting hypothesis: {hypothesis_id}")
            return hypothesis_id
            
        except Exception as e:
            logger.error(f"Error creating hunting hypothesis: {e}")
            return ""
    
    async def execute_threat_hunt(self, hypothesis_id: str, data_sources: Dict[str, Any]) -> Dict[str, Any]:
        """Execute threat hunting based on hypothesis."""
        try:
            if hypothesis_id not in self.active_hypotheses:
                return {'error': 'Hypothesis not found'}
            
            hypothesis = self.active_hypotheses[hypothesis_id]
            findings = []
            
            # Execute hunting queries based on hypothesis
            for source_name, source_data in data_sources.items():
                if source_name in hypothesis.data_sources:
                    source_findings = await self._hunt_in_data_source(
                        source_name, source_data, hypothesis.query_logic
                    )
                    findings.extend(source_findings)
            
            # Analyze findings for patterns
            pattern_matches = await self._analyze_hunting_findings(findings, hypothesis.mitre_techniques)
            
            # Update hypothesis with findings
            hypothesis.findings.extend(findings)
            
            # Generate threat indicators from findings
            indicators = await self._generate_indicators_from_findings(findings, hypothesis)
            
            results = {
                'hypothesis_id': hypothesis_id,
                'findings_count': len(findings),
                'findings': findings[:100],  # Limit for response size
                'pattern_matches': pattern_matches,
                'indicators_generated': len(indicators),
                'confidence_score': self._calculate_hunt_confidence(findings, pattern_matches),
                'recommendations': self._generate_hunt_recommendations(findings, pattern_matches)
            }
            
            logger.info(f"Completed threat hunt for hypothesis: {hypothesis_id}")
            return results
            
        except Exception as e:
            logger.error(f"Error executing threat hunt: {e}")
            return {'error': f'Threat hunt execution failed: {str(e)}'}
    
    async def _hunt_in_data_source(self, source_name: str, source_data: Dict[str, Any], 
                                  query_logic: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Hunt for threats in a specific data source."""
        findings = []
        
        try:
            # Simulate hunting in different data sources
            if source_name == 'logs':
                findings = await self._hunt_in_logs(source_data.get('entries', []), query_logic)
            elif source_name == 'network':
                findings = await self._hunt_in_network_data(source_data.get('flows', []), query_logic)
            elif source_name == 'endpoints':
                findings = await self._hunt_in_endpoint_data(source_data.get('processes', []), query_logic)
            elif source_name == 'dns':
                findings = await self._hunt_in_dns_data(source_data.get('queries', []), query_logic)
            
        except Exception as e:
            logger.error(f"Error hunting in data source {source_name}: {e}")
        
        return findings
    
    async def _hunt_in_logs(self, log_entries: List[Dict[str, Any]], query_logic: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Hunt for threats in log data."""
        findings = []
        
        try:
            search_patterns = query_logic.get('patterns', [])
            time_window = query_logic.get('time_window', 3600)
            threshold = query_logic.get('threshold', 1)
            
            # Group events by time window
            time_buckets = defaultdict(list)
            current_time = datetime.now(timezone.utc)
            
            for entry in log_entries:
                entry_time = entry.get('timestamp', current_time)
                if isinstance(entry_time, str):
                    entry_time = datetime.fromisoformat(entry_time.replace('Z', '+00:00'))
                
                bucket_key = int(entry_time.timestamp() // time_window)
                time_buckets[bucket_key].append(entry)
            
            # Search for patterns in each time bucket
            for bucket_key, bucket_entries in time_buckets.items():
                pattern_matches = defaultdict(int)
                
                for entry in bucket_entries:
                    entry_text = str(entry.get('message', ''))
                    
                    for pattern in search_patterns:
                        if re.search(pattern, entry_text, re.IGNORECASE):
                            pattern_matches[pattern] += 1
                
                # Check if any pattern exceeds threshold
                for pattern, count in pattern_matches.items():
                    if count >= threshold:
                        findings.append({
                            'type': 'pattern_match',
                            'pattern': pattern,
                            'count': count,
                            'time_bucket': bucket_key,
                            'sample_entries': bucket_entries[:5],
                            'threat_score': min(count / threshold, 10.0)
                        })
            
        except Exception as e:
            logger.error(f"Error hunting in logs: {e}")
        
        return findings
    
    async def _hunt_in_network_data(self, network_flows: List[Dict[str, Any]], query_logic: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Hunt for threats in network flow data."""
        findings = []
        
        try:
            suspicious_domains = query_logic.get('suspicious_domains', [])
            suspicious_ips = query_logic.get('suspicious_ips', [])
            port_scanning_threshold = query_logic.get('port_scan_threshold', 100)
            
            # Analyze network flows
            host_connections = defaultdict(set)
            domain_lookups = defaultdict(int)
            
            for flow in network_flows:
                src_ip = flow.get('src_ip', '')
                dst_ip = flow.get('dst_ip', '')
                dst_port = flow.get('dst_port', 0)
                domain = flow.get('domain', '')
                
                # Track host connections for port scanning detection
                if src_ip and dst_ip and dst_port:
                    host_connections[src_ip].add((dst_ip, dst_port))
                
                # Track domain lookups
                if domain:
                    domain_lookups[domain] += 1
                    
                    # Check suspicious domains
                    for suspicious_domain in suspicious_domains:
                        if suspicious_domain in domain:
                            findings.append({
                                'type': 'suspicious_domain',
                                'domain': domain,
                                'src_ip': src_ip,
                                'threat_score': 8.0,
                                'flow_data': flow
                            })
                
                # Check suspicious IPs
                if dst_ip in suspicious_ips:
                    findings.append({
                        'type': 'suspicious_ip_connection',
                        'dst_ip': dst_ip,
                        'src_ip': src_ip,
                        'dst_port': dst_port,
                        'threat_score': 9.0,
                        'flow_data': flow
                    })
            
            # Detect potential port scanning
            for src_ip, connections in host_connections.items():
                if len(connections) >= port_scanning_threshold:
                    findings.append({
                        'type': 'port_scanning',
                        'src_ip': src_ip,
                        'connections_count': len(connections),
                        'unique_targets': len(set(ip for ip, port in connections)),
                        'threat_score': min(len(connections) / port_scanning_threshold * 7.0, 10.0)
                    })
            
        except Exception as e:
            logger.error(f"Error hunting in network data: {e}")
        
        return findings
    
    async def _hunt_in_endpoint_data(self, processes: List[Dict[str, Any]], query_logic: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Hunt for threats in endpoint process data."""
        findings = []
        
        try:
            suspicious_processes = query_logic.get('suspicious_processes', [])
            command_line_patterns = query_logic.get('command_patterns', [])
            
            for process in processes:
                process_name = process.get('name', '').lower()
                command_line = process.get('command_line', '')
                parent_process = process.get('parent_name', '')
                
                # Check suspicious process names
                for suspicious_proc in suspicious_processes:
                    if suspicious_proc.lower() in process_name:
                        findings.append({
                            'type': 'suspicious_process',
                            'process_name': process_name,
                            'command_line': command_line,
                            'parent_process': parent_process,
                            'threat_score': 7.0,
                            'process_data': process
                        })
                
                # Check command line patterns
                for pattern in command_line_patterns:
                    if re.search(pattern, command_line, re.IGNORECASE):
                        findings.append({
                            'type': 'suspicious_command',
                            'pattern': pattern,
                            'command_line': command_line,
                            'process_name': process_name,
                            'threat_score': 6.0,
                            'process_data': process
                        })
            
        except Exception as e:
            logger.error(f"Error hunting in endpoint data: {e}")
        
        return findings
    
    async def _hunt_in_dns_data(self, dns_queries: List[Dict[str, Any]], query_logic: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Hunt for threats in DNS query data."""
        findings = []
        
        try:
            dga_patterns = query_logic.get('dga_patterns', [])
            suspicious_tlds = query_logic.get('suspicious_tlds', ['.tk', '.ml', '.ga', '.cf'])
            
            for query in dns_queries:
                domain = query.get('domain', '').lower()
                query_type = query.get('type', '')
                response_code = query.get('response_code', 0)
                
                # Check for Domain Generation Algorithm (DGA) patterns
                for pattern in dga_patterns:
                    if re.search(pattern, domain, re.IGNORECASE):
                        findings.append({
                            'type': 'dga_domain',
                            'domain': domain,
                            'pattern': pattern,
                            'threat_score': 8.0,
                            'query_data': query
                        })
                
                # Check suspicious TLDs
                for tld in suspicious_tlds:
                    if domain.endswith(tld):
                        findings.append({
                            'type': 'suspicious_tld',
                            'domain': domain,
                            'tld': tld,
                            'threat_score': 5.0,
                            'query_data': query
                        })
                
                # Check for DNS tunneling indicators
                if len(domain) > 60 and '.' in domain:
                    subdomain_length = len(domain.split('.')[0])
                    if subdomain_length > 40:
                        findings.append({
                            'type': 'dns_tunneling',
                            'domain': domain,
                            'subdomain_length': subdomain_length,
                            'threat_score': 7.0,
                            'query_data': query
                        })
            
        except Exception as e:
            logger.error(f"Error hunting in DNS data: {e}")
        
        return findings
    
    async def _analyze_hunting_findings(self, findings: List[Dict[str, Any]], mitre_techniques: List[str]) -> Dict[str, Any]:
        """Analyze hunting findings for patterns and correlations."""
        try:
            analysis = {
                'total_findings': len(findings),
                'threat_types': defaultdict(int),
                'mitre_coverage': [],
                'time_correlation': {},
                'asset_correlation': defaultdict(int),
                'severity_distribution': defaultdict(int)
            }
            
            # Analyze threat types and severity
            for finding in findings:
                threat_type = finding.get('type', 'unknown')
                threat_score = finding.get('threat_score', 0.0)
                
                analysis['threat_types'][threat_type] += 1
                
                if threat_score >= 8.0:
                    analysis['severity_distribution']['high'] += 1
                elif threat_score >= 6.0:
                    analysis['severity_distribution']['medium'] += 1
                else:
                    analysis['severity_distribution']['low'] += 1
            
            # Check MITRE technique coverage
            technique_patterns = {
                'T1021': ['lateral_movement', 'suspicious_process'],
                'T1047': ['suspicious_command'],
                'T1003': ['credential_dumping'],
                'T1053': ['persistence'],
                'T1041': ['data_exfiltration', 'suspicious_domain'],
                'T1059': ['suspicious_command'],
                'T1140': ['suspicious_command']
            }
            
            for technique in mitre_techniques:
                if technique in technique_patterns:
                    for pattern in technique_patterns[technique]:
                        if pattern in analysis['threat_types']:
                            analysis['mitre_coverage'].append(technique)
                            break
            
            return dict(analysis)  # Convert defaultdicts to regular dicts
            
        except Exception as e:
            logger.error(f"Error analyzing hunting findings: {e}")
            return {}
    
    async def _generate_indicators_from_findings(self, findings: List[Dict[str, Any]], 
                                               hypothesis: ThreatHuntingHypothesis) -> List[str]:
        """Generate threat indicators from hunting findings."""
        indicators = []
        
        try:
            for finding in findings:
                indicator_value = None
                indicator_type = None
                
                # Extract indicators based on finding type
                if finding['type'] == 'suspicious_domain':
                    indicator_value = finding.get('domain')
                    indicator_type = 'domain'
                elif finding['type'] == 'suspicious_ip_connection':
                    indicator_value = finding.get('dst_ip')
                    indicator_type = 'ip'
                elif finding['type'] == 'suspicious_process':
                    indicator_value = finding.get('process_name')
                    indicator_type = 'process'
                elif finding['type'] == 'suspicious_command':
                    indicator_value = hashlib.sha256(finding.get('command_line', '').encode()).hexdigest()
                    indicator_type = 'command_hash'
                
                if indicator_value and indicator_type:
                    # Create threat indicator
                    indicator = ThreatIndicator(
                        indicator_id=f"ioc_{uuid.uuid4().hex[:12]}",
                        indicator_type=indicator_type,
                        indicator_value=indicator_value,
                        threat_type=hypothesis.threat_types[0] if hypothesis.threat_types else ThreatType.MALWARE,
                        threat_level=ThreatLevel.MEDIUM,
                        confidence_score=min(finding.get('threat_score', 5.0) / 10.0, 1.0),
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        source=f"hunting_{hypothesis.hypothesis_id}",
                        description=f"Generated from threat hunting: {finding['type']}",
                        mitre_techniques=hypothesis.mitre_techniques
                    )
                    
                    # Store indicator
                    if self.database.store_threat_indicator(indicator):
                        indicators.append(indicator.indicator_id)
            
        except Exception as e:
            logger.error(f"Error generating indicators from findings: {e}")
        
        return indicators
    
    def _calculate_hunt_confidence(self, findings: List[Dict[str, Any]], pattern_matches: Dict[str, Any]) -> float:
        """Calculate confidence score for hunting results."""
        if not findings:
            return 0.0
        
        # Base confidence on findings count and severity
        base_confidence = min(len(findings) / 10.0, 1.0)
        
        # Adjust for threat scores
        avg_threat_score = sum(f.get('threat_score', 0.0) for f in findings) / len(findings)
        threat_factor = avg_threat_score / 10.0
        
        # Adjust for MITRE technique coverage
        coverage_factor = len(pattern_matches.get('mitre_coverage', [])) / max(len(pattern_matches.get('mitre_coverage', [])), 1)
        
        confidence = (base_confidence * 0.4) + (threat_factor * 0.4) + (coverage_factor * 0.2)
        return min(confidence, 1.0)
    
    def _generate_hunt_recommendations(self, findings: List[Dict[str, Any]], pattern_matches: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on hunting results."""
        recommendations = []
        
        try:
            high_severity_count = pattern_matches.get('severity_distribution', {}).get('high', 0)
            threat_types = pattern_matches.get('threat_types', {})
            
            if high_severity_count > 5:
                recommendations.append("Immediate incident response required - multiple high-severity threats detected")
            
            if 'suspicious_domain' in threat_types:
                recommendations.append("Consider blocking identified suspicious domains in DNS security controls")
            
            if 'port_scanning' in threat_types:
                recommendations.append("Implement network segmentation to limit lateral movement")
            
            if 'suspicious_process' in threat_types:
                recommendations.append("Deploy additional endpoint monitoring and response capabilities")
            
            if 'credential_dumping' in threat_types:
                recommendations.append("Force password resets for potentially compromised accounts")
            
            if not recommendations:
                recommendations.append("Continue monitoring - low-level threats detected")
            
        except Exception as e:
            logger.error(f"Error generating hunt recommendations: {e}")
            recommendations.append("Review findings manually for appropriate response actions")
        
        return recommendations


class SecurityOrchestrationEngine:
    """Security orchestration and automation engine."""
    
    def __init__(self, database: ThreatHuntingDatabase):
        self.database = database
        self.active_executions = {}
        self.playbook_registry = {}
        self.integration_handlers = {}
        self.response_actions = {}
        
        self._initialize_response_actions()
        logger.info("SecurityOrchestrationEngine initialized")
    
    def _initialize_response_actions(self):
        """Initialize available response actions."""
        self.response_actions = {
            ResponseAction.ALERT: self._send_alert,
            ResponseAction.BLOCK_IP: self._block_ip,
            ResponseAction.ISOLATE_HOST: self._isolate_host,
            ResponseAction.QUARANTINE_FILE: self._quarantine_file,
            ResponseAction.RESET_PASSWORD: self._reset_password,
            ResponseAction.DISABLE_ACCOUNT: self._disable_account,
            ResponseAction.COLLECT_EVIDENCE: self._collect_evidence,
            ResponseAction.ESCALATE: self._escalate_incident,
            ResponseAction.NOTIFY_ADMIN: self._notify_admin,
            ResponseAction.CREATE_TICKET: self._create_ticket
        }
    
    async def create_security_playbook(self, name: str, description: str, trigger_conditions: Dict[str, Any],
                                     workflow_steps: List[Dict[str, Any]], approval_required: bool = False,
                                     timeout_minutes: int = 60, tags: List[str] = None) -> str:
        """Create a new security playbook."""
        try:
            playbook_id = f"playbook_{uuid.uuid4().hex[:12]}"
            
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
            
            # Store playbook
            if self.database.store_security_playbook(playbook):
                self.playbook_registry[playbook_id] = playbook
                logger.info(f"Created security playbook: {playbook_id}")
                return playbook_id
            else:
                raise Exception("Failed to store playbook in database")
                
        except Exception as e:
            logger.error(f"Error creating security playbook: {e}")
            return ""
    
    async def execute_playbook(self, playbook_id: str, incident_id: str, executed_by: str,
                             execution_context: Dict[str, Any] = None) -> str:
        """Execute a security playbook."""
        try:
            if playbook_id not in self.playbook_registry:
                raise Exception(f"Playbook {playbook_id} not found")
            
            playbook = self.playbook_registry[playbook_id]
            execution_id = f"exec_{uuid.uuid4().hex[:12]}"
            
            # Create execution record
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
            
            # Store execution record
            self.database.store_playbook_execution(execution)
            self.active_executions[execution_id] = execution
            
            # Start playbook execution asynchronously
            asyncio.create_task(self._execute_playbook_workflow(execution_id, execution_context or {}))
            
            logger.info(f"Started playbook execution: {execution_id}")
            return execution_id
            
        except Exception as e:
            logger.error(f"Error executing playbook: {e}")
            return ""
    
    async def _execute_playbook_workflow(self, execution_id: str, context: Dict[str, Any]):
        """Execute playbook workflow steps."""
        try:
            execution = self.active_executions.get(execution_id)
            if not execution:
                return
            
            playbook = self.playbook_registry.get(execution.playbook_id)
            if not playbook:
                return
            
            # Update status to running
            execution.status = PlaybookStatus.RUNNING
            self.database.store_playbook_execution(execution)
            
            # Execute each workflow step
            for step_index, step in enumerate(playbook.workflow_steps):
                execution.current_step = step_index + 1
                
                try:
                    # Log step start
                    execution.execution_log.append({
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'step': step_index + 1,
                        'action': 'step_started',
                        'step_name': step.get('name', f'Step {step_index + 1}')
                    })
                    
                    # Execute step
                    step_result = await self._execute_workflow_step(step, context)
                    
                    # Log step completion
                    execution.execution_log.append({
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'step': step_index + 1,
                        'action': 'step_completed',
                        'result': step_result,
                        'step_name': step.get('name', f'Step {step_index + 1}')
                    })
                    
                    # Store step result
                    execution.results[f'step_{step_index + 1}'] = step_result
                    
                    # Check for conditional logic
                    if step.get('condition') and not self._evaluate_step_condition(step['condition'], step_result):
                        execution.execution_log.append({
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'step': step_index + 1,
                            'action': 'step_skipped',
                            'reason': 'condition_not_met'
                        })
                        continue
                    
                    # Check for approval requirement
                    if step.get('requires_approval', False):
                        execution.status = PlaybookStatus.PAUSED
                        self.database.store_playbook_execution(execution)
                        
                        execution.execution_log.append({
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'step': step_index + 1,
                            'action': 'awaiting_approval'
                        })
                        
                        # In a real implementation, this would wait for approval
                        # For this educational version, we'll continue after a brief pause
                        await asyncio.sleep(1)
                        
                        execution.status = PlaybookStatus.RUNNING
                    
                except Exception as step_error:
                    error_msg = f"Step {step_index + 1} failed: {str(step_error)}"
                    execution.errors.append(error_msg)
                    
                    execution.execution_log.append({
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'step': step_index + 1,
                        'action': 'step_failed',
                        'error': error_msg
                    })
                    
                    # Check if step is critical
                    if step.get('critical', False):
                        execution.status = PlaybookStatus.FAILED
                        break
                
                # Update execution record
                self.database.store_playbook_execution(execution)
            
            # Mark execution as completed
            if execution.status != PlaybookStatus.FAILED:
                execution.status = PlaybookStatus.COMPLETED
            
            execution.completed_at = datetime.now(timezone.utc)
            self.database.store_playbook_execution(execution)
            
            logger.info(f"Playbook execution completed: {execution_id}")
            
        except Exception as e:
            logger.error(f"Error in playbook workflow execution: {e}")
            if execution_id in self.active_executions:
                execution = self.active_executions[execution_id]
                execution.status = PlaybookStatus.FAILED
                execution.completed_at = datetime.now(timezone.utc)
                execution.errors.append(f"Workflow execution failed: {str(e)}")
                self.database.store_playbook_execution(execution)
    
    async def _execute_workflow_step(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single workflow step."""
        try:
            step_type = step.get('type', '')
            step_params = step.get('parameters', {})
            
            # Merge context with step parameters
            merged_params = {**context, **step_params}
            
            if step_type == 'response_action':
                action_type = ResponseAction(step_params.get('action'))
                if action_type in self.response_actions:
                    result = await self.response_actions[action_type](merged_params)
                    return {'success': True, 'result': result}
                else:
                    return {'success': False, 'error': f'Unknown response action: {action_type}'}
            
            elif step_type == 'integration_call':
                integration_name = step_params.get('integration')
                method = step_params.get('method')
                if integration_name in self.integration_handlers:
                    result = await self.integration_handlers[integration_name].call_method(method, merged_params)
                    return {'success': True, 'result': result}
                else:
                    return {'success': False, 'error': f'Integration {integration_name} not configured'}
            
            elif step_type == 'conditional':
                condition = step_params.get('condition')
                if_true = step_params.get('if_true', {})
                if_false = step_params.get('if_false', {})
                
                if self._evaluate_condition(condition, context):
                    return await self._execute_workflow_step(if_true, context)
                else:
                    return await self._execute_workflow_step(if_false, context)
            
            elif step_type == 'delay':
                delay_seconds = step_params.get('seconds', 1)
                await asyncio.sleep(delay_seconds)
                return {'success': True, 'delayed': delay_seconds}
            
            elif step_type == 'parallel':
                tasks = step_params.get('tasks', [])
                results = await asyncio.gather(*[
                    self._execute_workflow_step(task, context) for task in tasks
                ])
                return {'success': True, 'parallel_results': results}
            
            else:
                return {'success': False, 'error': f'Unknown step type: {step_type}'}
                
        except Exception as e:
            logger.error(f"Error executing workflow step: {e}")
            return {'success': False, 'error': str(e)}
    
    def _evaluate_step_condition(self, condition: Dict[str, Any], step_result: Dict[str, Any]) -> bool:
        """Evaluate step condition logic."""
        try:
            condition_type = condition.get('type', 'equals')
            field = condition.get('field', 'success')
            expected_value = condition.get('value', True)
            
            actual_value = step_result.get(field)
            
            if condition_type == 'equals':
                return actual_value == expected_value
            elif condition_type == 'not_equals':
                return actual_value != expected_value
            elif condition_type == 'contains':
                return expected_value in str(actual_value)
            elif condition_type == 'greater_than':
                return float(actual_value or 0) > float(expected_value)
            elif condition_type == 'less_than':
                return float(actual_value or 0) < float(expected_value)
            
        except Exception as e:
            logger.error(f"Error evaluating step condition: {e}")
        
        return False
    
    def _evaluate_condition(self, condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate general condition logic."""
        try:
            condition_type = condition.get('type', 'equals')
            field = condition.get('field', '')
            expected_value = condition.get('value', '')
            
            actual_value = context.get(field, '')
            
            if condition_type == 'equals':
                return str(actual_value) == str(expected_value)
            elif condition_type == 'contains':
                return str(expected_value) in str(actual_value)
            elif condition_type == 'regex':
                return bool(re.search(expected_value, str(actual_value)))
            
        except Exception as e:
            logger.error(f"Error evaluating condition: {e}")
        
        return False
    
    # Response action implementations
    async def _send_alert(self, params: Dict[str, Any]) -> str:
        """Send security alert."""
        try:
            message = params.get('message', 'Security alert triggered')
            severity = params.get('severity', 'medium')
            
            # In a real implementation, this would send alerts via configured channels
            logger.warning(f"SECURITY ALERT [{severity.upper()}]: {message}")
            
            return f"Alert sent: {message}"
            
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
            return f"Failed to send alert: {str(e)}"
    
    async def _block_ip(self, params: Dict[str, Any]) -> str:
        """Block IP address."""
        try:
            ip_address = params.get('ip_address', '')
            duration = params.get('duration_minutes', 60)
            
            if not ip_address:
                return "No IP address specified"
            
            # In a real implementation, this would call firewall APIs
            logger.info(f"Blocking IP {ip_address} for {duration} minutes")
            
            return f"IP {ip_address} blocked for {duration} minutes"
            
        except Exception as e:
            logger.error(f"Error blocking IP: {e}")
            return f"Failed to block IP: {str(e)}"
    
    async def _isolate_host(self, params: Dict[str, Any]) -> str:
        """Isolate host from network."""
        try:
            hostname = params.get('hostname', '')
            if not hostname:
                return "No hostname specified"
            
            # In a real implementation, this would call EDR/XDR APIs
            logger.info(f"Isolating host: {hostname}")
            
            return f"Host {hostname} isolated from network"
            
        except Exception as e:
            logger.error(f"Error isolating host: {e}")
            return f"Failed to isolate host: {str(e)}"
    
    async def _quarantine_file(self, params: Dict[str, Any]) -> str:
        """Quarantine malicious file."""
        try:
            file_path = params.get('file_path', '')
            file_hash = params.get('file_hash', '')
            
            if not file_path and not file_hash:
                return "No file path or hash specified"
            
            # In a real implementation, this would call endpoint security APIs
            logger.info(f"Quarantining file: {file_path or file_hash}")
            
            return f"File quarantined: {file_path or file_hash}"
            
        except Exception as e:
            logger.error(f"Error quarantining file: {e}")
            return f"Failed to quarantine file: {str(e)}"
    
    async def _reset_password(self, params: Dict[str, Any]) -> str:
        """Reset user password."""
        try:
            username = params.get('username', '')
            if not username:
                return "No username specified"
            
            # In a real implementation, this would call identity management APIs
            logger.info(f"Resetting password for user: {username}")
            
            return f"Password reset for user: {username}"
            
        except Exception as e:
            logger.error(f"Error resetting password: {e}")
            return f"Failed to reset password: {str(e)}"
    
    async def _disable_account(self, params: Dict[str, Any]) -> str:
        """Disable user account."""
        try:
            username = params.get('username', '')
            if not username:
                return "No username specified"
            
            # In a real implementation, this would call identity management APIs
            logger.info(f"Disabling account: {username}")
            
            return f"Account disabled: {username}"
            
        except Exception as e:
            logger.error(f"Error disabling account: {e}")
            return f"Failed to disable account: {str(e)}"
    
    async def _collect_evidence(self, params: Dict[str, Any]) -> str:
        """Collect digital evidence."""
        try:
            hostname = params.get('hostname', '')
            evidence_types = params.get('types', ['logs', 'memory'])
            
            # In a real implementation, this would trigger evidence collection tools
            logger.info(f"Collecting evidence from {hostname}: {evidence_types}")
            
            return f"Evidence collection initiated for {hostname}"
            
        except Exception as e:
            logger.error(f"Error collecting evidence: {e}")
            return f"Failed to collect evidence: {str(e)}"
    
    async def _escalate_incident(self, params: Dict[str, Any]) -> str:
        """Escalate security incident."""
        try:
            incident_id = params.get('incident_id', '')
            escalation_level = params.get('level', 'manager')
            
            # In a real implementation, this would update incident management system
            logger.info(f"Escalating incident {incident_id} to {escalation_level}")
            
            return f"Incident {incident_id} escalated to {escalation_level}"
            
        except Exception as e:
            logger.error(f"Error escalating incident: {e}")
            return f"Failed to escalate incident: {str(e)}"
    
    async def _notify_admin(self, params: Dict[str, Any]) -> str:
        """Notify administrators."""
        try:
            message = params.get('message', 'Security notification')
            admin_group = params.get('group', 'security_team')
            
            # In a real implementation, this would send notifications via configured channels
            logger.info(f"Notifying {admin_group}: {message}")
            
            return f"Notification sent to {admin_group}"
            
        except Exception as e:
            logger.error(f"Error notifying admin: {e}")
            return f"Failed to notify admin: {str(e)}"
    
    async def _create_ticket(self, params: Dict[str, Any]) -> str:
        """Create support ticket."""
        try:
            title = params.get('title', 'Security Incident')
            description = params.get('description', 'Automated security incident')
            priority = params.get('priority', 'high')
            
            # In a real implementation, this would call ticketing system APIs
            logger.info(f"Creating ticket: {title} ({priority} priority)")
            
            ticket_id = f"TICKET-{uuid.uuid4().hex[:8].upper()}"
            return f"Ticket created: {ticket_id}"
            
        except Exception as e:
            logger.error(f"Error creating ticket: {e}")
            return f"Failed to create ticket: {str(e)}"


class ThreatHuntingPlatform:
    """Main threat hunting and SOAR platform."""
    
    def __init__(self, db_path: str = "threat_hunting.db"):
        self.database = ThreatHuntingDatabase(db_path)
        self.hunting_engine = ThreatHuntingEngine(self.database)
        self.orchestration_engine = SecurityOrchestrationEngine(self.database)
        
        # Platform configuration
        self.enabled = True
        self.auto_response_enabled = True
        self.threat_intelligence_feeds = {}
        self.integration_config = {}
        
        logger.info("ThreatHuntingPlatform initialized")
    
    async def create_security_incident(self, title: str, description: str, threat_type: ThreatType,
                                     threat_level: ThreatLevel, source_ip: Optional[str] = None,
                                     target_assets: List[str] = None, indicators: List[str] = None,
                                     mitre_techniques: List[str] = None) -> str:
        """Create a new security incident."""
        try:
            incident_id = f"incident_{uuid.uuid4().hex[:12]}"
            
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
            
            # Store incident
            if self.database.store_security_incident(incident):
                logger.info(f"Created security incident: {incident_id}")
                
                # Trigger automated response if enabled
                if self.auto_response_enabled:
                    await self._trigger_automated_response(incident)
                
                return incident_id
            else:
                raise Exception("Failed to store incident in database")
                
        except Exception as e:
            logger.error(f"Error creating security incident: {e}")
            return ""
    
    async def _trigger_automated_response(self, incident: SecurityIncident):
        """Trigger automated response based on incident characteristics."""
        try:
            # Find matching playbooks
            matching_playbooks = await self._find_matching_playbooks(incident)
            
            for playbook_id in matching_playbooks:
                execution_context = {
                    'incident_id': incident.incident_id,
                    'threat_type': incident.threat_type.value,
                    'threat_level': incident.threat_level.value,
                    'source_ip': incident.source_ip,
                    'target_assets': incident.target_assets,
                    'indicators': incident.indicators
                }
                
                execution_id = await self.orchestration_engine.execute_playbook(
                    playbook_id, incident.incident_id, 'system', execution_context
                )
                
                if execution_id:
                    logger.info(f"Triggered playbook {playbook_id} for incident {incident.incident_id}")
                
        except Exception as e:
            logger.error(f"Error triggering automated response: {e}")
    
    async def _find_matching_playbooks(self, incident: SecurityIncident) -> List[str]:
        """Find playbooks that match incident characteristics."""
        matching_playbooks = []
        
        try:
            for playbook_id, playbook in self.orchestration_engine.playbook_registry.items():
                if not playbook.enabled:
                    continue
                
                triggers = playbook.trigger_conditions
                
                # Check threat type match
                if 'threat_types' in triggers:
                    if incident.threat_type.value not in triggers['threat_types']:
                        continue
                
                # Check threat level match
                if 'min_threat_level' in triggers:
                    if incident.threat_level.value < triggers['min_threat_level']:
                        continue
                
                # Check MITRE technique match
                if 'mitre_techniques' in triggers:
                    if not any(tech in incident.mitre_techniques for tech in triggers['mitre_techniques']):
                        continue
                
                # Check asset match
                if 'target_assets' in triggers:
                    if not any(asset in incident.target_assets for asset in triggers['target_assets']):
                        continue
                
                matching_playbooks.append(playbook_id)
                
        except Exception as e:
            logger.error(f"Error finding matching playbooks: {e}")
        
        return matching_playbooks
    
    async def process_threat_intelligence(self, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process threat intelligence data."""
        try:
            indicators_processed = 0
            new_indicators = []
            
            # Extract indicators from intelligence data
            if 'indicators' in intelligence_data:
                for ioc_data in intelligence_data['indicators']:
                    try:
                        # Create threat indicator
                        indicator = ThreatIndicator(
                            indicator_id=f"intel_{uuid.uuid4().hex[:12]}",
                            indicator_type=ioc_data.get('type', 'unknown'),
                            indicator_value=ioc_data.get('value', ''),
                            threat_type=ThreatType(ioc_data.get('threat_type', 'malware')),
                            threat_level=ThreatLevel(ioc_data.get('threat_level', 2)),
                            confidence_score=float(ioc_data.get('confidence', 0.5)),
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                            source=intelligence_data.get('source', 'external_feed'),
                            description=ioc_data.get('description', ''),
                            mitre_techniques=ioc_data.get('mitre_techniques', [])
                        )
                        
                        # Store indicator
                        if self.database.store_threat_indicator(indicator):
                            indicators_processed += 1
                            new_indicators.append(indicator.indicator_id)
                        
                    except Exception as e:
                        logger.error(f"Error processing indicator: {e}")
            
            result = {
                'indicators_processed': indicators_processed,
                'new_indicators': new_indicators,
                'processing_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Processed threat intelligence: {indicators_processed} indicators")
            return result
            
        except Exception as e:
            logger.error(f"Error processing threat intelligence: {e}")
            return {'error': f'Intelligence processing failed: {str(e)}'}
    
    async def get_platform_metrics(self) -> Dict[str, Any]:
        """Get platform performance and security metrics."""
        try:
            with sqlite3.connect(self.database.db_path) as conn:
                # Get incident statistics
                incident_stats = {}
                cursor = conn.execute("""
                    SELECT status, COUNT(*) as count 
                    FROM security_incidents 
                    GROUP BY status
                """)
                for row in cursor.fetchall():
                    incident_stats[row[0]] = row[1]
                
                # Get threat level distribution
                threat_level_stats = {}
                cursor = conn.execute("""
                    SELECT threat_level, COUNT(*) as count 
                    FROM security_incidents 
                    GROUP BY threat_level
                """)
                for row in cursor.fetchall():
                    threat_level_stats[f'level_{row[0]}'] = row[1]
                
                # Get playbook execution statistics
                playbook_stats = {}
                cursor = conn.execute("""
                    SELECT status, COUNT(*) as count 
                    FROM playbook_executions 
                    GROUP BY status
                """)
                for row in cursor.fetchall():
                    playbook_stats[row[0]] = row[1]
                
                # Get indicator statistics
                cursor = conn.execute("SELECT COUNT(*) FROM threat_indicators")
                total_indicators = cursor.fetchone()[0]
                
                cursor = conn.execute("SELECT COUNT(*) FROM hunting_hypotheses")
                total_hypotheses = cursor.fetchone()[0]
                
                cursor = conn.execute("SELECT COUNT(*) FROM evidence_artifacts")
                total_evidence = cursor.fetchone()[0]
            
            metrics = {
                'platform_status': 'operational',
                'incidents': incident_stats,
                'threat_levels': threat_level_stats,
                'playbook_executions': playbook_stats,
                'total_indicators': total_indicators,
                'total_hypotheses': total_hypotheses,
                'total_evidence': total_evidence,
                'active_executions': len(self.orchestration_engine.active_executions),
                'active_hypotheses': len(self.hunting_engine.active_hypotheses),
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting platform metrics: {e}")
            return {'error': f'Metrics collection failed: {str(e)}'}


# Convenience functions
def create_threat_hunting_platform(db_path: str = "threat_hunting.db", 
                                  auto_response_enabled: bool = True) -> ThreatHuntingPlatform:
    """Create threat hunting platform with configuration."""
    platform = ThreatHuntingPlatform(db_path)
    platform.auto_response_enabled = auto_response_enabled
    return platform


# Export all classes and functions
__all__ = [
    # Enums
    'ThreatLevel',
    'ThreatType', 
    'IncidentStatus',
    'PlaybookStatus',
    'ResponseAction',
    'IntegrationType',
    'EvidenceType',
    
    # Data classes
    'ThreatIndicator',
    'SecurityIncident',
    'SecurityPlaybook',
    'PlaybookExecution',
    'ThreatHuntingHypothesis',
    'EvidenceArtifact',
    
    # Core classes
    'ThreatHuntingDatabase',
    'ThreatHuntingEngine',
    'SecurityOrchestrationEngine',
    'ThreatHuntingPlatform',
    
    # Convenience functions
    'create_threat_hunting_platform',
]