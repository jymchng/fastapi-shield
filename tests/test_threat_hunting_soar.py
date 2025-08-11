"""Comprehensive test suite for Advanced Threat Hunting and Security Orchestration Platform."""

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

from src.fastapi_shield.threat_hunting_soar import (
    ThreatHuntingPlatform, ThreatHuntingDatabase, ThreatHuntingEngine,
    SecurityOrchestrationEngine, 
    ThreatLevel, ThreatType, IncidentStatus, PlaybookStatus, ResponseAction,
    IntegrationType, EvidenceType,
    ThreatIndicator, SecurityIncident, SecurityPlaybook, PlaybookExecution,
    ThreatHuntingHypothesis, EvidenceArtifact,
    create_threat_hunting_platform
)
from tests.mocks.mock_threat_hunting_soar import (
    MockThreatHuntingPlatform, MockThreatHuntingTestEnvironment,
    MockThreatHuntingDatabase, MockThreatHuntingEngine, MockSecurityOrchestrationEngine
)


class TestThreatHuntingDatabase:
    """Test threat hunting database functionality."""
    
    def test_database_initialization(self, tmp_path):
        """Test database initialization and schema creation."""
        db_path = tmp_path / "test_threat_hunting.db"
        db = ThreatHuntingDatabase(str(db_path))
        
        assert db.db_path == str(db_path)
        assert os.path.exists(str(db_path))
        
        # Test table creation
        import sqlite3
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            expected_tables = [
                'threat_indicators', 'security_incidents', 'security_playbooks',
                'playbook_executions', 'hunting_hypotheses', 'evidence_artifacts',
                'integrations', 'threat_intel_feeds', 'security_metrics'
            ]
            for table in expected_tables:
                assert table in tables
    
    def test_threat_indicator_storage_and_retrieval(self, tmp_path):
        """Test storing and retrieving threat indicators."""
        db_path = tmp_path / "test_indicators.db"
        db = ThreatHuntingDatabase(str(db_path))
        
        indicator = ThreatIndicator(
            indicator_id="ioc_001",
            indicator_type="domain",
            indicator_value="malicious.com",
            threat_type=ThreatType.COMMAND_AND_CONTROL,
            threat_level=ThreatLevel.HIGH,
            confidence_score=0.85,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            source="test_feed",
            description="Test malicious domain",
            tags=["c2", "malware"],
            mitre_techniques=["T1071"]
        )
        
        # Store indicator
        assert db.store_threat_indicator(indicator) == True
        
        # Retrieve indicators
        indicators = db.get_threat_indicators(indicator_type="domain")
        assert len(indicators) >= 1
        
        retrieved = indicators[0]
        assert retrieved.indicator_id == "ioc_001"
        assert retrieved.indicator_value == "malicious.com"
        assert retrieved.threat_type == ThreatType.COMMAND_AND_CONTROL
        assert retrieved.threat_level == ThreatLevel.HIGH
        assert retrieved.confidence_score == 0.85
        assert len(retrieved.tags) == 2
        assert len(retrieved.mitre_techniques) == 1
    
    def test_security_incident_storage_and_retrieval(self, tmp_path):
        """Test storing and retrieving security incidents."""
        db_path = tmp_path / "test_incidents.db"
        db = ThreatHuntingDatabase(str(db_path))
        
        incident = SecurityIncident(
            incident_id="inc_001",
            title="Test Malware Incident",
            description="Test incident for malware detection",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.CRITICAL,
            status=IncidentStatus.NEW,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            target_assets=["workstation-01", "server-01"],
            indicators=["ioc_001", "ioc_002"],
            mitre_techniques=["T1055", "T1486"]
        )
        
        # Store incident
        assert db.store_security_incident(incident) == True
        
        # Retrieve incident
        retrieved = db.get_security_incident("inc_001")
        assert retrieved is not None
        assert retrieved.incident_id == "inc_001"
        assert retrieved.title == "Test Malware Incident"
        assert retrieved.threat_type == ThreatType.MALWARE
        assert retrieved.threat_level == ThreatLevel.CRITICAL
        assert retrieved.status == IncidentStatus.NEW
        assert len(retrieved.target_assets) == 2
        assert len(retrieved.indicators) == 2
        assert len(retrieved.mitre_techniques) == 2
    
    def test_security_playbook_storage(self, tmp_path):
        """Test storing security playbooks."""
        db_path = tmp_path / "test_playbooks.db"
        db = ThreatHuntingDatabase(str(db_path))
        
        playbook = SecurityPlaybook(
            playbook_id="pb_001",
            name="Test Malware Response",
            description="Automated malware response playbook",
            trigger_conditions={"threat_types": ["malware"], "min_threat_level": 3},
            workflow_steps=[
                {"name": "Alert", "type": "response_action", "parameters": {"action": "alert"}},
                {"name": "Isolate", "type": "response_action", "parameters": {"action": "isolate_host"}}
            ],
            approval_required=False,
            timeout_minutes=30,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            tags=["malware", "automated"]
        )
        
        # Store playbook
        assert db.store_security_playbook(playbook) == True
    
    def test_playbook_execution_storage(self, tmp_path):
        """Test storing playbook executions."""
        db_path = tmp_path / "test_executions.db"
        db = ThreatHuntingDatabase(str(db_path))
        
        execution = PlaybookExecution(
            execution_id="exec_001",
            playbook_id="pb_001",
            incident_id="inc_001",
            status=PlaybookStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            current_step=2,
            total_steps=2,
            executed_by="analyst_smith",
            execution_log=[
                {"step": 1, "action": "step_completed", "result": {"success": True}},
                {"step": 2, "action": "step_completed", "result": {"success": True}}
            ],
            results={"step_1": {"success": True}, "step_2": {"success": True}}
        )
        
        # Store execution
        assert db.store_playbook_execution(execution) == True
    
    def test_nonexistent_incident_retrieval(self, tmp_path):
        """Test retrieving non-existent incidents."""
        db_path = tmp_path / "test_nonexistent.db"
        db = ThreatHuntingDatabase(str(db_path))
        
        # Test non-existent incident
        incident = db.get_security_incident("nonexistent_incident")
        assert incident is None
    
    def test_indicator_filtering_and_limits(self, tmp_path):
        """Test threat indicator filtering and limits."""
        db_path = tmp_path / "test_filtering.db"
        db = ThreatHuntingDatabase(str(db_path))
        
        # Create multiple indicators of different types
        for i in range(10):
            indicator = ThreatIndicator(
                indicator_id=f"ioc_{i:03d}",
                indicator_type="domain" if i % 2 == 0 else "ip",
                indicator_value=f"test{i}.com" if i % 2 == 0 else f"192.168.1.{i}",
                threat_type=ThreatType.MALWARE,
                threat_level=ThreatLevel.MEDIUM,
                confidence_score=0.7,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                source="test"
            )
            db.store_threat_indicator(indicator)
        
        # Test filtering by type
        domain_indicators = db.get_threat_indicators(indicator_type="domain")
        assert len(domain_indicators) == 5
        
        ip_indicators = db.get_threat_indicators(indicator_type="ip")
        assert len(ip_indicators) == 5
        
        # Test limit
        limited_indicators = db.get_threat_indicators(limit=3)
        assert len(limited_indicators) == 3


class TestThreatHuntingEngine:
    """Test threat hunting engine functionality."""
    
    @pytest.mark.asyncio
    async def test_create_hunting_hypothesis(self, tmp_path):
        """Test creating threat hunting hypotheses."""
        db_path = tmp_path / "test_hunting_engine.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = ThreatHuntingEngine(db)
        
        hypothesis_id = await engine.create_hunting_hypothesis(
            title="Test Credential Dumping Hunt",
            description="Hunt for credential dumping activities",
            threat_types=[ThreatType.INSIDER_THREAT, ThreatType.APT],
            mitre_techniques=["T1003", "T1558"],
            data_sources=["logs", "endpoints"],
            query_logic={
                "patterns": ["mimikatz", "lsadump", "secretsdump"],
                "time_window": 3600,
                "threshold": 1
            },
            created_by="analyst_test"
        )
        
        assert hypothesis_id != ""
        assert hypothesis_id.startswith("hypothesis_")
        assert hypothesis_id in engine.active_hypotheses
        
        hypothesis = engine.active_hypotheses[hypothesis_id]
        assert hypothesis.title == "Test Credential Dumping Hunt"
        assert len(hypothesis.threat_types) == 2
        assert len(hypothesis.mitre_techniques) == 2
        assert len(hypothesis.data_sources) == 2
        assert hypothesis.created_by == "analyst_test"
    
    @pytest.mark.asyncio
    async def test_execute_threat_hunt_with_findings(self, tmp_path):
        """Test executing threat hunt with mock findings."""
        db_path = tmp_path / "test_threat_hunt.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = ThreatHuntingEngine(db)
        
        # Create hypothesis
        hypothesis_id = await engine.create_hunting_hypothesis(
            title="Test Hunt",
            description="Test hunting execution",
            threat_types=[ThreatType.LATERAL_MOVEMENT],
            mitre_techniques=["T1021"],
            data_sources=["logs", "network"],
            query_logic={
                "patterns": ["psexec", "wmic"],
                "time_window": 3600,
                "threshold": 3
            },
            created_by="test_analyst"
        )
        
        # Mock data sources with suspicious activity
        mock_data_sources = {
            "logs": {
                "entries": [
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "message": "psexec.exe executed with remote target",
                        "source_host": "workstation-01"
                    },
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "message": "wmic process call create detected",
                        "source_host": "workstation-02"
                    },
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "message": "psexec lateral movement to server-01",
                        "source_host": "workstation-01"
                    },
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "message": "psexec connection established",
                        "source_host": "workstation-03"
                    }
                ]
            },
            "network": {
                "flows": [
                    {
                        "src_ip": "192.168.1.100",
                        "dst_ip": "192.168.1.101",
                        "dst_port": 445,
                        "protocol": "tcp"
                    }
                ]
            }
        }
        
        # Execute hunt
        hunt_results = await engine.execute_threat_hunt(hypothesis_id, mock_data_sources)
        
        assert "error" not in hunt_results
        assert hunt_results["hypothesis_id"] == hypothesis_id
        assert hunt_results["findings_count"] > 0
        assert len(hunt_results["findings"]) > 0
        assert "pattern_matches" in hunt_results
        assert "confidence_score" in hunt_results
        assert "recommendations" in hunt_results
        
        # Check that findings contain expected patterns
        findings = hunt_results["findings"]
        pattern_finding = next((f for f in findings if f.get("type") == "pattern_match"), None)
        assert pattern_finding is not None
        assert pattern_finding["count"] >= 3  # Should meet threshold
    
    @pytest.mark.asyncio
    async def test_execute_threat_hunt_no_findings(self, tmp_path):
        """Test executing threat hunt with no findings."""
        db_path = tmp_path / "test_no_findings.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = ThreatHuntingEngine(db)
        
        # Create hypothesis
        hypothesis_id = await engine.create_hunting_hypothesis(
            title="Test Hunt No Findings",
            description="Hunt that should find nothing",
            threat_types=[ThreatType.MALWARE],
            mitre_techniques=["T1055"],
            data_sources=["logs"],
            query_logic={
                "patterns": ["nonexistent_malware"],
                "time_window": 3600,
                "threshold": 1
            },
            created_by="test_analyst"
        )
        
        # Mock data sources with benign activity
        mock_data_sources = {
            "logs": {
                "entries": [
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "message": "normal system activity",
                        "source_host": "workstation-01"
                    }
                ]
            }
        }
        
        # Execute hunt
        hunt_results = await engine.execute_threat_hunt(hypothesis_id, mock_data_sources)
        
        assert "error" not in hunt_results
        assert hunt_results["findings_count"] == 0
        assert len(hunt_results["findings"]) == 0
        assert hunt_results["confidence_score"] == 0.0
    
    @pytest.mark.asyncio
    async def test_execute_threat_hunt_nonexistent_hypothesis(self, tmp_path):
        """Test executing hunt with nonexistent hypothesis."""
        db_path = tmp_path / "test_nonexistent_hypothesis.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = ThreatHuntingEngine(db)
        
        # Try to execute hunt with nonexistent hypothesis
        hunt_results = await engine.execute_threat_hunt("nonexistent_hypothesis", {})
        
        assert "error" in hunt_results
        assert hunt_results["error"] == "Hypothesis not found"
    
    @pytest.mark.asyncio
    async def test_hunt_in_network_data_suspicious_domains(self, tmp_path):
        """Test hunting in network data for suspicious domains."""
        db_path = tmp_path / "test_network_hunt.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = ThreatHuntingEngine(db)
        
        # Mock network flows with suspicious domains
        network_flows = [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "203.0.113.1",
                "dst_port": 443,
                "domain": "malicious-c2.com"
            },
            {
                "src_ip": "192.168.1.101",
                "dst_ip": "203.0.113.2",
                "dst_port": 80,
                "domain": "evil-command-control.net"
            }
        ]
        
        query_logic = {
            "suspicious_domains": ["malicious-c2.com", "evil-command-control.net"]
        }
        
        # Test network hunting
        findings = await engine._hunt_in_network_data(network_flows, query_logic)
        
        assert len(findings) == 2
        assert all(f["type"] == "suspicious_domain" for f in findings)
        assert findings[0]["domain"] == "malicious-c2.com"
        assert findings[1]["domain"] == "evil-command-control.net"
    
    @pytest.mark.asyncio
    async def test_hunt_in_endpoint_data_suspicious_processes(self, tmp_path):
        """Test hunting in endpoint data for suspicious processes."""
        db_path = tmp_path / "test_endpoint_hunt.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = ThreatHuntingEngine(db)
        
        # Mock process data
        processes = [
            {
                "name": "mimikatz.exe",
                "command_line": "mimikatz.exe sekurlsa::logonpasswords",
                "parent_name": "cmd.exe"
            },
            {
                "name": "powershell.exe", 
                "command_line": "powershell.exe -enc aGVsbG8gd29ybGQ=",
                "parent_name": "winword.exe"
            }
        ]
        
        query_logic = {
            "suspicious_processes": ["mimikatz", "powershell"],
            "command_patterns": [r"powershell.*-enc", r"mimikatz.*sekurlsa"]
        }
        
        # Test endpoint hunting
        findings = await engine._hunt_in_endpoint_data(processes, query_logic)
        
        assert len(findings) >= 2
        process_findings = [f for f in findings if f["type"] == "suspicious_process"]
        command_findings = [f for f in findings if f["type"] == "suspicious_command"]
        
        assert len(process_findings) >= 1
        assert len(command_findings) >= 1
    
    def test_detection_rules_initialization(self, tmp_path):
        """Test detection rules are properly initialized."""
        db_path = tmp_path / "test_detection_rules.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = ThreatHuntingEngine(db)
        
        assert len(engine.detection_rules) > 0
        assert "lateral_movement" in engine.detection_rules
        assert "credential_dumping" in engine.detection_rules
        assert "persistence" in engine.detection_rules
        
        # Check rule structure
        lateral_rule = engine.detection_rules["lateral_movement"]
        assert "pattern" in lateral_rule
        assert "threshold" in lateral_rule
        assert "time_window" in lateral_rule
        assert "mitre_techniques" in lateral_rule
        assert len(lateral_rule["mitre_techniques"]) > 0


class TestSecurityOrchestrationEngine:
    """Test security orchestration engine functionality."""
    
    @pytest.mark.asyncio
    async def test_create_security_playbook(self, tmp_path):
        """Test creating security playbooks."""
        db_path = tmp_path / "test_orchestration.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = SecurityOrchestrationEngine(db)
        
        playbook_id = await engine.create_security_playbook(
            name="Test Malware Response",
            description="Automated response to malware incidents",
            trigger_conditions={
                "threat_types": ["malware", "ransomware"],
                "min_threat_level": 3
            },
            workflow_steps=[
                {
                    "name": "Send Alert",
                    "type": "response_action",
                    "parameters": {"action": "alert", "message": "Malware detected"}
                },
                {
                    "name": "Isolate Host",
                    "type": "response_action",
                    "parameters": {"action": "isolate_host", "hostname": "workstation-01"}
                },
                {
                    "name": "Collect Evidence",
                    "type": "response_action",
                    "parameters": {"action": "collect_evidence", "hostname": "workstation-01"}
                }
            ],
            approval_required=False,
            timeout_minutes=30,
            tags=["malware", "automated"]
        )
        
        assert playbook_id != ""
        assert playbook_id.startswith("playbook_")
        assert playbook_id in engine.playbook_registry
        
        playbook = engine.playbook_registry[playbook_id]
        assert playbook.name == "Test Malware Response"
        assert len(playbook.workflow_steps) == 3
        assert playbook.approval_required == False
        assert playbook.timeout_minutes == 30
        assert len(playbook.tags) == 2
    
    @pytest.mark.asyncio
    async def test_execute_playbook(self, tmp_path):
        """Test executing security playbooks."""
        db_path = tmp_path / "test_playbook_execution.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = SecurityOrchestrationEngine(db)
        
        # Create playbook first
        playbook_id = await engine.create_security_playbook(
            name="Test Response Playbook",
            description="Test playbook execution",
            trigger_conditions={"threat_types": ["malware"]},
            workflow_steps=[
                {
                    "name": "Test Alert",
                    "type": "response_action",
                    "parameters": {"action": "alert", "message": "Test alert"}
                },
                {
                    "name": "Test Delay",
                    "type": "delay",
                    "parameters": {"seconds": 0.1}
                }
            ],
            approval_required=False,
            timeout_minutes=5
        )
        
        # Execute playbook
        execution_id = await engine.execute_playbook(
            playbook_id=playbook_id,
            incident_id="test_incident_001",
            executed_by="test_analyst",
            execution_context={"test_data": "value"}
        )
        
        assert execution_id != ""
        assert execution_id.startswith("exec_")
        assert execution_id in engine.active_executions
        
        execution = engine.active_executions[execution_id]
        assert execution.playbook_id == playbook_id
        assert execution.incident_id == "test_incident_001"
        assert execution.executed_by == "test_analyst"
        assert execution.total_steps == 2
        
        # Wait a bit for async execution to complete
        await asyncio.sleep(0.5)
        
        # Check execution completed
        updated_execution = engine.active_executions[execution_id]
        assert updated_execution.status in [PlaybookStatus.RUNNING, PlaybookStatus.COMPLETED]
    
    @pytest.mark.asyncio
    async def test_execute_nonexistent_playbook(self, tmp_path):
        """Test executing nonexistent playbook."""
        db_path = tmp_path / "test_nonexistent_playbook.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = SecurityOrchestrationEngine(db)
        
        execution_id = await engine.execute_playbook(
            playbook_id="nonexistent_playbook",
            incident_id="test_incident",
            executed_by="test_analyst"
        )
        
        assert execution_id == ""
    
    @pytest.mark.asyncio
    async def test_response_action_alert(self, tmp_path):
        """Test alert response action."""
        db_path = tmp_path / "test_response_actions.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = SecurityOrchestrationEngine(db)
        
        params = {
            "message": "Test security alert",
            "severity": "high"
        }
        
        result = await engine._send_alert(params)
        
        assert "Alert sent" in result
        assert "Test security alert" in result
    
    @pytest.mark.asyncio
    async def test_response_action_block_ip(self, tmp_path):
        """Test block IP response action."""
        db_path = tmp_path / "test_block_ip.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = SecurityOrchestrationEngine(db)
        
        params = {
            "ip_address": "203.0.113.100",
            "duration_minutes": 120
        }
        
        result = await engine._block_ip(params)
        
        assert "IP 203.0.113.100 blocked" in result
        assert "120 minutes" in result
    
    @pytest.mark.asyncio
    async def test_response_action_isolate_host(self, tmp_path):
        """Test isolate host response action."""
        db_path = tmp_path / "test_isolate_host.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = SecurityOrchestrationEngine(db)
        
        params = {
            "hostname": "workstation-infected"
        }
        
        result = await engine._isolate_host(params)
        
        assert "Host workstation-infected isolated" in result
    
    @pytest.mark.asyncio
    async def test_workflow_step_conditional(self, tmp_path):
        """Test conditional workflow step execution."""
        db_path = tmp_path / "test_conditional.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = SecurityOrchestrationEngine(db)
        
        # Test true condition
        step = {
            "type": "conditional",
            "parameters": {
                "condition": {
                    "type": "equals",
                    "field": "threat_level",
                    "value": "high"
                },
                "if_true": {
                    "type": "response_action",
                    "parameters": {"action": "alert", "message": "High threat detected"}
                },
                "if_false": {
                    "type": "response_action",
                    "parameters": {"action": "alert", "message": "Low threat detected"}
                }
            }
        }
        
        context = {"threat_level": "high"}
        result = await engine._execute_workflow_step(step, context)
        
        assert result["success"] == True
    
    @pytest.mark.asyncio
    async def test_workflow_step_parallel(self, tmp_path):
        """Test parallel workflow step execution."""
        db_path = tmp_path / "test_parallel.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = SecurityOrchestrationEngine(db)
        
        step = {
            "type": "parallel",
            "parameters": {
                "tasks": [
                    {
                        "type": "response_action",
                        "parameters": {"action": "alert", "message": "Alert 1"}
                    },
                    {
                        "type": "response_action", 
                        "parameters": {"action": "alert", "message": "Alert 2"}
                    },
                    {
                        "type": "delay",
                        "parameters": {"seconds": 0.01}
                    }
                ]
            }
        }
        
        context = {}
        result = await engine._execute_workflow_step(step, context)
        
        assert result["success"] == True
        assert "parallel_results" in result
        assert len(result["parallel_results"]) == 3


class TestThreatHuntingPlatform:
    """Test main threat hunting platform functionality."""
    
    @pytest.mark.asyncio
    async def test_create_security_incident(self, tmp_path):
        """Test creating security incidents."""
        db_path = tmp_path / "test_platform.db"
        platform = ThreatHuntingPlatform(str(db_path))
        
        incident_id = await platform.create_security_incident(
            title="Test Ransomware Attack",
            description="Ransomware detected on multiple endpoints",
            threat_type=ThreatType.RANSOMWARE,
            threat_level=ThreatLevel.CRITICAL,
            source_ip="192.168.1.100",
            target_assets=["workstation-01", "workstation-02", "server-db-01"],
            indicators=["hash_abc123", "domain_evil.com"],
            mitre_techniques=["T1486", "T1055"]
        )
        
        assert incident_id != ""
        assert incident_id.startswith("incident_")
        
        # Verify incident was stored
        stored_incident = platform.database.get_security_incident(incident_id)
        assert stored_incident is not None
        assert stored_incident.title == "Test Ransomware Attack"
        assert stored_incident.threat_type == ThreatType.RANSOMWARE
        assert stored_incident.threat_level == ThreatLevel.CRITICAL
        assert len(stored_incident.target_assets) == 3
        assert len(stored_incident.indicators) == 2
        assert len(stored_incident.mitre_techniques) == 2
    
    @pytest.mark.asyncio
    async def test_create_security_incident_with_auto_response(self, tmp_path):
        """Test creating incident with automated response."""
        db_path = tmp_path / "test_auto_response.db"
        platform = ThreatHuntingPlatform(str(db_path))
        platform.auto_response_enabled = True
        
        # Create a matching playbook first
        playbook_id = await platform.orchestration_engine.create_security_playbook(
            name="Auto Malware Response",
            description="Automated malware response",
            trigger_conditions={
                "threat_types": ["malware"],
                "min_threat_level": 2
            },
            workflow_steps=[
                {
                    "name": "Alert Security Team",
                    "type": "response_action",
                    "parameters": {"action": "alert", "message": "Malware incident created"}
                }
            ]
        )
        
        # Create incident that should trigger the playbook
        incident_id = await platform.create_security_incident(
            title="Malware Detection",
            description="Malware found on endpoint",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.HIGH
        )
        
        assert incident_id != ""
        
        # Give some time for async auto-response to trigger
        await asyncio.sleep(0.2)
        
        # Check if playbook execution was triggered
        active_executions = platform.orchestration_engine.active_executions
        assert len(active_executions) > 0
    
    @pytest.mark.asyncio
    async def test_process_threat_intelligence(self, tmp_path):
        """Test processing threat intelligence feeds."""
        db_path = tmp_path / "test_threat_intel.db"
        platform = ThreatHuntingPlatform(str(db_path))
        
        intelligence_data = {
            "source": "test_threat_feed",
            "indicators": [
                {
                    "type": "domain",
                    "value": "malicious-domain.com",
                    "threat_type": "command_and_control",
                    "threat_level": 4,
                    "confidence": 0.95,
                    "description": "Known C2 domain",
                    "mitre_techniques": ["T1071"]
                },
                {
                    "type": "ip",
                    "value": "203.0.113.100",
                    "threat_type": "malware",
                    "threat_level": 3,
                    "confidence": 0.8,
                    "description": "Malware hosting IP",
                    "mitre_techniques": ["T1566"]
                },
                {
                    "type": "file_hash",
                    "value": "abc123def456789",
                    "threat_type": "ransomware",
                    "threat_level": 4,
                    "confidence": 0.9,
                    "description": "Ransomware sample hash"
                }
            ]
        }
        
        result = await platform.process_threat_intelligence(intelligence_data)
        
        assert "error" not in result
        assert result["indicators_processed"] == 3
        assert len(result["new_indicators"]) == 3
        assert "processing_timestamp" in result
        
        # Verify indicators were stored
        stored_indicators = platform.database.get_threat_indicators()
        assert len(stored_indicators) >= 3
        
        # Check specific indicator
        domain_indicators = platform.database.get_threat_indicators(indicator_type="domain")
        assert len(domain_indicators) >= 1
        domain_indicator = domain_indicators[0]
        assert domain_indicator.indicator_value == "malicious-domain.com"
        assert domain_indicator.threat_type == ThreatType.COMMAND_AND_CONTROL
    
    @pytest.mark.asyncio
    async def test_get_platform_metrics(self, tmp_path):
        """Test getting platform metrics."""
        db_path = tmp_path / "test_metrics.db"
        platform = ThreatHuntingPlatform(str(db_path))
        
        # Create some test data
        await platform.create_security_incident(
            title="Test Incident 1",
            description="Test incident",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.HIGH
        )
        
        await platform.create_security_incident(
            title="Test Incident 2", 
            description="Test incident 2",
            threat_type=ThreatType.PHISHING,
            threat_level=ThreatLevel.MEDIUM
        )
        
        # Get metrics
        metrics = await platform.get_platform_metrics()
        
        assert "error" not in metrics
        assert metrics["platform_status"] == "operational"
        assert "incidents" in metrics
        assert "threat_levels" in metrics
        assert "playbook_executions" in metrics
        assert "total_indicators" in metrics
        assert "total_hypotheses" in metrics
        assert "total_evidence" in metrics
        assert "last_updated" in metrics
        
        # Check incident counts
        assert metrics["incidents"]["new"] >= 2
    
    @pytest.mark.asyncio
    async def test_platform_with_disabled_auto_response(self, tmp_path):
        """Test platform with disabled auto-response."""
        db_path = tmp_path / "test_no_auto_response.db"
        platform = ThreatHuntingPlatform(str(db_path))
        platform.auto_response_enabled = False
        
        incident_id = await platform.create_security_incident(
            title="Manual Response Required",
            description="High severity incident requiring manual response",
            threat_type=ThreatType.APT,
            threat_level=ThreatLevel.CRITICAL
        )
        
        assert incident_id != ""
        
        # Verify no automatic playbook executions were triggered
        await asyncio.sleep(0.1)
        active_executions = platform.orchestration_engine.active_executions
        assert len(active_executions) == 0


class TestThreatHuntingIntegration:
    """Integration tests for threat hunting system."""
    
    @pytest.mark.asyncio
    async def test_complete_incident_response_workflow(self, tmp_path):
        """Test complete incident response workflow."""
        db_path = tmp_path / "test_integration_workflow.db"
        platform = ThreatHuntingPlatform(str(db_path))
        
        # Step 1: Create response playbook
        playbook_id = await platform.orchestration_engine.create_security_playbook(
            name="Complete Incident Response",
            description="Full incident response workflow",
            trigger_conditions={
                "threat_types": ["apt"],
                "min_threat_level": 3
            },
            workflow_steps=[
                {
                    "name": "Initial Alert",
                    "type": "response_action",
                    "parameters": {"action": "alert", "message": "APT incident detected"}
                },
                {
                    "name": "Isolate Affected Systems",
                    "type": "response_action", 
                    "parameters": {"action": "isolate_host", "hostname": "target_host"}
                },
                {
                    "name": "Collect Forensic Evidence",
                    "type": "response_action",
                    "parameters": {"action": "collect_evidence", "types": ["logs", "memory"]}
                },
                {
                    "name": "Notify Management",
                    "type": "response_action",
                    "parameters": {"action": "escalate", "level": "management"}
                },
                {
                    "name": "Create Support Ticket",
                    "type": "response_action",
                    "parameters": {"action": "create_ticket", "priority": "critical"}
                }
            ],
            approval_required=False,
            timeout_minutes=60
        )
        
        # Step 2: Process threat intelligence
        intel_result = await platform.process_threat_intelligence({
            "source": "apt_intelligence_feed",
            "indicators": [
                {
                    "type": "domain",
                    "value": "apt-c2-server.com",
                    "threat_type": "apt",
                    "threat_level": 4,
                    "confidence": 0.95
                }
            ]
        })
        
        assert intel_result["indicators_processed"] == 1
        
        # Step 3: Create APT incident
        incident_id = await platform.create_security_incident(
            title="Advanced Persistent Threat Detected",
            description="APT group activity detected across multiple systems",
            threat_type=ThreatType.APT,
            threat_level=ThreatLevel.CRITICAL,
            source_ip="203.0.113.50",
            target_assets=["server-01", "workstation-05", "database-server"],
            indicators=["apt-c2-server.com"],
            mitre_techniques=["T1071", "T1041", "T1055"]
        )
        
        assert incident_id != ""
        
        # Step 4: Wait for automated response
        await asyncio.sleep(0.5)
        
        # Step 5: Verify workflow execution
        executions = list(platform.orchestration_engine.active_executions.values())
        assert len(executions) >= 1
        
        execution = executions[0]
        assert execution.incident_id == incident_id
        assert execution.total_steps == 5
    
    @pytest.mark.asyncio
    async def test_threat_hunting_to_incident_pipeline(self, tmp_path):
        """Test pipeline from threat hunting to incident creation."""
        db_path = tmp_path / "test_hunting_pipeline.db"
        platform = ThreatHuntingPlatform(str(db_path))
        
        # Step 1: Create hunting hypothesis
        hypothesis_id = await platform.hunting_engine.create_hunting_hypothesis(
            title="Data Exfiltration Hunt",
            description="Hunt for signs of data exfiltration",
            threat_types=[ThreatType.DATA_EXFILTRATION],
            mitre_techniques=["T1041", "T1048"],
            data_sources=["network", "logs"],
            query_logic={
                "patterns": ["ftp upload", "large file transfer"],
                "suspicious_domains": ["file-sharing-site.com"],
                "time_window": 7200,
                "threshold": 2
            },
            created_by="threat_hunter_alpha"
        )
        
        # Step 2: Execute hunt with suspicious data
        mock_data_sources = {
            "network": {
                "flows": [
                    {
                        "src_ip": "192.168.1.150",
                        "dst_ip": "203.0.113.200",
                        "dst_port": 21,
                        "domain": "file-sharing-site.com",
                        "bytes_transferred": 1073741824  # 1GB
                    }
                ]
            },
            "logs": {
                "entries": [
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "message": "ftp upload initiated to external server",
                        "source_host": "workstation-accounting"
                    },
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "message": "large file transfer detected - 1GB uploaded",
                        "source_host": "workstation-accounting"
                    }
                ]
            }
        }
        
        hunt_results = await platform.hunting_engine.execute_threat_hunt(hypothesis_id, mock_data_sources)
        
        assert hunt_results["findings_count"] > 0
        assert hunt_results["confidence_score"] > 0.5
        
        # Step 3: Based on hunt results, create incident
        if hunt_results["confidence_score"] > 0.7:
            incident_id = await platform.create_security_incident(
                title="Suspected Data Exfiltration",
                description="Threat hunting detected potential data exfiltration activity",
                threat_type=ThreatType.DATA_EXFILTRATION,
                threat_level=ThreatLevel.HIGH,
                source_ip="192.168.1.150",
                target_assets=["workstation-accounting"],
                indicators=["file-sharing-site.com", "ftp_large_transfer"],
                mitre_techniques=["T1041", "T1048"]
            )
            
            assert incident_id != ""
            
            # Verify incident was created with hunt context
            incident = platform.database.get_security_incident(incident_id)
            assert incident.description.startswith("Threat hunting detected")
    
    @pytest.mark.asyncio
    async def test_multi_stage_playbook_execution(self, tmp_path):
        """Test complex multi-stage playbook execution."""
        db_path = tmp_path / "test_multi_stage.db"
        platform = ThreatHuntingPlatform(str(db_path))
        
        # Create complex playbook with conditional logic
        playbook_id = await platform.orchestration_engine.create_security_playbook(
            name="Multi-Stage Response",
            description="Complex multi-stage incident response",
            trigger_conditions={"threat_types": ["ransomware"]},
            workflow_steps=[
                {
                    "name": "Initial Assessment",
                    "type": "response_action",
                    "parameters": {"action": "alert", "message": "Starting incident response"}
                },
                {
                    "name": "Check Severity",
                    "type": "conditional",
                    "parameters": {
                        "condition": {"type": "equals", "field": "threat_level", "value": "critical"},
                        "if_true": {
                            "type": "response_action",
                            "parameters": {"action": "escalate", "level": "executive"}
                        },
                        "if_false": {
                            "type": "response_action", 
                            "parameters": {"action": "notify_admin", "group": "security_team"}
                        }
                    }
                },
                {
                    "name": "Parallel Response Actions",
                    "type": "parallel",
                    "parameters": {
                        "tasks": [
                            {
                                "type": "response_action",
                                "parameters": {"action": "isolate_host"}
                            },
                            {
                                "type": "response_action",
                                "parameters": {"action": "collect_evidence"}
                            },
                            {
                                "type": "response_action",
                                "parameters": {"action": "block_ip"}
                            }
                        ]
                    }
                },
                {
                    "name": "Final Notification",
                    "type": "response_action",
                    "parameters": {"action": "create_ticket", "title": "Ransomware Response Complete"}
                }
            ],
            timeout_minutes=90
        )
        
        # Execute playbook with context
        execution_id = await platform.orchestration_engine.execute_playbook(
            playbook_id=playbook_id,
            incident_id="test_ransomware_001",
            executed_by="senior_analyst",
            execution_context={
                "threat_level": "critical",
                "hostname": "server-critical-01",
                "ip_address": "203.0.113.100"
            }
        )
        
        assert execution_id != ""
        
        # Wait for execution to complete
        await asyncio.sleep(1.0)
        
        # Verify execution completed successfully
        execution = platform.orchestration_engine.active_executions[execution_id]
        assert execution.status in [PlaybookStatus.RUNNING, PlaybookStatus.COMPLETED]
        assert len(execution.execution_log) > 0
        assert len(execution.results) > 0


class TestThreatHuntingWithMocks:
    """Test threat hunting system using mock infrastructure."""
    
    def test_mock_platform_initialization(self):
        """Test mock platform initialization."""
        mock_platform = MockThreatHuntingPlatform()
        
        assert mock_platform.database is not None
        assert mock_platform.hunting_engine is not None
        assert mock_platform.orchestration_engine is not None
        assert mock_platform.enabled == True
        assert mock_platform.auto_response_enabled == True
    
    @pytest.mark.asyncio
    async def test_mock_incident_creation(self):
        """Test incident creation with mock platform."""
        mock_platform = MockThreatHuntingPlatform()
        
        incident_id = await mock_platform.create_security_incident(
            title="Mock Test Incident",
            description="Test incident using mock platform",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.HIGH,
            source_ip="192.168.1.100"
        )
        
        assert incident_id != ""
        assert incident_id.startswith("mock_incident_")
        assert len(mock_platform.incident_creation_calls) == 1
        assert mock_platform.incident_creation_calls[0]["title"] == "Mock Test Incident"
    
    @pytest.mark.asyncio
    async def test_mock_threat_intelligence_processing(self):
        """Test threat intelligence processing with mock platform."""
        mock_platform = MockThreatHuntingPlatform()
        
        intel_data = {
            "source": "mock_feed",
            "indicators": [
                {"type": "domain", "value": "mock-malicious.com", "threat_type": "malware", "threat_level": 3, "confidence": 0.8}
            ]
        }
        
        result = await mock_platform.process_threat_intelligence(intel_data)
        
        assert result["mock_processing"] == True
        assert result["indicators_processed"] == 1
        assert len(mock_platform.intelligence_processing_calls) == 1
    
    @pytest.mark.asyncio
    async def test_mock_test_environment(self):
        """Test mock test environment functionality."""
        mock_env = MockThreatHuntingTestEnvironment()
        
        assert len(mock_env.test_scenarios) >= 6
        assert mock_env.platform is not None
        
        # Test running a specific scenario
        result = await mock_env.run_test_scenario("malware_incident_high_severity")
        
        assert "error" not in result
        assert result["scenario"] == "malware_incident_high_severity"
        assert "incident_id" in result
        assert result["type"] == "incident"
    
    @pytest.mark.asyncio
    async def test_mock_hunting_hypothesis_scenario(self):
        """Test hunting hypothesis scenario with mock environment."""
        mock_env = MockThreatHuntingTestEnvironment()
        
        result = await mock_env.run_test_scenario("hunt_credential_dumping")
        
        assert "error" not in result
        assert result["scenario"] == "hunt_credential_dumping"
        assert "hypothesis_id" in result
        assert "hunt_result" in result
        assert result["type"] == "hunting_hypothesis"
    
    @pytest.mark.asyncio
    async def test_mock_performance_metrics(self):
        """Test performance metrics collection with mock environment."""
        mock_env = MockThreatHuntingTestEnvironment()
        
        # Run a few scenarios to generate metrics
        await mock_env.run_test_scenario("malware_incident_high_severity")
        await mock_env.run_test_scenario("hunt_credential_dumping")
        
        metrics = mock_env.get_performance_metrics()
        
        assert "incident_response_times" in metrics
        assert "threat_hunt_times" in metrics
        assert metrics["incident_response_times"]["count"] >= 1
        assert metrics["threat_hunt_times"]["count"] >= 1
    
    @pytest.mark.asyncio
    async def test_mock_load_testing(self):
        """Test load testing capabilities with mock environment."""
        mock_env = MockThreatHuntingTestEnvironment()
        
        load_results = await mock_env.simulate_load_test(num_incidents=10)
        
        assert "incidents_created" in load_results
        assert "total_time" in load_results
        assert load_results["incidents_created"] <= 10
        assert load_results["total_time"] > 0


class TestThreatHuntingConvenienceFunctions:
    """Test convenience functions and utilities."""
    
    def test_create_threat_hunting_platform_function(self, tmp_path):
        """Test convenience function for creating threat hunting platforms."""
        db_path = tmp_path / "test_convenience.db"
        
        # Test with defaults
        platform = create_threat_hunting_platform(str(db_path))
        assert isinstance(platform, ThreatHuntingPlatform)
        assert platform.auto_response_enabled == True
        
        # Test with auto-response disabled
        platform_no_auto = create_threat_hunting_platform(str(db_path), auto_response_enabled=False)
        assert platform_no_auto.auto_response_enabled == False
    
    def test_enum_value_consistency(self):
        """Test consistency of enum values."""
        # Test ThreatLevel ordering
        assert ThreatLevel.INFO.value < ThreatLevel.LOW.value
        assert ThreatLevel.LOW.value < ThreatLevel.MEDIUM.value
        assert ThreatLevel.MEDIUM.value < ThreatLevel.HIGH.value
        assert ThreatLevel.HIGH.value < ThreatLevel.CRITICAL.value
        
        # Test all enums have string values
        for threat_type in ThreatType:
            assert isinstance(threat_type.value, str)
        
        for status in IncidentStatus:
            assert isinstance(status.value, str)
        
        for action in ResponseAction:
            assert isinstance(action.value, str)
        
        for evidence_type in EvidenceType:
            assert isinstance(evidence_type.value, str)
    
    def test_data_structure_serialization(self):
        """Test data structure serialization."""
        # Test ThreatIndicator serialization
        indicator = ThreatIndicator(
            indicator_id="test_ioc_001",
            indicator_type="domain",
            indicator_value="test-malicious.com",
            threat_type=ThreatType.COMMAND_AND_CONTROL,
            threat_level=ThreatLevel.HIGH,
            confidence_score=0.9,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            source="test_feed",
            tags=["c2", "apt"],
            mitre_techniques=["T1071"]
        )
        
        indicator_dict = indicator.to_dict()
        assert isinstance(indicator_dict, dict)
        assert indicator_dict["indicator_id"] == "test_ioc_001"
        assert indicator_dict["threat_type"] == ThreatType.COMMAND_AND_CONTROL.value
        assert len(indicator_dict["tags"]) == 2
        
        # Test SecurityIncident serialization
        incident = SecurityIncident(
            incident_id="test_inc_001",
            title="Test Incident",
            description="Test incident description",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.CRITICAL,
            status=IncidentStatus.NEW,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            target_assets=["server-01", "workstation-02"]
        )
        
        incident_dict = incident.to_dict()
        assert isinstance(incident_dict, dict)
        assert incident_dict["incident_id"] == "test_inc_001"
        assert incident_dict["threat_type"] == ThreatType.MALWARE.value
        assert incident_dict["status"] == IncidentStatus.NEW.value
        assert len(incident_dict["target_assets"]) == 2
    
    def test_data_structure_validation(self):
        """Test data structure field validation."""
        # Test ThreatIndicator required fields
        with pytest.raises(TypeError):
            ThreatIndicator()  # Missing required fields
        
        # Test SecurityIncident required fields
        with pytest.raises(TypeError):
            SecurityIncident()  # Missing required fields
        
        # Test that valid instances can be created
        indicator = ThreatIndicator(
            indicator_id="test",
            indicator_type="ip",
            indicator_value="203.0.113.1",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.MEDIUM,
            confidence_score=0.7,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            source="test"
        )
        assert indicator.indicator_id == "test"
        
        incident = SecurityIncident(
            incident_id="test",
            title="Test",
            description="Test incident",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.MEDIUM,
            status=IncidentStatus.NEW,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert incident.incident_id == "test"


class TestThreatHuntingErrorHandling:
    """Test error handling and edge cases."""
    
    @pytest.mark.asyncio
    async def test_database_error_handling(self, tmp_path):
        """Test database error handling."""
        # Test with invalid database path
        invalid_db = ThreatHuntingDatabase("/invalid/path/database.db")
        
        # Should still initialize but operations may fail gracefully
        indicator = ThreatIndicator(
            indicator_id="test",
            indicator_type="domain",
            indicator_value="test.com",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.LOW,
            confidence_score=0.5,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            source="test"
        )
        
        # This should fail gracefully
        result = invalid_db.store_threat_indicator(indicator)
        assert isinstance(result, bool)
    
    @pytest.mark.asyncio
    async def test_invalid_threat_intelligence_data(self, tmp_path):
        """Test handling invalid threat intelligence data."""
        db_path = tmp_path / "test_invalid_intel.db"
        platform = ThreatHuntingPlatform(str(db_path))
        
        # Test with malformed data
        invalid_data = {
            "source": "test",
            "indicators": [
                {
                    # Missing required fields
                    "type": "domain"
                    # Missing value, threat_type, threat_level
                }
            ]
        }
        
        result = await platform.process_threat_intelligence(invalid_data)
        
        # Should handle gracefully
        assert isinstance(result, dict)
        assert result.get("indicators_processed", 0) >= 0
    
    @pytest.mark.asyncio
    async def test_playbook_execution_errors(self, tmp_path):
        """Test playbook execution error handling."""
        db_path = tmp_path / "test_playbook_errors.db"
        db = ThreatHuntingDatabase(str(db_path))
        engine = SecurityOrchestrationEngine(db)
        
        # Create playbook with invalid step
        playbook_id = await engine.create_security_playbook(
            name="Error Test Playbook",
            description="Playbook designed to test error handling",
            trigger_conditions={"threat_types": ["test"]},
            workflow_steps=[
                {
                    "name": "Invalid Step",
                    "type": "invalid_step_type",
                    "parameters": {"invalid": "parameter"}
                }
            ]
        )
        
        # Execute playbook - should handle errors gracefully
        execution_id = await engine.execute_playbook(
            playbook_id, "test_incident", "test_user"
        )
        
        assert execution_id != ""
        
        # Wait for execution to complete
        await asyncio.sleep(0.5)
        
        # Execution should complete but may have errors logged
        execution = engine.active_executions[execution_id]
        assert execution.status in [PlaybookStatus.RUNNING, PlaybookStatus.COMPLETED, PlaybookStatus.FAILED]
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, tmp_path):
        """Test concurrent operations handling."""
        db_path = tmp_path / "test_concurrent.db"
        platform = ThreatHuntingPlatform(str(db_path))
        
        # Create multiple incidents concurrently
        tasks = []
        for i in range(10):
            task = platform.create_security_incident(
                title=f"Concurrent Test Incident {i}",
                description=f"Concurrent test {i}",
                threat_type=ThreatType.MALWARE,
                threat_level=ThreatLevel.MEDIUM
            )
            tasks.append(task)
        
        # Wait for all incidents to be created
        incident_ids = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should complete successfully or handle errors gracefully
        successful_ids = [id for id in incident_ids if isinstance(id, str) and id != ""]
        assert len(successful_ids) >= 8  # Most should succeed
    
    @pytest.mark.asyncio
    async def test_large_data_processing(self, tmp_path):
        """Test processing large amounts of data."""
        db_path = tmp_path / "test_large_data.db"
        platform = ThreatHuntingPlatform(str(db_path))
        
        # Create large threat intelligence batch
        large_intel_data = {
            "source": "large_feed",
            "indicators": []
        }
        
        # Add 1000 indicators
        for i in range(1000):
            large_intel_data["indicators"].append({
                "type": "domain",
                "value": f"malicious-{i:04d}.com",
                "threat_type": "malware",
                "threat_level": 2,
                "confidence": 0.5
            })
        
        start_time = time.time()
        result = await platform.process_threat_intelligence(large_intel_data)
        processing_time = time.time() - start_time
        
        # Should complete within reasonable time (10 seconds)
        assert processing_time < 10.0
        assert result["indicators_processed"] == 1000
        
        # Verify some indicators were stored
        stored_indicators = platform.database.get_threat_indicators(limit=100)
        assert len(stored_indicators) >= 100


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])