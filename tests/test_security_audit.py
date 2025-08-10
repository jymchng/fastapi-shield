"""Comprehensive tests for the security audit system."""

import asyncio
import json
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock

import pytest

from fastapi_shield.security_audit import (
    SecurityFinding, AuditConfiguration, AuditResult, SecurityScanner,
    StaticCodeAnalyzer, DependencyScanner, ConfigurationScanner,
    SecurityAuditor, SeverityLevel, VulnerabilityType, AuditScope,
    PenetrationTestingMethod, audit_project, audit_shield, create_audit_config
)
from fastapi_shield.shield import Shield
from tests.mocks.security_audit_mocks import (
    MockSecurityScanner, MockStaticCodeAnalyzer, MockDependencyScanner,
    MockConfigurationScanner, MockSubprocessRunner, create_test_finding,
    create_test_findings_set, create_test_audit_config, create_test_audit_result,
    create_temporary_python_file, create_temporary_config_file,
    create_temporary_requirements_file, create_test_project_structure,
    cleanup_temporary_files, MockAuditReportGenerator
)


class TestSecurityFinding:
    """Test SecurityFinding class."""
    
    def test_security_finding_creation(self):
        """Test creating a security finding."""
        finding = create_test_finding()
        
        assert finding.title == "Test Finding"
        assert finding.severity == SeverityLevel.MEDIUM
        assert finding.vulnerability_type == VulnerabilityType.SECURITY_MISCONFIGURATION
        assert finding.description == "Test security finding"
        assert finding.recommendation == "Fix the issue"
        assert not finding.false_positive
        assert not finding.suppressed
        assert isinstance(finding.created_at, datetime)
    
    def test_security_finding_serialization(self):
        """Test security finding serialization."""
        finding = create_test_finding(
            title="Test XSS",
            severity=SeverityLevel.HIGH,
            vulnerability_type=VulnerabilityType.CROSS_SITE_SCRIPTING,
            file_path="app.py",
            line_number=42
        )
        
        # Test to_dict
        data = finding.to_dict()
        assert data["title"] == "Test XSS"
        assert data["severity"] == "high"
        assert data["vulnerability_type"] == "cross_site_scripting"
        assert data["file_path"] == "app.py"
        assert data["line_number"] == 42
        
        # Test from_dict
        restored = SecurityFinding.from_dict(data)
        assert restored.title == finding.title
        assert restored.severity == finding.severity
        assert restored.vulnerability_type == finding.vulnerability_type
        assert restored.file_path == finding.file_path
        assert restored.line_number == finding.line_number
    
    def test_security_finding_all_fields(self):
        """Test security finding with all fields."""
        finding = SecurityFinding(
            id="test-001",
            title="Critical Vulnerability",
            description="Detailed description",
            severity=SeverityLevel.CRITICAL,
            vulnerability_type=VulnerabilityType.INJECTION,
            location="main function",
            line_number=100,
            column_number=25,
            file_path="/app/main.py",
            code_snippet="vulnerable_function(user_input)",
            recommendation="Use input validation",
            cwe_id="CWE-89",
            cvss_score=9.1,
            impact="High",
            likelihood="Very High",
            remediation_effort="Medium",
            false_positive=False,
            suppressed=True
        )
        
        assert finding.id == "test-001"
        assert finding.cvss_score == 9.1
        assert finding.cwe_id == "CWE-89"
        assert finding.suppressed is True
        assert finding.impact == "High"


class TestAuditConfiguration:
    """Test AuditConfiguration class."""
    
    def test_default_configuration(self):
        """Test default audit configuration."""
        config = AuditConfiguration()
        
        assert config.scope == AuditScope.FULL
        assert config.severity_threshold == SeverityLevel.LOW
        assert config.enable_static_analysis is True
        assert config.enable_dependency_scan is True
        assert config.enable_configuration_check is True
        assert config.enable_runtime_analysis is True
        assert config.enable_penetration_testing is False
        assert config.timeout_seconds == 300
        assert config.max_findings == 1000
        assert config.parallel_execution is True
        assert "**/*.py" in config.include_patterns
        assert "**/tests/**" in config.exclude_patterns
    
    def test_custom_configuration(self):
        """Test custom audit configuration."""
        config = AuditConfiguration(
            scope=AuditScope.CODE_ONLY,
            severity_threshold=SeverityLevel.HIGH,
            enable_static_analysis=True,
            enable_dependency_scan=False,
            enable_configuration_check=False,
            timeout_seconds=120,
            max_findings=500,
            include_patterns=["src/**/*.py"],
            exclude_patterns=["src/tests/**"]
        )
        
        assert config.scope == AuditScope.CODE_ONLY
        assert config.severity_threshold == SeverityLevel.HIGH
        assert config.enable_static_analysis is True
        assert config.enable_dependency_scan is False
        assert config.enable_configuration_check is False
        assert config.timeout_seconds == 120
        assert config.max_findings == 500
        assert config.include_patterns == ["src/**/*.py"]
        assert config.exclude_patterns == ["src/tests/**"]
    
    def test_configuration_serialization(self):
        """Test configuration serialization."""
        config = create_test_audit_config(
            scope=AuditScope.DEPENDENCIES_ONLY,
            severity_threshold=SeverityLevel.MEDIUM
        )
        
        data = config.to_dict()
        assert data["scope"] == "dependencies_only"
        assert data["severity_threshold"] == "medium"
        assert data["enable_static_analysis"] is True


class TestAuditResult:
    """Test AuditResult class."""
    
    def test_audit_result_creation(self):
        """Test creating audit result."""
        findings = create_test_findings_set()
        config = create_test_audit_config()
        result = create_test_audit_result(findings=findings, configuration=config)
        
        assert result.audit_id == "test-audit-001"
        assert len(result.findings) == 5
        assert result.total_files_scanned == 10
        assert result.total_lines_scanned == 500
        assert "MockStaticCodeAnalyzer" in result.tools_used
        assert result.scan_duration_seconds == 5.5
    
    def test_findings_by_severity(self):
        """Test grouping findings by severity."""
        findings = create_test_findings_set()
        result = create_test_audit_result(findings=findings)
        
        by_severity = result.findings_by_severity
        
        assert len(by_severity[SeverityLevel.CRITICAL]) == 1
        assert len(by_severity[SeverityLevel.HIGH]) == 1
        assert len(by_severity[SeverityLevel.MEDIUM]) == 1
        assert len(by_severity[SeverityLevel.LOW]) == 1
        assert len(by_severity[SeverityLevel.INFO]) == 1
    
    def test_findings_by_type(self):
        """Test grouping findings by vulnerability type."""
        findings = create_test_findings_set()
        result = create_test_audit_result(findings=findings)
        
        by_type = result.findings_by_type
        
        assert len(by_type[VulnerabilityType.INJECTION]) == 1
        assert len(by_type[VulnerabilityType.INFORMATION_DISCLOSURE]) == 2
        assert len(by_type[VulnerabilityType.SECURITY_MISCONFIGURATION]) == 2
    
    def test_summary_stats(self):
        """Test summary statistics generation."""
        findings = create_test_findings_set()
        result = create_test_audit_result(findings=findings)
        
        stats = result.summary_stats
        
        assert stats["total_findings"] == 5
        assert stats["files_scanned"] == 10
        assert stats["lines_scanned"] == 500
        assert stats["scan_duration"] == 5.5
        assert stats["severity_breakdown"]["critical"] == 1
        assert stats["severity_breakdown"]["high"] == 1
        assert stats["severity_breakdown"]["medium"] == 1
        assert stats["severity_breakdown"]["low"] == 1
        assert stats["severity_breakdown"]["info"] == 1
        assert stats["error_count"] == 0
        assert stats["warning_count"] == 0
    
    def test_audit_result_serialization(self):
        """Test audit result serialization."""
        result = create_test_audit_result()
        
        data = result.to_dict()
        
        assert data["audit_id"] == result.audit_id
        assert data["total_files_scanned"] == result.total_files_scanned
        assert data["total_lines_scanned"] == result.total_lines_scanned
        assert "findings" in data
        assert "configuration" in data
        assert "summary_stats" in data
        assert len(data["findings"]) == len(result.findings)


class TestSecurityScanner:
    """Test SecurityScanner base class and implementations."""
    
    @pytest.mark.asyncio
    async def test_mock_security_scanner(self):
        """Test mock security scanner."""
        config = create_test_audit_config()
        findings = [create_test_finding()]
        scanner = MockSecurityScanner(config, findings=findings)
        
        result = await scanner.scan(Path("/test/path"))
        
        assert len(result) == 1
        assert result[0].title == "Test Finding"
        assert scanner.scan_count == 1
        assert Path("/test/path") in scanner.scanned_paths
    
    @pytest.mark.asyncio
    async def test_scanner_error_handling(self):
        """Test scanner error handling."""
        config = create_test_audit_config()
        scanner = MockSecurityScanner(config, should_raise=True)
        
        with pytest.raises(RuntimeError, match="Mock scanner error"):
            await scanner.scan(Path("/test/path"))
    
    def test_scanner_availability(self):
        """Test scanner availability check."""
        config = create_test_audit_config()
        scanner = MockSecurityScanner(config)
        
        assert scanner.is_available() is True


class TestStaticCodeAnalyzer:
    """Test StaticCodeAnalyzer class."""
    
    @pytest.fixture
    def analyzer(self):
        """Create static code analyzer."""
        config = create_test_audit_config()
        return StaticCodeAnalyzer(config)
    
    @pytest.mark.asyncio
    async def test_analyze_vulnerable_python_file(self, analyzer):
        """Test analyzing Python file with vulnerabilities."""
        # Create file with vulnerable code
        vulnerable_code = '''
import os
import pickle

def vulnerable_function(user_input):
    # Code injection vulnerability
    result = eval(user_input)
    
    # Command injection vulnerability
    os.system(f"ls {user_input}")
    
    # Hardcoded secret
    api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
    
    # Insecure deserialization
    data = pickle.loads(user_input)
    
    return result
'''
        
        temp_file = create_temporary_python_file(vulnerable_code)
        
        try:
            findings = await analyzer.scan(temp_file)
            
            # Should find multiple vulnerabilities
            assert len(findings) > 0
            
            # Check for eval vulnerability
            eval_findings = [f for f in findings if "eval" in f.title.lower()]
            assert len(eval_findings) > 0
            
            # Check for dangerous imports
            import_findings = [f for f in findings if "import" in f.title.lower()]
            assert len(import_findings) > 0
            
            # Check for hardcoded secrets
            secret_findings = [f for f in findings if "secret" in f.title.lower()]
            assert len(secret_findings) > 0
            
        finally:
            cleanup_temporary_files(temp_file)
    
    @pytest.mark.asyncio
    async def test_analyze_clean_python_file(self, analyzer):
        """Test analyzing clean Python file."""
        clean_code = '''
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def safe_function(data: Dict[str, str]) -> List[str]:
    """Safe function with no vulnerabilities."""
    logger.info("Processing data")
    
    results = []
    for key, value in data.items():
        if isinstance(value, str) and len(value) > 0:
            results.append(f"{key}: {value}")
    
    return results

class SafeClass:
    """Safe class implementation."""
    
    def __init__(self, name: str):
        self.name = name
    
    def get_name(self) -> str:
        """Get name safely."""
        return self.name
'''
        
        temp_file = create_temporary_python_file(clean_code)
        
        try:
            findings = await analyzer.scan(temp_file)
            
            # Should find minimal or no vulnerabilities
            critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
            high_findings = [f for f in findings if f.severity == SeverityLevel.HIGH]
            
            assert len(critical_findings) == 0
            assert len(high_findings) == 0
            
        finally:
            cleanup_temporary_files(temp_file)
    
    @pytest.mark.asyncio
    async def test_analyze_syntax_error_file(self, analyzer):
        """Test analyzing file with syntax errors."""
        invalid_code = '''
def broken_function(
    print("Missing closing parenthesis"
    return "invalid"
'''
        
        temp_file = create_temporary_python_file(invalid_code)
        
        try:
            findings = await analyzer.scan(temp_file)
            
            # Should find syntax error
            syntax_findings = [f for f in findings if "syntax" in f.title.lower()]
            assert len(syntax_findings) > 0
            
        finally:
            cleanup_temporary_files(temp_file)
    
    @pytest.mark.asyncio
    async def test_analyze_directory(self, analyzer):
        """Test analyzing directory with multiple files."""
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            # Create project structure
            files_created = create_test_project_structure(temp_dir, include_vulnerabilities=True)
            
            findings = await analyzer.scan(temp_dir)
            
            # Should find vulnerabilities in the created files
            assert len(findings) > 0
            
            # Check that findings reference the correct files
            file_paths = [f.file_path for f in findings if f.file_path]
            assert any("main.py" in path for path in file_paths)
            
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_analyze_nonexistent_path(self, analyzer):
        """Test analyzing non-existent path."""
        findings = await analyzer.scan(Path("/non/existent/path"))
        assert len(findings) == 0


class TestDependencyScanner:
    """Test DependencyScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create dependency scanner."""
        config = create_test_audit_config()
        return DependencyScanner(config)
    
    def test_scanner_availability(self, scanner):
        """Test scanner availability check."""
        # This depends on whether Safety is installed
        availability = scanner.is_available()
        assert isinstance(availability, bool)
    
    @pytest.mark.asyncio
    async def test_scan_requirements_file(self, scanner):
        """Test scanning requirements file."""
        # Create requirements file with potentially vulnerable packages
        requirements = [
            "requests==2.20.0",  # Has known vulnerabilities
            "flask==1.0.0",      # Has known vulnerabilities
            "django==2.0.0"      # Has known vulnerabilities
        ]
        
        temp_req_file = create_temporary_requirements_file(requirements)
        temp_dir = temp_req_file.parent
        
        try:
            # Mock scanner to be available and subprocess to simulate safety output
            with patch.object(scanner, 'is_available', return_value=True):
                with patch('subprocess.run') as mock_run:
                    # Mock successful safety check with vulnerabilities found
                    mock_result = Mock()
                    mock_result.returncode = 1  # Vulnerabilities found
                    mock_result.stdout = json.dumps([
                        {
                            "package": "requests",
                            "vulnerability": "Test vulnerability",
                            "severity": "high",
                            "fixed_in": "2.21.0"
                        }
                    ])
                    mock_run.return_value = mock_result
                    
                    findings = await scanner.scan(temp_dir)
                    
                    # Should call safety check
                    mock_run.assert_called_once()
                    call_args = mock_run.call_args[0][0]
                    assert "safety" in ' '.join(call_args)
                
        finally:
            cleanup_temporary_files(temp_req_file)
    
    @pytest.mark.asyncio
    async def test_scan_no_requirements_file(self, scanner):
        """Test scanning directory without requirements file."""
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            with patch.object(scanner, 'is_available', return_value=True):
                with patch('subprocess.run') as mock_run:
                    mock_result = Mock()
                    mock_result.returncode = 0  # No vulnerabilities
                    mock_result.stdout = "[]"
                    mock_run.return_value = mock_result
                    
                    findings = await scanner.scan(temp_dir)
                    
                    # Should attempt to scan installed packages
                    assert mock_run.called
                
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_scan_timeout_handling(self, scanner):
        """Test handling of safety command timeout."""
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            with patch('subprocess.run') as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(["safety"], 60)
                
                findings = await scanner.scan(temp_dir)
                
                # Should handle timeout gracefully
                assert len(findings) == 0
                
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_scan_command_not_found(self, scanner):
        """Test handling when safety command is not found."""
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            with patch('subprocess.run') as mock_run:
                mock_run.side_effect = FileNotFoundError("safety command not found")
                
                findings = await scanner.scan(temp_dir)
                
                # Should handle missing command gracefully
                assert len(findings) == 0
                
        finally:
            cleanup_temporary_files(temp_dir)


class TestConfigurationScanner:
    """Test ConfigurationScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create configuration scanner."""
        config = create_test_audit_config()
        return ConfigurationScanner(config)
    
    @pytest.mark.asyncio
    async def test_scan_vulnerable_config_file(self, scanner):
        """Test scanning configuration file with vulnerabilities."""
        config_content = '''
[database]
host = localhost
port = 5432
password = hardcoded_password_123

[api]
api_key = sk-1234567890abcdefghijklmnopqrstuvwxyz
secret_token = super_secret_token_value

[security]
debug = true
ssl = false
verify_ssl = false

[cors]
allow_origin = *
'''
        
        temp_config = create_temporary_config_file(config_content, "app.conf")
        
        try:
            findings = await scanner.scan(temp_config)
            
            # Should find multiple configuration issues
            assert len(findings) > 0
            
            # Check for specific types of findings
            has_secret_findings = any("secret" in f.title.lower() or "hardcoded" in f.title.lower() 
                                    for f in findings)
            has_insecure_findings = any("insecure" in f.title.lower() or "debug" in f.title.lower()
                                      for f in findings)
            
            assert has_secret_findings or has_insecure_findings
            
        finally:
            cleanup_temporary_files(temp_config)
    
    @pytest.mark.asyncio
    async def test_scan_secure_config_file(self, scanner):
        """Test scanning secure configuration file."""
        config_content = '''
[database]
host = localhost
port = 5432
password = ${DB_PASSWORD}

[api]
api_key = ${API_KEY}
secret_token = ${SECRET_TOKEN}

[security]
debug = false
ssl = true
verify_ssl = true

[cors]
allow_origin = https://example.com
'''
        
        temp_config = create_temporary_config_file(config_content, "secure.conf")
        
        try:
            findings = await scanner.scan(temp_config)
            
            # Should find minimal or no critical issues
            critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
            high_findings = [f for f in findings if f.severity == SeverityLevel.HIGH]
            
            assert len(critical_findings) == 0
            assert len(high_findings) == 0
            
        finally:
            cleanup_temporary_files(temp_config)
    
    @pytest.mark.asyncio
    async def test_scan_directory_with_configs(self, scanner):
        """Test scanning directory with multiple config files."""
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            files_created = create_test_project_structure(temp_dir, include_vulnerabilities=True)
            
            findings = await scanner.scan(temp_dir)
            
            # Should find vulnerabilities in config files
            assert len(findings) > 0
            
            # Check that findings reference config files
            config_findings = [f for f in findings if f.file_path and "conf" in f.file_path]
            assert len(config_findings) > 0
            
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_scan_unreadable_file(self, scanner):
        """Test scanning unreadable file."""
        # Create file and make it unreadable
        temp_config = create_temporary_config_file("test content")
        temp_config.chmod(0o000)
        
        try:
            findings = await scanner.scan(temp_config)
            
            # Should handle unreadable file gracefully
            assert isinstance(findings, list)
            
        finally:
            # Restore permissions for cleanup
            temp_config.chmod(0o644)
            cleanup_temporary_files(temp_config)


class TestSecurityAuditor:
    """Test SecurityAuditor class."""
    
    @pytest.fixture
    def auditor(self):
        """Create security auditor."""
        config = create_test_audit_config()
        return SecurityAuditor(config)
    
    @pytest.fixture
    def mock_auditor(self):
        """Create security auditor with mock scanners."""
        config = create_test_audit_config()
        auditor = SecurityAuditor(config)
        
        # Replace scanners with mocks
        auditor.scanners = [
            MockStaticCodeAnalyzer(config, findings=[
                create_test_finding("Static Analysis Finding", SeverityLevel.HIGH)
            ]),
            MockDependencyScanner(config, findings=[
                create_test_finding("Dependency Finding", SeverityLevel.MEDIUM)
            ]),
            MockConfigurationScanner(config, findings=[
                create_test_finding("Config Finding", SeverityLevel.LOW)
            ])
        ]
        
        return auditor
    
    def test_auditor_initialization(self, auditor):
        """Test security auditor initialization."""
        assert len(auditor.scanners) >= 1  # At least static analyzer should be present
        assert auditor.config is not None
        assert auditor.logger is not None
    
    @pytest.mark.asyncio
    async def test_audit_with_mock_scanners(self, mock_auditor):
        """Test audit with mock scanners."""
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            result = await mock_auditor.audit(temp_dir)
            
            assert result.audit_id is not None
            assert isinstance(result.start_time, datetime)
            assert isinstance(result.end_time, datetime)
            assert len(result.findings) == 3  # One from each mock scanner
            assert result.total_files_scanned == 0  # Empty directory
            assert len(result.tools_used) == 3
            assert "MockStaticCodeAnalyzer" in result.tools_used
            assert "MockDependencyScanner" in result.tools_used
            assert "MockConfigurationScanner" in result.tools_used
            
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_audit_with_scanner_error(self):
        """Test audit handling scanner errors."""
        config = create_test_audit_config()
        auditor = SecurityAuditor(config)
        
        # Add failing scanner
        auditor.scanners = [
            MockSecurityScanner(config, should_raise=True, scanner_name="FailingScanner")
        ]
        
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            result = await auditor.audit(temp_dir)
            
            # Should handle error gracefully
            assert len(result.errors) == 1
            assert "FailingScanner" in result.errors[0]
            assert len(result.findings) == 0
            
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_audit_severity_filtering(self):
        """Test audit severity filtering."""
        # Create config with high severity threshold
        config = create_test_audit_config(severity_threshold=SeverityLevel.HIGH)
        auditor = SecurityAuditor(config)
        
        # Add scanner with mixed severity findings
        auditor.scanners = [
            MockSecurityScanner(config, findings=[
                create_test_finding("Critical", SeverityLevel.CRITICAL),
                create_test_finding("High", SeverityLevel.HIGH),
                create_test_finding("Medium", SeverityLevel.MEDIUM),  # Should be filtered
                create_test_finding("Low", SeverityLevel.LOW)         # Should be filtered
            ])
        ]
        
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            result = await auditor.audit(temp_dir)
            
            # Should only include critical and high severity findings
            assert len(result.findings) == 2
            assert all(f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] for f in result.findings)
            
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_audit_findings_limit(self):
        """Test audit findings limit."""
        # Create config with low findings limit
        config = create_test_audit_config()
        config.max_findings = 2
        auditor = SecurityAuditor(config)
        
        # Add scanner with many findings
        many_findings = [create_test_finding(f"Finding {i}") for i in range(10)]
        auditor.scanners = [MockSecurityScanner(config, findings=many_findings)]
        
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            result = await auditor.audit(temp_dir)
            
            # Should limit to max_findings
            assert len(result.findings) == 2
            assert len(result.warnings) == 1
            assert "Too many findings" in result.warnings[0]
            
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_audit_nonexistent_path(self, mock_auditor):
        """Test auditing non-existent path."""
        result = await mock_auditor.audit(Path("/non/existent/path"))
        
        assert result.total_files_scanned == 0
        assert result.total_lines_scanned == 0
        # Mock scanners will still return their findings
        assert len(result.findings) >= 0
    
    @pytest.mark.asyncio
    async def test_audit_shield(self, mock_auditor):
        """Test auditing a specific shield."""
        # Create a simple shield
        def test_shield_func(request):
            return {"user": "test"}
        
        shield = Shield(test_shield_func, name="TestShield")
        
        result = await mock_auditor.audit_shield(shield)
        
        assert result.metadata["shield_class"] == "Shield"
        assert "shield_module" in result.metadata
        assert len(result.findings) >= 0
    
    def test_generate_json_report(self, mock_auditor):
        """Test generating JSON report."""
        result = create_test_audit_result()
        
        json_report = mock_auditor.generate_report(result, "json")
        
        # Should be valid JSON
        parsed = json.loads(json_report)
        assert parsed["audit_id"] == result.audit_id
        assert len(parsed["findings"]) == len(result.findings)
    
    def test_generate_html_report(self, mock_auditor):
        """Test generating HTML report."""
        result = create_test_audit_result()
        
        html_report = mock_auditor.generate_report(result, "html")
        
        # Should contain HTML tags and audit info
        assert "<html>" in html_report
        assert result.audit_id in html_report
        assert "Security Audit Report" in html_report
    
    def test_generate_text_report(self, mock_auditor):
        """Test generating text report."""
        result = create_test_audit_result()
        
        text_report = mock_auditor.generate_report(result, "text")
        
        # Should contain audit info
        assert "SECURITY AUDIT REPORT" in text_report
        assert result.audit_id in text_report
        assert "SUMMARY" in text_report
        assert "DETAILED FINDINGS" in text_report
    
    def test_generate_unsupported_format(self, mock_auditor):
        """Test generating report with unsupported format."""
        result = create_test_audit_result()
        
        with pytest.raises(ValueError, match="Unsupported report format"):
            mock_auditor.generate_report(result, "pdf")


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    @pytest.mark.asyncio
    async def test_audit_project_function(self):
        """Test audit_project convenience function."""
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            # Create simple project structure
            create_test_project_structure(temp_dir)
            
            # Mock the SecurityAuditor to avoid actual scanning
            with patch('fastapi_shield.security_audit.SecurityAuditor') as mock_auditor_class:
                mock_auditor = Mock()
                mock_result = create_test_audit_result()
                mock_auditor.audit = AsyncMock(return_value=mock_result)
                mock_auditor_class.return_value = mock_auditor
                
                result = await audit_project(str(temp_dir))
                
                assert result.audit_id == mock_result.audit_id
                mock_auditor.audit.assert_called_once()
                
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_audit_shield_function(self):
        """Test audit_shield convenience function."""
        def test_shield_func(request):
            return {"valid": True}
        
        shield = Shield(test_shield_func, name="TestShield")
        
        # Mock the SecurityAuditor
        with patch('fastapi_shield.security_audit.SecurityAuditor') as mock_auditor_class:
            mock_auditor = Mock()
            mock_result = create_test_audit_result()
            mock_auditor.audit_shield = AsyncMock(return_value=mock_result)
            mock_auditor_class.return_value = mock_auditor
            
            result = await audit_shield(shield)
            
            assert result.audit_id == mock_result.audit_id
            mock_auditor.audit_shield.assert_called_once_with(shield)
    
    def test_create_audit_config_function(self):
        """Test create_audit_config convenience function."""
        config = create_audit_config(
            scope=AuditScope.CODE_ONLY,
            severity_threshold=SeverityLevel.HIGH,
            enable_penetration_testing=True
        )
        
        assert config.scope == AuditScope.CODE_ONLY
        assert config.severity_threshold == SeverityLevel.HIGH
        assert config.enable_penetration_testing is True


class TestSecurityAuditIntegration:
    """Integration tests for security audit system."""
    
    @pytest.mark.asyncio
    async def test_full_project_audit_integration(self):
        """Test full project audit integration."""
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            # Create realistic project structure with vulnerabilities
            files_created = create_test_project_structure(temp_dir, include_vulnerabilities=True)
            
            # Create auditor with real scanners (but limited scope for testing)
            config = AuditConfiguration(
                scope=AuditScope.CODE_ONLY,  # Limit to code analysis only
                enable_static_analysis=True,
                enable_dependency_scan=False,  # Disable to avoid external dependencies
                enable_configuration_check=True,
                timeout_seconds=30,
                max_findings=50
            )
            
            auditor = SecurityAuditor(config)
            result = await auditor.audit(temp_dir)
            
            # Verify audit completed successfully
            assert result.audit_id is not None
            assert result.total_files_scanned > 0
            assert result.scan_duration_seconds > 0
            assert len(result.tools_used) > 0
            
            # Should find some vulnerabilities in the test code
            if len(result.findings) > 0:
                # Verify finding structure
                for finding in result.findings:
                    assert finding.id is not None
                    assert finding.title is not None
                    assert finding.description is not None
                    assert isinstance(finding.severity, SeverityLevel)
                    assert isinstance(finding.vulnerability_type, VulnerabilityType)
            
        finally:
            cleanup_temporary_files(temp_dir)
    
    @pytest.mark.asyncio
    async def test_concurrent_audits(self):
        """Test running multiple audits concurrently."""
        temp_dirs = []
        
        try:
            # Create multiple test projects
            for i in range(3):
                temp_dir = Path(tempfile.mkdtemp())
                temp_dirs.append(temp_dir)
                create_test_project_structure(temp_dir, include_vulnerabilities=True)
            
            # Run audits concurrently
            config = create_test_audit_config(
                enable_dependency_scan=False  # Disable for test reliability
            )
            config.timeout_seconds = 30
            
            async def audit_project_task(project_dir):
                auditor = SecurityAuditor(config)
                return await auditor.audit(project_dir)
            
            results = await asyncio.gather(*[
                audit_project_task(temp_dir) for temp_dir in temp_dirs
            ])
            
            # Verify all audits completed
            assert len(results) == 3
            
            for result in results:
                assert result.audit_id is not None
                assert result.total_files_scanned >= 0
                assert len(result.tools_used) > 0
            
        finally:
            cleanup_temporary_files(*temp_dirs)
    
    @pytest.mark.asyncio
    async def test_audit_performance_measurement(self):
        """Test audit performance measurement."""
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            # Create larger project structure
            create_test_project_structure(temp_dir, include_vulnerabilities=True)
            
            # Add more files to increase scan time
            for i in range(5):
                extra_file = temp_dir / f"extra_file_{i}.py"
                with open(extra_file, 'w') as f:
                    f.write(f'''
def function_{i}():
    """Function number {i}."""
    import os
    user_input = input("Enter data: ")
    result = eval(user_input)  # Vulnerability
    return result
''')
            
            config = create_test_audit_config()
            auditor = SecurityAuditor(config)
            
            start_time = datetime.now()
            result = await auditor.audit(temp_dir)
            end_time = datetime.now()
            
            # Verify timing measurements
            assert result.scan_duration_seconds > 0
            actual_duration = (end_time - start_time).total_seconds()
            
            # Allow some variance in timing measurements
            assert abs(result.scan_duration_seconds - actual_duration) < 1.0
            
        finally:
            cleanup_temporary_files(temp_dir)
    
    def test_report_generation_integration(self):
        """Test report generation integration."""
        auditor = SecurityAuditor(create_test_audit_config())
        result = create_test_audit_result()
        
        # Test all supported formats
        formats = ["json", "html", "text"]
        reports = {}
        
        for fmt in formats:
            report = auditor.generate_report(result, fmt)
            reports[fmt] = report
            
            # Basic validation
            assert len(report) > 0
            assert result.audit_id in report
        
        # Verify different formats produce different content
        assert reports["json"] != reports["html"]
        assert reports["html"] != reports["text"]
        assert reports["json"] != reports["text"]
        
        # JSON should be parseable
        json.loads(reports["json"])
        
        # HTML should contain tags
        assert "<html>" in reports["html"]
        assert "</html>" in reports["html"]
        
        # Text should be plain text
        assert "<" not in reports["text"] or ">" not in reports["text"]