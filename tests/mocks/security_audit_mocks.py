"""Mock classes for security audit testing."""

import asyncio
import json
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import Mock, MagicMock

from fastapi_shield.security_audit import (
    SecurityFinding, AuditConfiguration, AuditResult, SecurityScanner,
    SeverityLevel, VulnerabilityType, AuditScope
)


class MockSecurityScanner(SecurityScanner):
    """Mock security scanner for testing."""
    
    def __init__(self, config: AuditConfiguration, findings: Optional[List[SecurityFinding]] = None,
                 should_raise: bool = False, scanner_name: str = "MockScanner"):
        super().__init__(config)
        self.findings = findings or []
        self.should_raise = should_raise
        self._scanner_name = scanner_name
        self.scan_count = 0
        self.scanned_paths = []
    
    @property
    def scanner_name(self) -> str:
        return self._scanner_name
    
    async def scan(self, target_path: Path) -> List[SecurityFinding]:
        """Mock scan implementation."""
        self.scan_count += 1
        self.scanned_paths.append(target_path)
        
        if self.should_raise:
            raise RuntimeError("Mock scanner error")
        
        return self.findings.copy()


class MockStaticCodeAnalyzer(MockSecurityScanner):
    """Mock static code analyzer."""
    
    def __init__(self, config: AuditConfiguration, findings: Optional[List[SecurityFinding]] = None):
        super().__init__(config, findings, scanner_name="MockStaticCodeAnalyzer")
        self.analyzed_files = []
    
    async def scan(self, target_path: Path) -> List[SecurityFinding]:
        """Mock static analysis."""
        result = await super().scan(target_path)
        
        # Mock file analysis
        if target_path.exists():
            if target_path.is_file() and target_path.suffix == '.py':
                self.analyzed_files.append(target_path)
            elif target_path.is_dir():
                for py_file in target_path.rglob('*.py'):
                    self.analyzed_files.append(py_file)
        
        return result


class MockDependencyScanner(MockSecurityScanner):
    """Mock dependency scanner."""
    
    def __init__(self, config: AuditConfiguration, findings: Optional[List[SecurityFinding]] = None,
                 available: bool = True):
        super().__init__(config, findings, scanner_name="MockDependencyScanner")
        self._available = available
        self.requirements_files_found = []
    
    def is_available(self) -> bool:
        return self._available
    
    async def scan(self, target_path: Path) -> List[SecurityFinding]:
        """Mock dependency scan."""
        result = await super().scan(target_path)
        
        # Mock requirements file discovery
        if target_path.exists() and target_path.is_dir():
            for req_file in target_path.glob("requirements*.txt"):
                self.requirements_files_found.append(req_file)
        
        return result


class MockConfigurationScanner(MockSecurityScanner):
    """Mock configuration scanner."""
    
    def __init__(self, config: AuditConfiguration, findings: Optional[List[SecurityFinding]] = None):
        super().__init__(config, findings, scanner_name="MockConfigurationScanner")
        self.config_files_found = []
    
    async def scan(self, target_path: Path) -> List[SecurityFinding]:
        """Mock configuration scan."""
        result = await super().scan(target_path)
        
        # Mock config file discovery
        if target_path.exists() and target_path.is_dir():
            for config_file in target_path.glob("*.{ini,cfg,conf,yaml,yml,json}"):
                self.config_files_found.append(config_file)
        
        return result


class MockSubprocessRunner:
    """Mock subprocess runner for testing external tools."""
    
    def __init__(self):
        self.commands_run = []
        self.return_codes = {}
        self.stdout_outputs = {}
        self.stderr_outputs = {}
        self.should_timeout = set()
        self.should_raise = set()
    
    def set_command_result(self, command_pattern: str, return_code: int = 0, 
                          stdout: str = "", stderr: str = ""):
        """Set result for command pattern."""
        self.return_codes[command_pattern] = return_code
        self.stdout_outputs[command_pattern] = stdout
        self.stderr_outputs[command_pattern] = stderr
    
    def set_command_timeout(self, command_pattern: str):
        """Set command to timeout."""
        self.should_timeout.add(command_pattern)
    
    def set_command_error(self, command_pattern: str):
        """Set command to raise error."""
        self.should_raise.add(command_pattern)
    
    def mock_run(self, args, **kwargs):
        """Mock subprocess.run implementation."""
        command_str = ' '.join(args) if isinstance(args, list) else str(args)
        self.commands_run.append(command_str)
        
        # Check for timeout
        for pattern in self.should_timeout:
            if pattern in command_str:
                raise subprocess.TimeoutExpired(args, kwargs.get('timeout', 60))
        
        # Check for errors
        for pattern in self.should_raise:
            if pattern in command_str:
                raise FileNotFoundError("Mock command not found")
        
        # Find matching result
        return_code = 0
        stdout = ""
        stderr = ""
        
        for pattern in self.return_codes:
            if pattern in command_str:
                return_code = self.return_codes[pattern]
                stdout = self.stdout_outputs.get(pattern, "")
                stderr = self.stderr_outputs.get(pattern, "")
                break
        
        # Create mock result
        result = Mock()
        result.returncode = return_code
        result.stdout = stdout
        result.stderr = stderr
        return result


def create_test_finding(
    title: str = "Test Finding",
    severity: SeverityLevel = SeverityLevel.MEDIUM,
    vulnerability_type: VulnerabilityType = VulnerabilityType.SECURITY_MISCONFIGURATION,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    description: str = "Test security finding",
    recommendation: str = "Fix the issue"
) -> SecurityFinding:
    """Create a test security finding."""
    return SecurityFinding(
        id="test-finding-001",
        title=title,
        description=description,
        severity=severity,
        vulnerability_type=vulnerability_type,
        file_path=file_path,
        line_number=line_number,
        recommendation=recommendation
    )


def create_test_findings_set() -> List[SecurityFinding]:
    """Create a diverse set of test findings."""
    return [
        create_test_finding(
            title="Critical SQL Injection",
            severity=SeverityLevel.CRITICAL,
            vulnerability_type=VulnerabilityType.INJECTION,
            file_path="app/models.py",
            line_number=42,
            description="SQL query uses string concatenation with user input",
            recommendation="Use parameterized queries"
        ),
        create_test_finding(
            title="Hardcoded API Key",
            severity=SeverityLevel.HIGH,
            vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
            file_path="config.py",
            line_number=15,
            description="API key appears to be hardcoded",
            recommendation="Use environment variables for secrets"
        ),
        create_test_finding(
            title="Debug Mode Enabled",
            severity=SeverityLevel.MEDIUM,
            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
            file_path="settings.py",
            line_number=8,
            description="Debug mode is enabled in configuration",
            recommendation="Disable debug mode in production"
        ),
        create_test_finding(
            title="Unused Import",
            severity=SeverityLevel.LOW,
            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
            file_path="utils.py",
            line_number=3,
            description="Imported module is not used",
            recommendation="Remove unused imports"
        ),
        create_test_finding(
            title="Information Disclosure",
            severity=SeverityLevel.INFO,
            vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
            file_path="views.py",
            line_number=67,
            description="Error message may reveal sensitive information",
            recommendation="Use generic error messages"
        )
    ]


def create_test_audit_config(
    scope: AuditScope = AuditScope.FULL,
    severity_threshold: SeverityLevel = SeverityLevel.LOW,
    enable_static_analysis: bool = True,
    enable_dependency_scan: bool = True,
    enable_configuration_check: bool = True
) -> AuditConfiguration:
    """Create test audit configuration."""
    return AuditConfiguration(
        scope=scope,
        severity_threshold=severity_threshold,
        enable_static_analysis=enable_static_analysis,
        enable_dependency_scan=enable_dependency_scan,
        enable_configuration_check=enable_configuration_check,
        timeout_seconds=60,
        max_findings=100,
        parallel_execution=False  # Disable for testing
    )


def create_test_audit_result(
    findings: Optional[List[SecurityFinding]] = None,
    configuration: Optional[AuditConfiguration] = None,
    errors: Optional[List[str]] = None,
    warnings: Optional[List[str]] = None
) -> AuditResult:
    """Create test audit result."""
    now = datetime.now()
    
    return AuditResult(
        audit_id="test-audit-001",
        start_time=now,
        end_time=now,
        configuration=configuration or create_test_audit_config(),
        findings=findings or create_test_findings_set(),
        total_files_scanned=10,
        total_lines_scanned=500,
        tools_used=["MockStaticCodeAnalyzer", "MockDependencyScanner"],
        scan_duration_seconds=5.5,
        errors=errors or [],
        warnings=warnings or [],
        metadata={
            "test_mode": True,
            "target_path": "/test/path"
        }
    )


def create_temporary_python_file(content: str, filename: str = "test.py") -> Path:
    """Create temporary Python file with content."""
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', suffix=f'_{filename}', delete=False
    )
    temp_file.write(content)
    temp_file.close()
    return Path(temp_file.name)


def create_temporary_config_file(content: str, filename: str = "config.ini") -> Path:
    """Create temporary config file with content."""
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', suffix=f'_{filename}', delete=False
    )
    temp_file.write(content)
    temp_file.close()
    return Path(temp_file.name)


def create_temporary_requirements_file(requirements: List[str]) -> Path:
    """Create temporary requirements file."""
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', suffix='_requirements.txt', delete=False
    )
    for req in requirements:
        temp_file.write(f"{req}\n")
    temp_file.close()
    return Path(temp_file.name)


def create_test_project_structure(base_path: Path, include_vulnerabilities: bool = True) -> Dict[str, Path]:
    """Create test project structure with optional vulnerabilities."""
    # Create directories
    app_dir = base_path / "app"
    tests_dir = base_path / "tests"
    config_dir = base_path / "config"
    
    app_dir.mkdir(parents=True, exist_ok=True)
    tests_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    
    files_created = {}
    
    # Create main application file
    main_content = '''
"""Main application file."""
import os
from app.models import User

def main():
    """Main function."""
    print("Starting application")
    user = User.get_by_id(1)
    print(f"User: {user.name}")
'''
    
    if include_vulnerabilities:
        main_content += '''
    
    # Vulnerable code
    user_input = input("Enter command: ")
    eval(user_input)  # Code injection vulnerability
'''
    
    main_file = app_dir / "main.py"
    with open(main_file, 'w') as f:
        f.write(main_content)
    files_created['main'] = main_file
    
    # Create models file
    models_content = '''
"""Database models."""
import sqlite3

class User:
    """User model."""
    
    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email
    
    @classmethod
    def get_by_id(cls, user_id):
        """Get user by ID."""
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
'''
    
    if include_vulnerabilities:
        models_content += f'''
        # SQL injection vulnerability
        query = f"SELECT * FROM users WHERE id = {{user_id}}"
        cursor.execute(query)
'''
    else:
        models_content += '''
        # Secure parameterized query
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''
    
    models_content += '''
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return cls(result[0], result[1], result[2])
        return None
'''
    
    models_file = app_dir / "models.py"
    with open(models_file, 'w') as f:
        f.write(models_content)
    files_created['models'] = models_file
    
    # Create config file
    config_content = '''
[database]
host = localhost
port = 5432
name = myapp

[security]
'''
    
    if include_vulnerabilities:
        config_content += '''
debug = true
ssl_enabled = false
secret_key = hardcoded_secret_key_12345
api_key = sk-1234567890abcdef
'''
    else:
        config_content += '''
debug = false
ssl_enabled = true
secret_key = ${SECRET_KEY}
api_key = ${API_KEY}
'''
    
    config_file = config_dir / "app.conf"
    with open(config_file, 'w') as f:
        f.write(config_content)
    files_created['config'] = config_file
    
    # Create requirements file
    requirements = [
        "fastapi==0.68.0",
        "uvicorn==0.15.0",
        "pydantic==1.8.2"
    ]
    
    if include_vulnerabilities:
        # Add vulnerable package
        requirements.append("requests==2.20.0")  # Has known vulnerabilities
    
    req_file = base_path / "requirements.txt"
    with open(req_file, 'w') as f:
        for req in requirements:
            f.write(f"{req}\n")
    files_created['requirements'] = req_file
    
    # Create test file
    test_content = '''
"""Tests for the application."""
import unittest
from app.models import User

class TestUser(unittest.TestCase):
    """Test user model."""
    
    def test_user_creation(self):
        """Test user creation."""
        user = User(1, "John", "john@example.com")
        self.assertEqual(user.name, "John")
'''
    
    test_file = tests_dir / "test_models.py"
    with open(test_file, 'w') as f:
        f.write(test_content)
    files_created['tests'] = test_file
    
    return files_created


def cleanup_temporary_files(*paths: Path) -> None:
    """Clean up temporary files and directories.
    
    Args:
        paths: Paths to clean up
    """
    import shutil
    
    for path in paths:
        try:
            if path.exists():
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    shutil.rmtree(path)
        except (FileNotFoundError, OSError, PermissionError):
            pass  # Ignore cleanup errors


class MockAuditReportGenerator:
    """Mock audit report generator."""
    
    def __init__(self):
        self.generated_reports = []
        self.report_formats = []
    
    def generate_report(self, result: AuditResult, format_type: str = "json") -> str:
        """Generate mock report."""
        self.report_formats.append(format_type)
        
        if format_type == "json":
            report = json.dumps(result.to_dict(), indent=2, default=str)
        elif format_type == "html":
            report = f"<html><body><h1>Audit Report {result.audit_id}</h1></body></html>"
        elif format_type == "text":
            report = f"AUDIT REPORT\n============\nID: {result.audit_id}\nFindings: {len(result.findings)}"
        else:
            report = f"Unknown format: {format_type}"
        
        self.generated_reports.append(report)
        return report