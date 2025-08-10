"""Security audit system for FastAPI Shield.

This module provides comprehensive security auditing capabilities including
vulnerability assessment, code analysis, dependency scanning, penetration testing,
and security best practices validation.
"""

import ast
import hashlib
import importlib
import inspect
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import (
    Any, Dict, List, Optional, Set, Tuple, Union, Callable,
    Pattern, NamedTuple
)
import threading
import weakref

try:
    import bandit
    from bandit.core import manager as bandit_manager
    from bandit.core import config as bandit_config
    BANDIT_AVAILABLE = True
except ImportError:
    BANDIT_AVAILABLE = False

try:
    import safety
    SAFETY_AVAILABLE = True
except ImportError:
    SAFETY_AVAILABLE = False

try:
    import semgrep
    SEMGREP_AVAILABLE = True
except ImportError:
    SEMGREP_AVAILABLE = False

from fastapi import Request, Response
from fastapi_shield.shield import Shield

logger = logging.getLogger(__name__)


class SeverityLevel(str, Enum):
    """Security issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """Types of security vulnerabilities."""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ENCRYPTION = "encryption"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    BUFFER_OVERFLOW = "buffer_overflow"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"
    CROSS_SITE_REQUEST_FORGERY = "cross_site_request_forgery"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    LOGGING_MONITORING = "logging_monitoring"
    SERVER_SIDE_REQUEST_FORGERY = "server_side_request_forgery"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    INSUFFICIENT_LOGGING = "insufficient_logging"


class AuditScope(str, Enum):
    """Scope of security audit."""
    FULL = "full"
    CODE_ONLY = "code_only"
    DEPENDENCIES_ONLY = "dependencies_only"
    CONFIGURATION_ONLY = "configuration_only"
    RUNTIME_ONLY = "runtime_only"


class PenetrationTestingMethod(str, Enum):
    """Penetration testing methods."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    INTERACTIVE_TESTING = "interactive_testing"
    AUTOMATED_SCANNING = "automated_scanning"
    MANUAL_TESTING = "manual_testing"


@dataclass
class SecurityFinding:
    """Represents a security finding from audit."""
    id: str
    title: str
    description: str
    severity: SeverityLevel
    vulnerability_type: VulnerabilityType
    location: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    impact: Optional[str] = None
    likelihood: Optional[str] = None
    remediation_effort: Optional[str] = None
    false_positive: bool = False
    suppressed: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "vulnerability_type": self.vulnerability_type.value,
            "location": self.location,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "file_path": self.file_path,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "remediation_effort": self.remediation_effort,
            "false_positive": self.false_positive,
            "suppressed": self.suppressed,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityFinding':
        """Create finding from dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            severity=SeverityLevel(data["severity"]),
            vulnerability_type=VulnerabilityType(data["vulnerability_type"]),
            location=data.get("location"),
            line_number=data.get("line_number"),
            column_number=data.get("column_number"),
            file_path=data.get("file_path"),
            code_snippet=data.get("code_snippet"),
            recommendation=data.get("recommendation"),
            cwe_id=data.get("cwe_id"),
            cvss_score=data.get("cvss_score"),
            impact=data.get("impact"),
            likelihood=data.get("likelihood"),
            remediation_effort=data.get("remediation_effort"),
            false_positive=data.get("false_positive", False),
            suppressed=data.get("suppressed", False),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"])
        )


@dataclass
class AuditConfiguration:
    """Configuration for security audit."""
    scope: AuditScope = AuditScope.FULL
    include_patterns: List[str] = field(default_factory=lambda: ["**/*.py"])
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "**/tests/**", "**/test_*.py", "**/__pycache__/**", "**/.*"
    ])
    severity_threshold: SeverityLevel = SeverityLevel.LOW
    enable_static_analysis: bool = True
    enable_dependency_scan: bool = True
    enable_configuration_check: bool = True
    enable_runtime_analysis: bool = True
    enable_penetration_testing: bool = False  # Disabled by default
    custom_rules: List[Dict[str, Any]] = field(default_factory=list)
    timeout_seconds: int = 300  # 5 minutes
    max_findings: int = 1000
    parallel_execution: bool = True
    generate_report: bool = True
    report_format: str = "json"  # json, html, pdf
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "scope": self.scope.value,
            "include_patterns": self.include_patterns,
            "exclude_patterns": self.exclude_patterns,
            "severity_threshold": self.severity_threshold.value,
            "enable_static_analysis": self.enable_static_analysis,
            "enable_dependency_scan": self.enable_dependency_scan,
            "enable_configuration_check": self.enable_configuration_check,
            "enable_runtime_analysis": self.enable_runtime_analysis,
            "enable_penetration_testing": self.enable_penetration_testing,
            "custom_rules": self.custom_rules,
            "timeout_seconds": self.timeout_seconds,
            "max_findings": self.max_findings,
            "parallel_execution": self.parallel_execution,
            "generate_report": self.generate_report,
            "report_format": self.report_format
        }


@dataclass
class AuditResult:
    """Results of security audit."""
    audit_id: str
    start_time: datetime
    end_time: datetime
    configuration: AuditConfiguration
    findings: List[SecurityFinding]
    total_files_scanned: int = 0
    total_lines_scanned: int = 0
    tools_used: List[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def findings_by_severity(self) -> Dict[SeverityLevel, List[SecurityFinding]]:
        """Group findings by severity."""
        grouped = {}
        for severity in SeverityLevel:
            grouped[severity] = [f for f in self.findings if f.severity == severity]
        return grouped
    
    @property
    def findings_by_type(self) -> Dict[VulnerabilityType, List[SecurityFinding]]:
        """Group findings by vulnerability type."""
        grouped = {}
        for vuln_type in VulnerabilityType:
            grouped[vuln_type] = [f for f in self.findings if f.vulnerability_type == vuln_type]
        return grouped
    
    @property
    def summary_stats(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        severity_counts = {
            severity.value: len(findings) 
            for severity, findings in self.findings_by_severity.items()
        }
        
        type_counts = {
            vuln_type.value: len(findings)
            for vuln_type, findings in self.findings_by_type.items()
            if len(findings) > 0
        }
        
        return {
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "vulnerability_type_breakdown": type_counts,
            "files_scanned": self.total_files_scanned,
            "lines_scanned": self.total_lines_scanned,
            "scan_duration": self.scan_duration_seconds,
            "tools_used": self.tools_used,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit result to dictionary."""
        return {
            "audit_id": self.audit_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "configuration": self.configuration.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "total_files_scanned": self.total_files_scanned,
            "total_lines_scanned": self.total_lines_scanned,
            "tools_used": self.tools_used,
            "scan_duration_seconds": self.scan_duration_seconds,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
            "summary_stats": self.summary_stats
        }


class SecurityScanner(ABC):
    """Abstract base class for security scanners."""
    
    def __init__(self, config: AuditConfiguration):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    async def scan(self, target_path: Path) -> List[SecurityFinding]:
        """Scan target for security issues.
        
        Args:
            target_path: Path to scan
            
        Returns:
            List of security findings
        """
        pass
    
    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Get scanner name."""
        pass
    
    def is_available(self) -> bool:
        """Check if scanner is available."""
        return True


class StaticCodeAnalyzer(SecurityScanner):
    """Static code analysis scanner."""
    
    DANGEROUS_FUNCTIONS = {
        'eval': 'Use of eval() can lead to code injection',
        'exec': 'Use of exec() can lead to code injection', 
        'compile': 'Use of compile() with user input can be dangerous',
        'input': 'Use of input() can lead to injection attacks in Python 2',
        '__import__': 'Dynamic imports can be dangerous',
        'getattr': 'Dynamic attribute access can be exploited',
        'setattr': 'Dynamic attribute setting can be exploited',
        'hasattr': 'Dynamic attribute checking can leak information',
        'delattr': 'Dynamic attribute deletion can be exploited'
    }
    
    DANGEROUS_MODULES = {
        'os': 'OS module can lead to command injection',
        'subprocess': 'Subprocess module can lead to command injection',
        'pickle': 'Pickle module can lead to deserialization attacks',
        'marshal': 'Marshal module can lead to deserialization attacks',
        'shelve': 'Shelve module can lead to deserialization attacks'
    }
    
    @property
    def scanner_name(self) -> str:
        return "StaticCodeAnalyzer"
    
    async def scan(self, target_path: Path) -> List[SecurityFinding]:
        """Perform static code analysis."""
        findings = []
        
        if not target_path.exists():
            return findings
        
        python_files = self._find_python_files(target_path)
        
        for file_path in python_files:
            try:
                file_findings = await self._analyze_file(file_path)
                findings.extend(file_findings)
            except Exception as e:
                self.logger.error(f"Error analyzing {file_path}: {e}")
        
        return findings
    
    def _find_python_files(self, path: Path) -> List[Path]:
        """Find Python files to analyze."""
        if path.is_file() and path.suffix == '.py':
            return [path]
        
        python_files = []
        if path.is_dir():
            for pattern in self.config.include_patterns:
                python_files.extend(path.glob(pattern))
        
        # Filter out excluded patterns
        filtered_files = []
        for file_path in python_files:
            if not any(file_path.match(pattern) for pattern in self.config.exclude_patterns):
                filtered_files.append(file_path)
        
        return filtered_files
    
    async def _analyze_file(self, file_path: Path) -> List[SecurityFinding]:
        """Analyze a single Python file."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content, filename=str(file_path))
            
            # Analyze AST
            findings.extend(self._analyze_ast(tree, file_path, content))
            
            # Analyze raw content
            findings.extend(self._analyze_content(content, file_path))
            
        except SyntaxError as e:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4()),
                title="Syntax Error",
                description=f"Syntax error in file: {e}",
                severity=SeverityLevel.MEDIUM,
                vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                file_path=str(file_path),
                line_number=getattr(e, 'lineno', None)
            ))
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {e}")
        
        return findings
    
    def _analyze_ast(self, tree: ast.AST, file_path: Path, content: str) -> List[SecurityFinding]:
        """Analyze AST for security issues."""
        findings = []
        lines = content.split('\n')
        
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in self.DANGEROUS_FUNCTIONS:
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4()),
                            title=f"Dangerous Function: {func_name}",
                            description=self.DANGEROUS_FUNCTIONS[func_name],
                            severity=SeverityLevel.HIGH,
                            vulnerability_type=VulnerabilityType.INJECTION,
                            file_path=str(file_path),
                            line_number=node.lineno,
                            column_number=node.col_offset,
                            code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else None,
                            recommendation=f"Avoid using {func_name}() with untrusted input"
                        ))
            
            # Check for dangerous imports
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.DANGEROUS_MODULES:
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4()),
                            title=f"Dangerous Import: {alias.name}",
                            description=self.DANGEROUS_MODULES[alias.name],
                            severity=SeverityLevel.MEDIUM,
                            vulnerability_type=VulnerabilityType.VULNERABLE_COMPONENTS,
                            file_path=str(file_path),
                            line_number=node.lineno,
                            column_number=node.col_offset,
                            code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else None,
                            recommendation=f"Use {alias.name} module carefully and validate all inputs"
                        ))
            
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module in self.DANGEROUS_MODULES:
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        title=f"Dangerous Import: {node.module}",
                        description=self.DANGEROUS_MODULES[node.module],
                        severity=SeverityLevel.MEDIUM,
                        vulnerability_type=VulnerabilityType.VULNERABLE_COMPONENTS,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else None,
                        recommendation=f"Use {node.module} module carefully and validate all inputs"
                    ))
            
            # Check for hardcoded secrets
            elif isinstance(node, ast.Str):
                if self._looks_like_secret(node.s):
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        title="Potential Hardcoded Secret",
                        description="String value looks like a secret or API key",
                        severity=SeverityLevel.HIGH,
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else None,
                        recommendation="Use environment variables or secure configuration for secrets"
                    ))
        
        return findings
    
    def _analyze_content(self, content: str, file_path: Path) -> List[SecurityFinding]:
        """Analyze raw content for security issues."""
        findings = []
        lines = content.split('\n')
        
        # Check for potential SQL injection patterns
        sql_patterns = [
            r'SELECT\s+\*\s+FROM\s+\w+\s+WHERE.*\+',
            r'INSERT\s+INTO\s+\w+.*\+',
            r'UPDATE\s+\w+\s+SET.*\+',
            r'DELETE\s+FROM\s+\w+\s+WHERE.*\+'
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        title="Potential SQL Injection",
                        description="SQL query appears to use string concatenation",
                        severity=SeverityLevel.HIGH,
                        vulnerability_type=VulnerabilityType.INJECTION,
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Use parameterized queries instead of string concatenation"
                    ))
        
        # Check for debug code
        debug_patterns = [
            r'print\s*\(',
            r'pdb\.set_trace\(\)',
            r'import\s+pdb',
            r'breakpoint\(\)',
            r'console\.log\(',
            r'alert\('
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in debug_patterns:
                if re.search(pattern, line):
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        title="Debug Code Present",
                        description="Debug code found that should be removed in production",
                        severity=SeverityLevel.LOW,
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Remove debug code before production deployment"
                    ))
        
        return findings
    
    def _looks_like_secret(self, value: str) -> bool:
        """Check if string looks like a secret."""
        if len(value) < 16:
            return False
        
        # Check for common secret patterns
        secret_patterns = [
            r'^[A-Za-z0-9+/]{40,}={0,2}$',  # Base64
            r'^[a-fA-F0-9]{32,}$',          # Hex
            r'^[A-Za-z0-9_-]{32,}$',        # URL-safe base64
        ]
        
        for pattern in secret_patterns:
            if re.match(pattern, value):
                return True
        
        # Check for common secret keywords
        secret_keywords = [
            'password', 'secret', 'key', 'token', 'api_key', 
            'private_key', 'access_token', 'refresh_token'
        ]
        
        value_lower = value.lower()
        for keyword in secret_keywords:
            if keyword in value_lower and len(value) > 20:
                return True
        
        return False


class DependencyScanner(SecurityScanner):
    """Dependency vulnerability scanner."""
    
    @property
    def scanner_name(self) -> str:
        return "DependencyScanner"
    
    def is_available(self) -> bool:
        """Check if Safety is available."""
        return SAFETY_AVAILABLE
    
    async def scan(self, target_path: Path) -> List[SecurityFinding]:
        """Scan dependencies for vulnerabilities."""
        findings = []
        
        if not self.is_available():
            self.logger.warning("Safety not available, skipping dependency scan")
            return findings
        
        # Find requirements files
        req_files = self._find_requirements_files(target_path)
        
        for req_file in req_files:
            try:
                file_findings = await self._scan_requirements_file(req_file)
                findings.extend(file_findings)
            except Exception as e:
                self.logger.error(f"Error scanning {req_file}: {e}")
        
        # Scan installed packages if no requirements files found
        if not req_files:
            try:
                findings.extend(await self._scan_installed_packages())
            except Exception as e:
                self.logger.error(f"Error scanning installed packages: {e}")
        
        return findings
    
    def _find_requirements_files(self, path: Path) -> List[Path]:
        """Find requirements files."""
        req_files = []
        
        if path.is_dir():
            # Common requirements file patterns
            patterns = [
                'requirements.txt',
                'requirements-*.txt', 
                'requirements/*.txt',
                'Pipfile',
                'pyproject.toml',
                'setup.py'
            ]
            
            for pattern in patterns:
                req_files.extend(path.glob(pattern))
        
        return req_files
    
    async def _scan_requirements_file(self, req_file: Path) -> List[SecurityFinding]:
        """Scan a requirements file for vulnerabilities."""
        findings = []
        
        try:
            # Use safety check command
            result = subprocess.run([
                sys.executable, '-m', 'safety', 'check',
                '-r', str(req_file),
                '--json'
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # No vulnerabilities found
                return findings
            
            # Parse safety output
            if result.stdout:
                try:
                    vulns = json.loads(result.stdout)
                    for vuln in vulns:
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4()),
                            title=f"Vulnerable Dependency: {vuln.get('package', 'unknown')}",
                            description=vuln.get('vulnerability', 'Unknown vulnerability'),
                            severity=self._map_safety_severity(vuln.get('severity', 'medium')),
                            vulnerability_type=VulnerabilityType.VULNERABLE_COMPONENTS,
                            file_path=str(req_file),
                            recommendation=f"Update {vuln.get('package')} to version {vuln.get('fixed_in', 'latest')}",
                            cwe_id=vuln.get('cwe')
                        ))
                except json.JSONDecodeError:
                    # Fallback to text parsing
                    findings.extend(self._parse_safety_text_output(result.stdout, req_file))
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout scanning {req_file}")
        except FileNotFoundError:
            self.logger.error("Safety command not found")
        
        return findings
    
    async def _scan_installed_packages(self) -> List[SecurityFinding]:
        """Scan installed packages for vulnerabilities."""
        findings = []
        
        try:
            # Use safety check command on installed packages
            result = subprocess.run([
                sys.executable, '-m', 'safety', 'check',
                '--json'
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return findings
            
            if result.stdout:
                try:
                    vulns = json.loads(result.stdout)
                    for vuln in vulns:
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4()),
                            title=f"Vulnerable Package: {vuln.get('package', 'unknown')}",
                            description=vuln.get('vulnerability', 'Unknown vulnerability'),
                            severity=self._map_safety_severity(vuln.get('severity', 'medium')),
                            vulnerability_type=VulnerabilityType.VULNERABLE_COMPONENTS,
                            recommendation=f"Update {vuln.get('package')} to version {vuln.get('fixed_in', 'latest')}",
                            cwe_id=vuln.get('cwe')
                        ))
                except json.JSONDecodeError:
                    findings.extend(self._parse_safety_text_output(result.stdout, None))
        
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout scanning installed packages")
        except FileNotFoundError:
            self.logger.error("Safety command not found")
        
        return findings
    
    def _map_safety_severity(self, safety_severity: str) -> SeverityLevel:
        """Map Safety severity to our severity levels."""
        mapping = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW
        }
        return mapping.get(safety_severity.lower(), SeverityLevel.MEDIUM)
    
    def _parse_safety_text_output(self, output: str, req_file: Optional[Path]) -> List[SecurityFinding]:
        """Parse Safety text output."""
        findings = []
        
        # Basic text parsing for Safety output
        lines = output.split('\n')
        current_vuln = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith('vulnerability found in'):
                # Extract package name
                parts = line.split()
                if len(parts) > 3:
                    current_vuln['package'] = parts[3]
            elif line.startswith('installed:'):
                current_vuln['installed_version'] = line.split(':')[1].strip()
            elif line.startswith('affected:'):
                current_vuln['affected_versions'] = line.split(':')[1].strip()
            elif line.startswith('ID:'):
                current_vuln['id'] = line.split(':')[1].strip()
            elif line and 'vulnerability' not in line.lower() and current_vuln:
                # This might be the description
                current_vuln['description'] = line
                
                # Create finding
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    title=f"Vulnerable Dependency: {current_vuln.get('package', 'unknown')}",
                    description=current_vuln.get('description', 'Vulnerability found'),
                    severity=SeverityLevel.MEDIUM,
                    vulnerability_type=VulnerabilityType.VULNERABLE_COMPONENTS,
                    file_path=str(req_file) if req_file else None,
                    recommendation=f"Update {current_vuln.get('package', 'package')} to a fixed version"
                ))
                current_vuln = {}
        
        return findings


class ConfigurationScanner(SecurityScanner):
    """Configuration security scanner."""
    
    @property
    def scanner_name(self) -> str:
        return "ConfigurationScanner"
    
    async def scan(self, target_path: Path) -> List[SecurityFinding]:
        """Scan configuration for security issues."""
        findings = []
        
        if target_path.is_file():
            # If target is a single file, scan it directly
            try:
                file_findings = await self._scan_config_file(target_path)
                findings.extend(file_findings)
            except Exception as e:
                self.logger.error(f"Error scanning {target_path}: {e}")
        else:
            # If target is a directory, find config files
            config_files = self._find_config_files(target_path)
            
            for config_file in config_files:
                try:
                    file_findings = await self._scan_config_file(config_file)
                    findings.extend(file_findings)
                except Exception as e:
                    self.logger.error(f"Error scanning {config_file}: {e}")
        
        return findings
    
    def _find_config_files(self, path: Path) -> List[Path]:
        """Find configuration files."""
        config_files = []
        
        if path.is_dir():
            patterns = [
                '*.ini', '*.cfg', '*.conf', '*.config',
                '*.yaml', '*.yml', '*.json', '*.toml',
                '.env', '.env.*', 'Dockerfile', 'docker-compose.yml',
                'requirements.txt', 'setup.py', 'pyproject.toml'
            ]
            
            for pattern in patterns:
                config_files.extend(path.rglob(pattern))
        
        return config_files
    
    async def _scan_config_file(self, config_file: Path) -> List[SecurityFinding]:
        """Scan configuration file for security issues."""
        findings = []
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            # Check for hardcoded secrets
            for i, line in enumerate(lines, 1):
                if self._contains_secret(line):
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        title="Hardcoded Secret in Configuration",
                        description="Configuration file contains what appears to be a hardcoded secret",
                        severity=SeverityLevel.HIGH,
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        file_path=str(config_file),
                        line_number=i,
                        code_snippet=self._sanitize_secret_line(line),
                        recommendation="Use environment variables or secure configuration management"
                    ))
            
            # Check for insecure settings
            insecure_patterns = [
                (r'debug\s*=\s*true', 'Debug mode enabled', SeverityLevel.MEDIUM),
                (r'ssl\s*=\s*false', 'SSL disabled', SeverityLevel.HIGH),
                (r'verify_ssl\s*=\s*false', 'SSL verification disabled', SeverityLevel.HIGH),
                (r'allow_origin\s*=\s*\*', 'CORS allows all origins', SeverityLevel.MEDIUM),
                (r'host\s*=\s*0\.0\.0\.0', 'Service binds to all interfaces', SeverityLevel.LOW)
            ]
            
            for i, line in enumerate(lines, 1):
                for pattern, description, severity in insecure_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4()),
                            title="Insecure Configuration",
                            description=description,
                            severity=severity,
                            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                            file_path=str(config_file),
                            line_number=i,
                            code_snippet=line.strip(),
                            recommendation="Review and secure configuration settings"
                        ))
            
        except Exception as e:
            self.logger.error(f"Error reading {config_file}: {e}")
        
        return findings
    
    def _contains_secret(self, line: str) -> bool:
        """Check if line contains a secret."""
        secret_patterns = [
            r'(password|secret|key|token)\s*[:=]\s*["\']?[a-zA-Z0-9+/]{16,}["\']?',
            r'api[_-]key\s*[:=]\s*["\']?[a-zA-Z0-9_-]{16,}["\']?',
            r'private[_-]key\s*[:=]',
            r'(access|refresh)[_-]token\s*[:=]'
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        return False
    
    def _sanitize_secret_line(self, line: str) -> str:
        """Sanitize line containing secrets."""
        # Replace potential secrets with [REDACTED]
        sanitized = re.sub(
            r'([:=]\s*["\']?)[a-zA-Z0-9+/]{8,}(["\']?)',
            r'\1[REDACTED]\2',
            line
        )
        return sanitized.strip()


class SecurityAuditor:
    """Main security auditor orchestrating all security scans."""
    
    def __init__(self, config: Optional[AuditConfiguration] = None):
        """Initialize security auditor.
        
        Args:
            config: Audit configuration
        """
        self.config = config or AuditConfiguration()
        self.scanners: List[SecurityScanner] = []
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._setup_scanners()
    
    def _setup_scanners(self):
        """Setup available security scanners."""
        if self.config.enable_static_analysis:
            self.scanners.append(StaticCodeAnalyzer(self.config))
        
        if self.config.enable_dependency_scan:
            scanner = DependencyScanner(self.config)
            if scanner.is_available():
                self.scanners.append(scanner)
            else:
                self.logger.warning("Dependency scanner not available")
        
        if self.config.enable_configuration_check:
            self.scanners.append(ConfigurationScanner(self.config))
    
    async def audit(self, target_path: Path) -> AuditResult:
        """Perform comprehensive security audit.
        
        Args:
            target_path: Path to audit
            
        Returns:
            Audit results
        """
        audit_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        self.logger.info(f"Starting security audit {audit_id} for {target_path}")
        
        all_findings = []
        tools_used = []
        errors = []
        warnings = []
        total_files = 0
        total_lines = 0
        
        # Run scanners
        for scanner in self.scanners:
            try:
                self.logger.info(f"Running {scanner.scanner_name}")
                scanner_findings = await scanner.scan(target_path)
                all_findings.extend(scanner_findings)
                tools_used.append(scanner.scanner_name)
                
            except Exception as e:
                error_msg = f"Error running {scanner.scanner_name}: {e}"
                self.logger.error(error_msg)
                errors.append(error_msg)
        
        # Count files and lines
        if target_path.exists():
            total_files, total_lines = self._count_files_and_lines(target_path)
        
        # Filter findings by severity threshold
        filtered_findings = self._filter_findings(all_findings)
        
        # Limit findings if necessary
        if len(filtered_findings) > self.config.max_findings:
            warnings.append(f"Too many findings ({len(filtered_findings)}), limiting to {self.config.max_findings}")
            filtered_findings = filtered_findings[:self.config.max_findings]
        
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        result = AuditResult(
            audit_id=audit_id,
            start_time=start_time,
            end_time=end_time,
            configuration=self.config,
            findings=filtered_findings,
            total_files_scanned=total_files,
            total_lines_scanned=total_lines,
            tools_used=tools_used,
            scan_duration_seconds=scan_duration,
            errors=errors,
            warnings=warnings,
            metadata={
                'target_path': str(target_path),
                'scanner_count': len(self.scanners),
                'findings_before_filter': len(all_findings)
            }
        )
        
        self.logger.info(f"Security audit {audit_id} completed in {scan_duration:.2f}s with {len(filtered_findings)} findings")
        
        return result
    
    def _count_files_and_lines(self, target_path: Path) -> Tuple[int, int]:
        """Count files and lines in target."""
        total_files = 0
        total_lines = 0
        
        try:
            if target_path.is_file():
                if target_path.suffix == '.py':
                    total_files = 1
                    with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
                        total_lines = sum(1 for _ in f)
            else:
                for pattern in self.config.include_patterns:
                    for file_path in target_path.glob(pattern):
                        if not any(file_path.match(excl) for excl in self.config.exclude_patterns):
                            total_files += 1
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    total_lines += sum(1 for _ in f)
                            except Exception:
                                pass  # Skip files we can't read
        except Exception as e:
            self.logger.error(f"Error counting files and lines: {e}")
        
        return total_files, total_lines
    
    def _filter_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Filter findings by severity threshold."""
        severity_order = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }
        
        threshold_level = severity_order[self.config.severity_threshold]
        
        filtered = []
        for finding in findings:
            if not finding.suppressed and severity_order[finding.severity] >= threshold_level:
                filtered.append(finding)
        
        # Sort by severity (highest first)
        filtered.sort(key=lambda x: severity_order[x.severity], reverse=True)
        
        return filtered
    
    async def audit_shield(self, shield: Shield) -> AuditResult:
        """Audit a specific shield.
        
        Args:
            shield: Shield instance to audit
            
        Returns:
            Audit results
        """
        # Create temporary file with shield source
        shield_source = inspect.getsource(shield.__class__)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
            temp_file.write(shield_source)
            temp_file.flush()
            
            try:
                result = await self.audit(Path(temp_file.name))
                result.metadata['shield_class'] = shield.__class__.__name__
                result.metadata['shield_module'] = shield.__class__.__module__
                return result
            finally:
                os.unlink(temp_file.name)
    
    def generate_report(self, result: AuditResult, format_type: str = "json") -> str:
        """Generate audit report.
        
        Args:
            result: Audit result to generate report from
            format_type: Report format (json, html, text)
            
        Returns:
            Generated report as string
        """
        if format_type.lower() == "json":
            return self._generate_json_report(result)
        elif format_type.lower() == "html":
            return self._generate_html_report(result)
        elif format_type.lower() == "text":
            return self._generate_text_report(result)
        else:
            raise ValueError(f"Unsupported report format: {format_type}")
    
    def _generate_json_report(self, result: AuditResult) -> str:
        """Generate JSON report."""
        return json.dumps(result.to_dict(), indent=2, default=str)
    
    def _generate_html_report(self, result: AuditResult) -> str:
        """Generate HTML report."""
        stats = result.summary_stats
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report - {result.audit_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .findings {{ margin: 20px 0; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #28a745; }}
        .info {{ border-left: 5px solid #17a2b8; }}
        .code {{ background: #f8f9fa; padding: 10px; font-family: monospace; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Audit Report</h1>
        <p><strong>Audit ID:</strong> {result.audit_id}</p>
        <p><strong>Date:</strong> {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Duration:</strong> {result.scan_duration_seconds:.2f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Findings</td><td>{stats['total_findings']}</td></tr>
            <tr><td>Files Scanned</td><td>{stats['files_scanned']}</td></tr>
            <tr><td>Lines Scanned</td><td>{stats['lines_scanned']}</td></tr>
            <tr><td>Tools Used</td><td>{', '.join(stats['tools_used'])}</td></tr>
        </table>
        
        <h3>Findings by Severity</h3>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
        """
        
        for severity, count in stats['severity_breakdown'].items():
            html += f"<tr><td>{severity.title()}</td><td>{count}</td></tr>"
        
        html += """
        </table>
    </div>
    
    <div class="findings">
        <h2>Detailed Findings</h2>
        """
        
        for finding in result.findings:
            severity_class = finding.severity.value
            html += f"""
        <div class="finding {severity_class}">
            <h3>{finding.title}</h3>
            <p><strong>Severity:</strong> {finding.severity.value.upper()}</p>
            <p><strong>Type:</strong> {finding.vulnerability_type.value.replace('_', ' ').title()}</p>
            <p><strong>Description:</strong> {finding.description}</p>
            """
            
            if finding.file_path:
                html += f"<p><strong>File:</strong> {finding.file_path}"
                if finding.line_number:
                    html += f" (Line {finding.line_number})"
                html += "</p>"
            
            if finding.code_snippet:
                html += f'<div class="code">{finding.code_snippet}</div>'
            
            if finding.recommendation:
                html += f"<p><strong>Recommendation:</strong> {finding.recommendation}</p>"
            
            html += "</div>"
        
        html += """
    </div>
</body>
</html>
        """
        
        return html
    
    def _generate_text_report(self, result: AuditResult) -> str:
        """Generate text report."""
        stats = result.summary_stats
        
        report = f"""
SECURITY AUDIT REPORT
=====================

Audit ID: {result.audit_id}
Date: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}
Duration: {result.scan_duration_seconds:.2f} seconds

SUMMARY
-------
Total Findings: {stats['total_findings']}
Files Scanned: {stats['files_scanned']}
Lines Scanned: {stats['lines_scanned']}
Tools Used: {', '.join(stats['tools_used'])}

FINDINGS BY SEVERITY
--------------------
"""
        
        for severity, count in stats['severity_breakdown'].items():
            if count > 0:
                report += f"{severity.upper()}: {count}\n"
        
        report += "\nDETAILED FINDINGS\n"
        report += "-" * 17 + "\n"
        
        for i, finding in enumerate(result.findings, 1):
            report += f"\n{i}. {finding.title}\n"
            report += f"   Severity: {finding.severity.value.upper()}\n"
            report += f"   Type: {finding.vulnerability_type.value.replace('_', ' ').title()}\n"
            report += f"   Description: {finding.description}\n"
            
            if finding.file_path:
                location = finding.file_path
                if finding.line_number:
                    location += f":{finding.line_number}"
                report += f"   Location: {location}\n"
            
            if finding.code_snippet:
                report += f"   Code: {finding.code_snippet}\n"
            
            if finding.recommendation:
                report += f"   Recommendation: {finding.recommendation}\n"
        
        return report


# Convenience functions
async def audit_project(project_path: str, config: Optional[AuditConfiguration] = None) -> AuditResult:
    """Audit entire project.
    
    Args:
        project_path: Path to project directory
        config: Audit configuration
        
    Returns:
        Audit results
    """
    auditor = SecurityAuditor(config)
    return await auditor.audit(Path(project_path))


async def audit_shield(shield: Shield, config: Optional[AuditConfiguration] = None) -> AuditResult:
    """Audit specific shield.
    
    Args:
        shield: Shield to audit
        config: Audit configuration
        
    Returns:
        Audit results
    """
    auditor = SecurityAuditor(config)
    return await auditor.audit_shield(shield)


def create_audit_config(
    scope: AuditScope = AuditScope.FULL,
    severity_threshold: SeverityLevel = SeverityLevel.LOW,
    enable_penetration_testing: bool = False
) -> AuditConfiguration:
    """Create audit configuration.
    
    Args:
        scope: Audit scope
        severity_threshold: Minimum severity to report
        enable_penetration_testing: Enable penetration testing
        
    Returns:
        Audit configuration
    """
    return AuditConfiguration(
        scope=scope,
        severity_threshold=severity_threshold,
        enable_penetration_testing=enable_penetration_testing
    )