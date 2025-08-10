"""SQL Injection detection shield for FastAPI Shield.

This module provides comprehensive SQL injection detection capabilities to identify
and block potential SQL injection attacks in request parameters, form data, JSON
payloads, and URL paths. It includes pattern-based detection, payload analysis,
and configurable response policies.
"""

import json
import re
import time
import urllib.parse
from collections import defaultdict
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple, Union
from urllib.parse import parse_qs, unquote

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from fastapi_shield.shield import Shield, shield


class DetectionLevel(str, Enum):
    """SQL injection detection sensitivity levels."""
    LOW = "low"        # Only obvious injection patterns
    MEDIUM = "medium"  # Standard patterns and variations  
    HIGH = "high"      # Aggressive detection including edge cases
    PARANOID = "paranoid"  # Maximum sensitivity with false positive risk


class SQLDialect(str, Enum):
    """SQL dialect variations for pattern matching."""
    GENERIC = "generic"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"


class InjectionType(str, Enum):
    """Types of SQL injection patterns."""
    UNION_BASED = "union_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    BLIND = "blind"
    STACKED_QUERIES = "stacked_queries"
    COMMENT_INJECTION = "comment_injection"
    FUNCTION_CALLS = "function_calls"
    SYSTEM_COMMANDS = "system_commands"
    INFORMATION_SCHEMA = "information_schema"


class ActionPolicy(str, Enum):
    """Actions to take when SQL injection is detected."""
    LOG_ONLY = "log_only"
    BLOCK = "block"
    SANITIZE = "sanitize"
    ALERT = "alert"


class SQLInjectionConfig(BaseModel):
    """Configuration for SQL injection detection."""
    
    # Detection settings
    detection_level: DetectionLevel = DetectionLevel.MEDIUM
    sql_dialects: List[SQLDialect] = Field(default_factory=lambda: [SQLDialect.GENERIC])
    
    # Pattern matching
    case_sensitive: bool = False
    decode_url: bool = True
    decode_html: bool = True
    decode_base64: bool = True
    normalize_whitespace: bool = True
    max_payload_length: int = Field(default=10000, gt=0)
    
    # Detection scope
    check_query_params: bool = True
    check_form_data: bool = True
    check_json_data: bool = True
    check_path_params: bool = True
    check_headers: bool = False
    header_whitelist: List[str] = Field(default_factory=lambda: ["user-agent", "referer"])
    
    # Response policy
    default_action: ActionPolicy = ActionPolicy.LOG_ONLY
    injection_type_actions: Dict[InjectionType, ActionPolicy] = Field(default_factory=dict)
    
    # Performance settings
    max_patterns_per_check: int = Field(default=100, gt=0)
    enable_caching: bool = True
    cache_ttl_seconds: int = Field(default=300, gt=0)
    
    # Logging and monitoring
    log_all_detections: bool = True
    log_sanitized_payloads: bool = False
    include_request_details: bool = True
    alert_threshold: int = Field(default=5, gt=0)  # Alerts after N detections
    
    # Rate limiting integration
    track_source_ips: bool = True
    suspicious_ip_threshold: int = Field(default=10, gt=0)
    ip_block_duration_minutes: int = Field(default=60, gt=0)
    
    # Custom patterns
    custom_patterns: List[str] = Field(default_factory=list)
    whitelist_patterns: List[str] = Field(default_factory=list)
    
    @field_validator('custom_patterns', 'whitelist_patterns')
    @classmethod
    def validate_patterns(cls, v):
        """Validate regex patterns."""
        valid_patterns = []
        for pattern in v:
            try:
                re.compile(pattern)
                valid_patterns.append(pattern)
            except re.error:
                # Skip invalid patterns instead of raising an error
                continue
        return valid_patterns


class InjectionDetection(BaseModel):
    """SQL injection detection result."""
    
    detected: bool
    injection_type: Optional[InjectionType] = None
    confidence_score: float = Field(ge=0.0, le=1.0)
    matched_patterns: List[str] = Field(default_factory=list)
    payload: str = ""
    sanitized_payload: Optional[str] = None
    source_location: str = ""  # query_params, form_data, json_data, etc.
    parameter_name: Optional[str] = None
    detection_level: DetectionLevel
    sql_dialect: Optional[SQLDialect] = None
    action_taken: ActionPolicy
    timestamp: float = Field(default_factory=time.time)
    request_id: Optional[str] = None


class SQLPatternLibrary:
    """Library of SQL injection detection patterns."""
    
    def __init__(self):
        """Initialize pattern library."""
        self.patterns: Dict[InjectionType, Dict[DetectionLevel, List[Pattern]]] = defaultdict(lambda: defaultdict(list))
        self.dialect_patterns: Dict[SQLDialect, Dict[InjectionType, List[Pattern]]] = defaultdict(lambda: defaultdict(list))
        self._initialize_patterns()
    
    def _initialize_patterns(self) -> None:
        """Initialize built-in SQL injection patterns."""
        
        # UNION-based injection patterns
        union_patterns = {
            DetectionLevel.LOW: [
                r'\bunion\s+select\b',
                r'\bunion\s+all\s+select\b',
            ],
            DetectionLevel.MEDIUM: [
                r'\bunion\s+select\b',
                r'\bunion\s+all\s+select\b',
                r'\bunion\s*\(\s*select\b',
                r'\/\*.*\*\/\s*union\s+select',
                r'union\s+select.*from\s+information_schema',
            ],
            DetectionLevel.HIGH: [
                r'\bunion\s+select\b',
                r'\bunion\s+all\s+select\b',
                r'\bunion\s*\(\s*select\b',
                r'\/\*.*\*\/\s*union\s+select',
                r'union\s+select.*from\s+information_schema',
                r'union\s+select.*null.*null',
                r'union.*select.*char\(',
                r'union.*select.*unhex\(',
                r'union.*select.*0x[0-9a-f]+',
            ],
            DetectionLevel.PARANOID: [
                r'\bunion\s+select\b',
                r'\bunion\s+all\s+select\b',
                r'\bunion\s*\(\s*select\b',
                r'\/\*.*\*\/\s*union\s+select',
                r'union\s+select.*from\s+information_schema',
                r'union\s+select.*null.*null',
                r'union.*select.*char\(',
                r'union.*select.*unhex\(',
                r'union.*select.*0x[0-9a-f]+',
                r'un\w*ion\s+se\w*lect',  # Obfuscated
                r'u\s*n\s*i\s*o\s*n\s+s\s*e\s*l\s*e\s*c\s*t',  # Spaced
            ]
        }
        
        # Boolean-based injection patterns
        boolean_patterns = {
            DetectionLevel.LOW: [
                r"'\s*or\s*'1'\s*=\s*'1",
                r"'\s*or\s*1\s*=\s*1\s*--",
                r"admin'\s*--",
            ],
            DetectionLevel.MEDIUM: [
                r"'\s*or\s*'1'\s*=\s*'1",
                r"'\s*or\s*1\s*=\s*1\s*--",
                r"admin'\s*--",
                r"'\s*or\s*'.*'\s*=\s*'.*",
                r"'\s*and\s*'1'\s*=\s*'2",
                r"'\s*or\s+1\s*=\s*1\s*(#|--|\s|$)",
                r"\bor\s+1\s*=\s*1\b",
                r"\band\s+1\s*=\s*1\b",
            ],
            DetectionLevel.HIGH: [
                r"'\s*or\s*'1'\s*=\s*'1",
                r"'\s*or\s*1\s*=\s*1\s*--",
                r"admin'\s*--",
                r"'\s*or\s*'.*'\s*=\s*'.*",
                r"'\s*and\s*'1'\s*=\s*'2",
                r"'\s*or\s+1\s*=\s*1\s*(#|--|\s|$)",
                r"\bor\s+1\s*=\s*1\b",
                r"\band\s+1\s*=\s*1\b",
                r"'\s*or\s*\d+\s*=\s*\d+",
                r"\"\s*or\s*\d+\s*=\s*\d+",
                r"\bor\s+\d+\s*[<>=]+\s*\d+",
                r"'\s*or\s+'.*'\s*like\s+'.*",
            ],
            DetectionLevel.PARANOID: [
                r"'\s*or\s*'1'\s*=\s*'1",
                r"'\s*or\s*1\s*=\s*1\s*--",
                r"admin'\s*--",
                r"'\s*or\s*'.*'\s*=\s*'.*",
                r"'\s*and\s*'1'\s*=\s*'2",
                r"'\s*or\s+1\s*=\s*1\s*(#|--|\s|$)",
                r"\bor\s+1\s*=\s*1\b",
                r"\band\s+1\s*=\s*1\b",
                r"'\s*or\s*\d+\s*=\s*\d+",
                r"\"\s*or\s*\d+\s*=\s*\d+",
                r"\bor\s+\d+\s*[<>=]+\s*\d+",
                r"'\s*or\s+'.*'\s*like\s+'.*",
                r"or\s+.*\s*=\s*.*\s+and",
                r"'\s*o\s*r\s*'",  # Spaced
                r"'\s*O\s*R\s*'",  # Case variations
            ]
        }
        
        # Time-based injection patterns
        time_patterns = {
            DetectionLevel.LOW: [
                r"\bsleep\s*\(\s*\d+\s*\)",
                r"\bwaitfor\s+delay\s+",
            ],
            DetectionLevel.MEDIUM: [
                r"\bsleep\s*\(\s*\d+\s*\)",
                r"\bwaitfor\s+delay\s+",
                r"\bbenchmark\s*\(\s*\d+",
                r"\bpg_sleep\s*\(\s*\d+\s*\)",
                r"\bdbms_lock\.sleep\s*\(\s*\d+\s*\)",
            ],
            DetectionLevel.HIGH: [
                r"\bsleep\s*\(\s*\d+\s*\)",
                r"\bwaitfor\s+delay\s+",
                r"\bbenchmark\s*\(\s*\d+",
                r"\bpg_sleep\s*\(\s*\d+\s*\)",
                r"\bdbms_lock\.sleep\s*\(\s*\d+\s*\)",
                r"sleep\s*\(\s*\d*\.\d+\s*\)",
                r"waitfor\s+time\s+",
                r"generate_series\s*\(\s*1\s*,\s*\d+",
            ],
            DetectionLevel.PARANOID: [
                r"\bsleep\s*\(\s*\d+\s*\)",
                r"\bwaitfor\s+delay\s+",
                r"\bbenchmark\s*\(\s*\d+",
                r"\bpg_sleep\s*\(\s*\d+\s*\)",
                r"\bdbms_lock\.sleep\s*\(\s*\d+\s*\)",
                r"sleep\s*\(\s*\d*\.\d+\s*\)",
                r"waitfor\s+time\s+",
                r"generate_series\s*\(\s*1\s*,\s*\d+",
                r"if\s*\(.*,\s*sleep\s*\(\s*\d+",
                r"case\s+when.*then\s+sleep\s*\(",
            ]
        }
        
        # Error-based injection patterns
        error_patterns = {
            DetectionLevel.LOW: [
                r"extractvalue\s*\(\s*1\s*,",
                r"updatexml\s*\(\s*1\s*,",
            ],
            DetectionLevel.MEDIUM: [
                r"extractvalue\s*\(\s*1\s*,",
                r"updatexml\s*\(\s*1\s*,",
                r"exp\s*\(\s*~\s*\(",
                r"\bcast\s*\(\s*.*\s+as\s+int\s*\)",
                r"convert\s*\(\s*int\s*,",
            ],
            DetectionLevel.HIGH: [
                r"extractvalue\s*\(\s*1\s*,",
                r"updatexml\s*\(\s*1\s*,",
                r"exp\s*\(\s*~\s*\(",
                r"\bcast\s*\(\s*.*\s+as\s+int\s*\)",
                r"convert\s*\(\s*int\s*,",
                r"xmltype\s*\(\s*.*\s*\)\.extract",
                r"utl_inaddr\.get_host_name",
                r"ctxsys\.drithsx\.sn",
            ],
            DetectionLevel.PARANOID: [
                r"extractvalue\s*\(\s*1\s*,",
                r"updatexml\s*\(\s*1\s*,",
                r"exp\s*\(\s*~\s*\(",
                r"\bcast\s*\(\s*.*\s+as\s+int\s*\)",
                r"convert\s*\(\s*int\s*,",
                r"xmltype\s*\(\s*.*\s*\)\.extract",
                r"utl_inaddr\.get_host_name",
                r"ctxsys\.drithsx\.sn",
                r"floor\s*\(\s*rand\s*\(\s*0\s*\)\s*\*\s*2\s*\)",
                r"pow\s*\(\s*9\s*,\s*9\s*,\s*9\s*\)",
            ]
        }
        
        # Stacked queries patterns
        stacked_patterns = {
            DetectionLevel.LOW: [
                r";\s*drop\s+table",
                r";\s*delete\s+from",
            ],
            DetectionLevel.MEDIUM: [
                r";\s*drop\s+table",
                r";\s*delete\s+from",
                r";\s*insert\s+into",
                r";\s*update\s+.*\s+set",
                r";\s*create\s+table",
                r";\s*alter\s+table",
            ],
            DetectionLevel.HIGH: [
                r";\s*drop\s+table",
                r";\s*delete\s+from",
                r";\s*insert\s+into",
                r";\s*update\s+.*\s+set",
                r";\s*create\s+table",
                r";\s*alter\s+table",
                r";\s*truncate\s+table",
                r";\s*exec\s*\(",
                r";\s*execute\s+",
                r";\s*sp_",
                r";\s*xp_",
            ],
            DetectionLevel.PARANOID: [
                r";\s*drop\s+table",
                r";\s*delete\s+from",
                r";\s*insert\s+into",
                r";\s*update\s+.*\s+set",
                r";\s*create\s+table",
                r";\s*alter\s+table",
                r";\s*truncate\s+table",
                r";\s*exec\s*\(",
                r";\s*execute\s+",
                r";\s*sp_",
                r";\s*xp_",
                r";\s*grant\s+",
                r";\s*revoke\s+",
                r";\s*shutdown\s*;",
            ]
        }
        
        # Comment injection patterns
        comment_patterns = {
            DetectionLevel.LOW: [
                r"--\s*$",
                r"\/\*.*\*\/",
            ],
            DetectionLevel.MEDIUM: [
                r"--\s*$",
                r"\/\*.*\*\/",
                r"#.*$",
                r"--\s+.*",
                r"\/\*.*\*\/.*",
            ],
            DetectionLevel.HIGH: [
                r"--\s*$",
                r"\/\*.*\*\/",
                r"#.*$",
                r"--\s+.*",
                r"\/\*.*\*\/.*",
                r"\/\*\!\d+.*\*\/",
                r"--\+",
                r"#\s*\d+",
            ],
            DetectionLevel.PARANOID: [
                r"--\s*$",
                r"\/\*.*\*\/",
                r"#.*$",
                r"--\s+.*",
                r"\/\*.*\*\/.*",
                r"\/\*\!\d+.*\*\/",
                r"--\+",
                r"#\s*\d+",
                r"\/\*\!\s*\d*.*\*\/",
                r"--\s*[a-zA-Z]",
            ]
        }
        
        # Function calls patterns
        function_patterns = {
            DetectionLevel.LOW: [
                r"\bversion\s*\(\s*\)",
                r"\buser\s*\(\s*\)",
            ],
            DetectionLevel.MEDIUM: [
                r"\bversion\s*\(\s*\)",
                r"\buser\s*\(\s*\)",
                r"\bdatabase\s*\(\s*\)",
                r"\bschema\s*\(\s*\)",
                r"\bchar\s*\(\s*\d+",
                r"\bconcat\s*\(",
            ],
            DetectionLevel.HIGH: [
                r"\bversion\s*\(\s*\)",
                r"\buser\s*\(\s*\)",
                r"\bdatabase\s*\(\s*\)",
                r"\bschema\s*\(\s*\)",
                r"\bchar\s*\(\s*\d+",
                r"\bconcat\s*\(",
                r"\bsubstring\s*\(",
                r"\blength\s*\(",
                r"\bassii\s*\(",
                r"\bhex\s*\(",
                r"\bunhex\s*\(",
            ],
            DetectionLevel.PARANOID: [
                r"\bversion\s*\(\s*\)",
                r"\buser\s*\(\s*\)",
                r"\bdatabase\s*\(\s*\)",
                r"\bschema\s*\(\s*\)",
                r"\bchar\s*\(\s*\d+",
                r"\bconcat\s*\(",
                r"\bsubstring\s*\(",
                r"\blength\s*\(",
                r"\bassii\s*\(",
                r"\bhex\s*\(",
                r"\bunhex\s*\(",
                r"\bmid\s*\(",
                r"\bright\s*\(",
                r"\bleft\s*\(",
                r"\bload_file\s*\(",
            ]
        }
        
        # System commands patterns
        system_patterns = {
            DetectionLevel.LOW: [
                r"\binto\s+outfile\s+",
                r"\binto\s+dumpfile\s+",
            ],
            DetectionLevel.MEDIUM: [
                r"\binto\s+outfile\s+",
                r"\binto\s+dumpfile\s+",
                r"\bload_file\s*\(",
                r"\bsystem\s*\(",
                r"exec\s+master\.dbo\.xp_cmdshell",
            ],
            DetectionLevel.HIGH: [
                r"\binto\s+outfile\s+",
                r"\binto\s+dumpfile\s+",
                r"\bload_file\s*\(",
                r"\bsystem\s*\(",
                r"exec\s+master\.dbo\.xp_cmdshell",
                r"xp_cmdshell\s*\(",
                r"sp_makewebtask",
                r"sp_addextendedproc",
            ],
            DetectionLevel.PARANOID: [
                r"\binto\s+outfile\s+",
                r"\binto\s+dumpfile\s+",
                r"\bload_file\s*\(",
                r"\bsystem\s*\(",
                r"exec\s+master\.dbo\.xp_cmdshell",
                r"xp_cmdshell\s*\(",
                r"sp_makewebtask",
                r"sp_addextendedproc",
                r"sp_oacreate",
                r"utl_file",
                r"dbms_java",
            ]
        }
        
        # Information schema patterns
        info_patterns = {
            DetectionLevel.LOW: [
                r"\binformation_schema\.",
            ],
            DetectionLevel.MEDIUM: [
                r"\binformation_schema\.",
                r"\bmysql\.",
                r"\bpg_",
                r"\bsys\.",
            ],
            DetectionLevel.HIGH: [
                r"\binformation_schema\.",
                r"\bmysql\.",
                r"\bpg_",
                r"\bsys\.",
                r"\ball_tables",
                r"\ball_columns",
                r"\buser_tables",
                r"\buser_tab_columns",
            ],
            DetectionLevel.PARANOID: [
                r"\binformation_schema\.",
                r"\bmysql\.",
                r"\bpg_",
                r"\bsys\.",
                r"\ball_tables",
                r"\ball_columns",
                r"\buser_tables",
                r"\buser_tab_columns",
                r"\bsysobjects",
                r"\bsyscolumns",
                r"\bmaster\.",
                r"\bmsdb\.",
            ]
        }
        
        # Compile patterns for each injection type and level
        pattern_sets = {
            InjectionType.UNION_BASED: union_patterns,
            InjectionType.BOOLEAN_BASED: boolean_patterns,
            InjectionType.TIME_BASED: time_patterns,
            InjectionType.ERROR_BASED: error_patterns,
            InjectionType.STACKED_QUERIES: stacked_patterns,
            InjectionType.COMMENT_INJECTION: comment_patterns,
            InjectionType.FUNCTION_CALLS: function_patterns,
            InjectionType.SYSTEM_COMMANDS: system_patterns,
            InjectionType.INFORMATION_SCHEMA: info_patterns,
        }
        
        for injection_type, level_patterns in pattern_sets.items():
            for level, patterns in level_patterns.items():
                compiled_patterns = []
                for pattern in patterns:
                    try:
                        compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                        compiled_patterns.append(compiled)
                    except re.error:
                        continue  # Skip invalid patterns
                
                self.patterns[injection_type][level] = compiled_patterns
    
    def get_patterns(self, injection_type: InjectionType, level: DetectionLevel) -> List[Pattern]:
        """Get compiled patterns for injection type and detection level.
        
        Args:
            injection_type: Type of SQL injection
            level: Detection sensitivity level
            
        Returns:
            List of compiled regex patterns
        """
        patterns = []
        
        # Get patterns for current level
        patterns.extend(self.patterns[injection_type][level])
        
        # Include patterns from lower levels
        if level in [DetectionLevel.MEDIUM, DetectionLevel.HIGH, DetectionLevel.PARANOID]:
            patterns.extend(self.patterns[injection_type][DetectionLevel.LOW])
        
        if level in [DetectionLevel.HIGH, DetectionLevel.PARANOID]:
            patterns.extend(self.patterns[injection_type][DetectionLevel.MEDIUM])
        
        if level == DetectionLevel.PARANOID:
            patterns.extend(self.patterns[injection_type][DetectionLevel.HIGH])
        
        return patterns
    
    def get_all_patterns(self, level: DetectionLevel) -> Dict[InjectionType, List[Pattern]]:
        """Get all patterns for a detection level.
        
        Args:
            level: Detection sensitivity level
            
        Returns:
            Dictionary of injection types to pattern lists
        """
        all_patterns = {}
        
        for injection_type in InjectionType:
            all_patterns[injection_type] = self.get_patterns(injection_type, level)
        
        return all_patterns


class SQLInjectionDetector:
    """SQL injection detection engine."""
    
    def __init__(self, config: SQLInjectionConfig):
        """Initialize SQL injection detector.
        
        Args:
            config: Detection configuration
        """
        self.config = config
        self.pattern_library = SQLPatternLibrary()
        self.detection_cache: Dict[str, Tuple[InjectionDetection, float]] = {}
        self.ip_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'detections': 0,
            'first_seen': time.time(),
            'last_detection': 0,
            'blocked': False,
            'block_until': 0
        })
        
        # Compile custom patterns
        self.custom_patterns: List[Pattern] = []
        self.whitelist_patterns: List[Pattern] = []
        
        for pattern in config.custom_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE if not config.case_sensitive else 0)
                self.custom_patterns.append(compiled)
            except re.error:
                continue
        
        for pattern in config.whitelist_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE if not config.case_sensitive else 0)
                self.whitelist_patterns.append(compiled)
            except re.error:
                continue
    
    def _normalize_payload(self, payload: str) -> str:
        """Normalize payload for better detection.
        
        Args:
            payload: Raw payload string
            
        Returns:
            Normalized payload
        """
        normalized = payload
        
        # URL decode
        if self.config.decode_url:
            try:
                normalized = unquote(normalized)
                # Handle double encoding
                if '%' in normalized:
                    normalized = unquote(normalized)
            except Exception:
                pass
        
        # HTML decode
        if self.config.decode_html:
            html_entities = {
                '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"',
                '&#39;': "'", '&#x27;': "'", '&#x2F;': '/', '&#x60;': '`',
                '&apos;': "'", '&#x3C;': '<', '&#x3E;': '>', '&#47;': '/',
                '&#42;': '*'  # Add asterisk entity
            }
            for entity, char in html_entities.items():
                normalized = normalized.replace(entity, char)
        
        # Base64 decode (try if it looks like base64)
        if self.config.decode_base64 and len(normalized) > 4:
            try:
                import base64
                # Simple heuristic for base64
                if re.match(r'^[A-Za-z0-9+/]*={0,2}$', normalized) and len(normalized) % 4 == 0:
                    decoded = base64.b64decode(normalized).decode('utf-8', errors='ignore')
                    if len(decoded) > 0:
                        normalized += ' ' + decoded  # Add to original for analysis
            except Exception:
                pass
        
        # Normalize whitespace
        if self.config.normalize_whitespace:
            normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        return normalized
    
    def _check_whitelist(self, payload: str) -> bool:
        """Check if payload matches whitelist patterns.
        
        Args:
            payload: Payload to check
            
        Returns:
            True if payload is whitelisted
        """
        for pattern in self.whitelist_patterns:
            if pattern.search(payload):
                return True
        return False
    
    def _calculate_confidence(self, matches: List[Tuple[InjectionType, str]]) -> float:
        """Calculate confidence score based on matches.
        
        Args:
            matches: List of (injection_type, matched_pattern) tuples
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not matches:
            return 0.0
        
        # Base confidence based on number of matches
        base_confidence = min(len(matches) * 0.2, 0.8)
        
        # Boost confidence for high-risk injection types
        high_risk_types = {
            InjectionType.UNION_BASED,
            InjectionType.STACKED_QUERIES,
            InjectionType.SYSTEM_COMMANDS,
            InjectionType.INFORMATION_SCHEMA
        }
        
        risk_boost = 0.0
        for injection_type, _ in matches:
            if injection_type in high_risk_types:
                risk_boost += 0.1
        
        confidence = min(base_confidence + risk_boost, 1.0)
        
        # Adjust based on detection level
        if self.config.detection_level == DetectionLevel.PARANOID:
            confidence *= 0.8  # Reduce confidence for paranoid level due to higher false positives
        elif self.config.detection_level == DetectionLevel.LOW:
            confidence *= 1.2  # Increase confidence for low level (fewer false positives)
        
        return min(confidence, 1.0)
    
    def _detect_injection_patterns(self, payload: str) -> List[Tuple[InjectionType, str]]:
        """Detect SQL injection patterns in payload.
        
        Args:
            payload: Normalized payload to analyze
            
        Returns:
            List of (injection_type, pattern) matches
        """
        matches = []
        all_patterns = self.pattern_library.get_all_patterns(self.config.detection_level)
        
        patterns_checked = 0
        for injection_type, patterns in all_patterns.items():
            if patterns_checked >= self.config.max_patterns_per_check:
                break
            
            for pattern in patterns:
                if patterns_checked >= self.config.max_patterns_per_check:
                    break
                
                patterns_checked += 1
                if pattern.search(payload):
                    matches.append((injection_type, pattern.pattern))
                    # Don't break - collect all matches for better confidence calculation
        
        # Check custom patterns
        for pattern in self.custom_patterns:
            if patterns_checked >= self.config.max_patterns_per_check:
                break
            
            patterns_checked += 1
            if pattern.search(payload):
                matches.append((InjectionType.BLIND, pattern.pattern))
        
        return matches
    
    def _sanitize_payload(self, payload: str) -> str:
        """Sanitize malicious SQL injection payload.
        
        Args:
            payload: Original payload
            
        Returns:
            Sanitized payload
        """
        sanitized = payload
        
        # Remove common SQL injection patterns
        dangerous_patterns = [
            (r'union\s+select', 'UNION_BLOCKED'),
            (r';\s*drop\s+table', ';BLOCKED'),
            (r';\s*delete\s+from', ';BLOCKED'),
            (r';\s*insert\s+into', ';BLOCKED'),
            (r';\s*update\s+.*set', ';BLOCKED'),
            (r"'\s*or\s*'1'\s*=\s*'1", "'BLOCKED'"),
            (r"'\s*or\s*1\s*=\s*1", "'BLOCKED'"),
            (r'--.*$', ''),
            (r'\/\*.*\*\/', ''),
            (r'#.*$', ''),
        ]
        
        for pattern, replacement in dangerous_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def detect(self, payload: str, source_location: str, parameter_name: Optional[str] = None) -> InjectionDetection:
        """Detect SQL injection in payload.
        
        Args:
            payload: Payload to analyze
            source_location: Source of payload (query_params, form_data, etc.)
            parameter_name: Name of parameter containing payload
            
        Returns:
            Injection detection result
        """
        # Check cache first
        if self.config.enable_caching:
            cache_key = f"{payload}:{source_location}:{parameter_name}"
            if cache_key in self.detection_cache:
                cached_result, timestamp = self.detection_cache[cache_key]
                if time.time() - timestamp < self.config.cache_ttl_seconds:
                    return cached_result
        
        # Truncate overly long payloads
        if len(payload) > self.config.max_payload_length:
            payload = payload[:self.config.max_payload_length]
        
        # Normalize payload
        normalized_payload = self._normalize_payload(payload)
        
        # Check whitelist
        if self._check_whitelist(normalized_payload):
            result = InjectionDetection(
                detected=False,
                confidence_score=0.0,
                payload=payload,
                source_location=source_location,
                parameter_name=parameter_name,
                detection_level=self.config.detection_level,
                action_taken=ActionPolicy.LOG_ONLY
            )
            
            # Cache result
            if self.config.enable_caching:
                self.detection_cache[cache_key] = (result, time.time())
            
            return result
        
        # Detect injection patterns
        matches = self._detect_injection_patterns(normalized_payload)
        
        if not matches:
            result = InjectionDetection(
                detected=False,
                confidence_score=0.0,
                payload=payload,
                source_location=source_location,
                parameter_name=parameter_name,
                detection_level=self.config.detection_level,
                action_taken=ActionPolicy.LOG_ONLY
            )
        else:
            # Determine primary injection type (first match or highest priority)
            primary_type = matches[0][0]
            confidence = self._calculate_confidence(matches)
            
            # Determine action - check injection type specific actions first, then default
            action = self.config.injection_type_actions.get(primary_type, self.config.default_action)
            
            # Sanitize if needed
            sanitized_payload = None
            if action == ActionPolicy.SANITIZE:
                sanitized_payload = self._sanitize_payload(payload)
            
            result = InjectionDetection(
                detected=True,
                injection_type=primary_type,
                confidence_score=confidence,
                matched_patterns=[match[1] for match in matches[:10]],  # Limit to 10 patterns
                payload=payload,
                sanitized_payload=sanitized_payload,
                source_location=source_location,
                parameter_name=parameter_name,
                detection_level=self.config.detection_level,
                action_taken=action
            )
        
        # Cache result
        if self.config.enable_caching:
            self.detection_cache[cache_key] = (result, time.time())
        
        return result
    
    def analyze_request(self, request: Request) -> List[InjectionDetection]:
        """Analyze entire request for SQL injection attempts.
        
        Args:
            request: FastAPI request object
            
        Returns:
            List of injection detections
        """
        detections = []
        
        # Check query parameters
        if self.config.check_query_params and request.query_params:
            for param_name, param_value in request.query_params.items():
                if param_value:
                    detection = self.detect(param_value, "query_params", param_name)
                    if detection.detected:
                        detections.append(detection)
        
        # Check path parameters
        if self.config.check_path_params and hasattr(request, 'path_params'):
            try:
                for param_name, param_value in request.path_params.items():
                    if param_value:
                        detection = self.detect(str(param_value), "path_params", param_name)
                        if detection.detected:
                            detections.append(detection)
            except (AttributeError, TypeError):
                # Handle cases where path_params is not iterable or doesn't exist
                pass
        
        # Check headers
        if self.config.check_headers:
            for header_name, header_value in request.headers.items():
                if (header_name.lower() in self.config.header_whitelist and
                    header_value):
                    detection = self.detect(header_value, "headers", header_name)
                    if detection.detected:
                        detections.append(detection)
        
        return detections
    
    async def analyze_request_body(self, request: Request) -> List[InjectionDetection]:
        """Analyze request body for SQL injection attempts.
        
        Args:
            request: FastAPI request object
            
        Returns:
            List of injection detections
        """
        detections = []
        
        try:
            # Check form data
            if self.config.check_form_data and request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                try:
                    form = await request.form()
                    for field_name, field_value in form.items():
                        if field_value and isinstance(field_value, str):
                            detection = self.detect(field_value, "form_data", field_name)
                            if detection.detected:
                                detections.append(detection)
                except Exception:
                    pass
            
            # Check JSON data
            elif self.config.check_json_data and request.headers.get("content-type", "").startswith("application/json"):
                try:
                    json_data = await request.json()
                    self._analyze_json_recursive(json_data, detections)
                except Exception:
                    pass
            
        except Exception:
            # If body was already consumed, skip body analysis
            pass
        
        return detections
    
    def _analyze_json_recursive(self, data: Any, detections: List[InjectionDetection], path: str = "json_data") -> None:
        """Recursively analyze JSON data for injections.
        
        Args:
            data: JSON data to analyze
            detections: List to append detections to
            path: Current JSON path
        """
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}"
                if isinstance(value, str):
                    detection = self.detect(value, "json_data", new_path)
                    if detection.detected:
                        detections.append(detection)
                else:
                    self._analyze_json_recursive(value, detections, new_path)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{path}[{i}]"
                if isinstance(item, str):
                    detection = self.detect(item, "json_data", new_path)
                    if detection.detected:
                        detections.append(detection)
                else:
                    self._analyze_json_recursive(item, detections, new_path)
    
    def track_ip_activity(self, ip_address: str, detections: List[InjectionDetection]) -> bool:
        """Track IP address activity and determine if it should be blocked.
        
        Args:
            ip_address: Client IP address
            detections: List of detections for this request
            
        Returns:
            True if IP should be blocked
        """
        if not self.config.track_source_ips:
            return False
        
        current_time = time.time()
        ip_data = self.ip_stats[ip_address]
        
        # Check if IP is currently blocked
        if ip_data['blocked'] and current_time < ip_data['block_until']:
            return True
        elif ip_data['blocked'] and current_time >= ip_data['block_until']:
            # Unblock IP
            ip_data['blocked'] = False
            ip_data['detections'] = 0
        
        # Update stats
        if detections:
            ip_data['detections'] += len(detections)
            ip_data['last_detection'] = current_time
            
            # Check if threshold exceeded
            if ip_data['detections'] >= self.config.suspicious_ip_threshold:
                ip_data['blocked'] = True
                ip_data['block_until'] = current_time + (self.config.ip_block_duration_minutes * 60)
                return True
        
        return False


class SQLInjectionShield:
    """SQL injection detection shield for FastAPI endpoints."""
    
    def __init__(self, config: SQLInjectionConfig):
        """Initialize SQL injection shield.
        
        Args:
            config: SQL injection detection configuration
        """
        self.config = config
        self.detector = SQLInjectionDetector(config)
    
    def create_shield(self, name: str = "SQLInjectionDetection") -> Shield:
        """Create a shield for SQL injection detection.
        
        Args:
            name: Shield name
            
        Returns:
            Shield instance
        """
        
        async def sql_injection_shield(request: Request) -> Dict[str, Any]:
            """SQL injection detection shield function."""
            
            # Get client IP
            client_ip = self._get_client_ip(request)
            
            # Check if IP is blocked
            if self.detector.track_ip_activity(client_ip, []):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="IP address temporarily blocked due to suspicious activity",
                    headers={"X-Block-Reason": "sql_injection_attempts"}
                )
            
            # Analyze request
            detections = self.detector.analyze_request(request)
            
            # Analyze request body if needed
            if (self.config.check_form_data or self.config.check_json_data):
                body_detections = await self.detector.analyze_request_body(request)
                detections.extend(body_detections)
            
            # Track IP activity
            should_block_ip = self.detector.track_ip_activity(client_ip, detections)
            
            # Handle detections
            blocked_detections = []
            for detection in detections:
                if detection.action_taken == ActionPolicy.BLOCK:
                    blocked_detections.append(detection)
            
            # Block request if any detection requires blocking
            if blocked_detections:
                detail = f"SQL injection attempt detected: {blocked_detections[0].injection_type.value}"
                if len(blocked_detections) > 1:
                    detail += f" (and {len(blocked_detections) - 1} other attempts)"
                
                headers = {
                    "X-Injection-Type": blocked_detections[0].injection_type.value,
                    "X-Detection-Count": str(len(detections)),
                    "X-Confidence": f"{blocked_detections[0].confidence_score:.2f}"
                }
                
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=detail,
                    headers=headers
                )
            
            # Block IP if threshold exceeded
            if should_block_ip:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many SQL injection attempts from this IP",
                    headers={"X-Block-Reason": "injection_threshold_exceeded"}
                )
            
            # Return detection results
            result = {
                "sql_injection_detection_passed": True,
                "detections_count": len(detections),
                "blocked_count": len(blocked_detections),
                "client_ip": client_ip,
                "detections": [
                    {
                        "type": d.injection_type.value if d.injection_type else "unknown",
                        "confidence": d.confidence_score,
                        "source": d.source_location,
                        "parameter": d.parameter_name,
                        "action": d.action_taken.value
                    }
                    for d in detections
                ],
            }
            
            # Add sanitized payloads if any
            sanitized_payloads = {}
            for detection in detections:
                if detection.sanitized_payload and detection.parameter_name:
                    sanitized_payloads[detection.parameter_name] = detection.sanitized_payload
            
            if sanitized_payloads:
                result["sanitized_payloads"] = sanitized_payloads
            
            return result
        
        return shield(
            sql_injection_shield,
            name=name,
            auto_error=True,
        )
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Client IP address
        """
        # Check for forwarded headers (in order of preference)
        forwarded_headers = [
            'x-forwarded-for',
            'x-real-ip',
            'cf-connecting-ip',  # Cloudflare
            'x-client-ip',
            'forwarded'
        ]
        
        for header in forwarded_headers:
            if header in request.headers:
                ip = request.headers[header].split(',')[0].strip()
                if ip and ip != 'unknown':
                    return ip
        
        # Fallback to client host
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return 'unknown'


def sql_injection_detection_shield(
    detection_level: DetectionLevel = DetectionLevel.MEDIUM,
    action_policy: ActionPolicy = ActionPolicy.LOG_ONLY,
    check_query_params: bool = True,
    check_form_data: bool = True,
    check_json_data: bool = True,
    name: str = "SQLInjectionDetection",
) -> Shield:
    """Create a SQL injection detection shield.
    
    Args:
        detection_level: Detection sensitivity level
        action_policy: Default action for detected injections
        check_query_params: Whether to check query parameters
        check_form_data: Whether to check form data
        check_json_data: Whether to check JSON data
        name: Shield name
        
    Returns:
        SQL injection detection shield
        
    Examples:
        ```python
        # Basic SQL injection detection
        @app.get("/api/data")
        @sql_injection_detection_shield()
        def get_data(query: str):
            return {"query": query}
        
        # Strict detection that blocks suspicious requests
        @app.post("/api/search")
        @sql_injection_detection_shield(
            detection_level=DetectionLevel.HIGH,
            action_policy=ActionPolicy.BLOCK
        )
        def search_data(search_term: str):
            return {"results": []}
        
        # Paranoid detection for sensitive endpoints
        @app.post("/admin/query")
        @sql_injection_detection_shield(
            detection_level=DetectionLevel.PARANOID,
            action_policy=ActionPolicy.BLOCK
        )
        def admin_query(sql: str):
            return {"executed": True}
        ```
    """
    config = SQLInjectionConfig(
        detection_level=detection_level,
        default_action=action_policy,
        check_query_params=check_query_params,
        check_form_data=check_form_data,
        check_json_data=check_json_data,
    )
    
    shield_instance = SQLInjectionShield(config)
    return shield_instance.create_shield(name)


def strict_sql_injection_shield(
    name: str = "StrictSQLInjectionDetection",
) -> Shield:
    """Create a strict SQL injection detection shield.
    
    Args:
        name: Shield name
        
    Returns:
        Strict SQL injection detection shield
        
    Examples:
        ```python
        @app.post("/api/sensitive")
        @strict_sql_injection_shield()
        def sensitive_endpoint(data: dict):
            return {"processed": True}
        ```
    """
    config = SQLInjectionConfig(
        detection_level=DetectionLevel.HIGH,
        default_action=ActionPolicy.BLOCK,
        check_query_params=True,
        check_form_data=True,
        check_json_data=True,
        check_headers=True,
        track_source_ips=True,
        suspicious_ip_threshold=3,
        ip_block_duration_minutes=30,
    )
    
    shield_instance = SQLInjectionShield(config)
    return shield_instance.create_shield(name)


def monitoring_sql_injection_shield(
    name: str = "MonitoringSQLInjection",
) -> Shield:
    """Create a monitoring-focused SQL injection detection shield.
    
    Args:
        name: Shield name
        
    Returns:
        Monitoring SQL injection detection shield
        
    Examples:
        ```python
        @app.get("/api/public")
        @monitoring_sql_injection_shield()
        def public_endpoint(query: str):
            return {"data": "public"}
        ```
    """
    config = SQLInjectionConfig(
        detection_level=DetectionLevel.MEDIUM,
        default_action=ActionPolicy.LOG_ONLY,
        log_all_detections=True,
        include_request_details=True,
        track_source_ips=True,
        alert_threshold=3,
        check_query_params=True,
        check_form_data=True,
        check_json_data=True,
    )
    
    shield_instance = SQLInjectionShield(config)
    return shield_instance.create_shield(name)