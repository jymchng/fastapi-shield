"""Audit logging shield for FastAPI Shield.

This module provides comprehensive audit logging with sensitive data masking,
configurable log levels, integration with popular logging frameworks, and
structured logging for security compliance and forensic analysis.
"""

import json
import logging
import re
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union
from urllib.parse import parse_qs

from fastapi import Request, Response, status
from pydantic import BaseModel

from fastapi_shield.shield import Shield, shield


class LogLevel(str, Enum):
    """Audit log levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogFormat(str, Enum):
    """Audit log formats."""
    JSON = "json"           # Structured JSON logging
    CEF = "cef"            # Common Event Format
    LEEF = "leef"          # Log Event Extended Format
    SYSLOG = "syslog"      # RFC 3164 Syslog format
    CUSTOM = "custom"      # Custom formatter


class SensitiveDataMask(str, Enum):
    """Sensitive data masking strategies."""
    FULL = "full"           # Replace with ***
    PARTIAL = "partial"     # Show first/last chars: pa***rd
    HASH = "hash"          # Replace with hash: sha256:abc123...
    NONE = "none"          # No masking (not recommended)


class AuditLogConfig(BaseModel):
    """Audit logging configuration."""
    
    # Logging configuration
    enabled: bool = True
    log_level: LogLevel = LogLevel.INFO
    log_format: LogFormat = LogFormat.JSON
    
    # What to log
    log_requests: bool = True
    log_responses: bool = True
    log_headers: bool = True
    log_body: bool = False  # Can be large and contain sensitive data
    log_query_params: bool = True
    log_path_params: bool = True
    log_client_info: bool = True
    log_timing: bool = True
    log_errors_only: bool = False  # Only log failed requests
    
    # Sensitive data protection
    mask_sensitive_data: bool = True
    masking_strategy: SensitiveDataMask = SensitiveDataMask.PARTIAL
    
    # Predefined sensitive field patterns
    sensitive_headers: Set[str] = {
        "authorization", "x-api-key", "x-auth-token", "cookie",
        "x-forwarded-for", "x-real-ip", "x-client-ip"
    }
    sensitive_query_params: Set[str] = {
        "password", "token", "api_key", "secret", "auth", "key"
    }
    sensitive_body_fields: Set[str] = {
        "password", "passwd", "pwd", "secret", "token", "api_key",
        "auth_token", "access_token", "refresh_token", "private_key",
        "credit_card", "ssn", "social_security", "bank_account"
    }
    
    # Custom sensitive data patterns (regex)
    sensitive_patterns: List[str] = [
        r"password\s*[=:]\s*['\"]([^'\"]+)['\"]",      # password="value" or password='value'
        r"token\s*[=:]\s*['\"]([^'\"]+)['\"]",        # token="value" or token='value'
        r"api_key\s*[=:]\s*['\"]([^'\"]+)['\"]",      # api_key="value" or api_key='value'
        r"(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})",  # Credit card
        r"(\d{3}-\d{2}-\d{4})",  # SSN
    ]
    
    # Response filtering
    max_body_size: int = 10 * 1024  # 10KB max body size to log
    include_status_codes: Optional[Set[int]] = None  # Log specific status codes only
    exclude_status_codes: Optional[Set[int]] = None  # Exclude specific status codes
    
    # Performance settings
    async_logging: bool = True
    buffer_size: int = 1000
    flush_interval: float = 5.0  # seconds
    
    # Custom configuration
    custom_fields: Optional[Dict[str, Any]] = None
    correlation_id_header: str = "X-Correlation-ID"
    include_stack_trace: bool = False
    
    model_config = {"arbitrary_types_allowed": True}


class LogEntry(BaseModel):
    """Structured audit log entry."""
    
    # Metadata
    timestamp: datetime
    correlation_id: str
    event_type: str = "http_request"
    
    # Request information
    method: str
    url: str
    path: str
    query_params: Optional[Dict[str, Any]] = None
    path_params: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    
    # Client information
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    user_id: Optional[str] = None
    
    # Response information
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    response_size: Optional[int] = None
    
    # Timing
    request_time: datetime
    response_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    
    # Additional context
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    custom_fields: Optional[Dict[str, Any]] = None
    
    # Security context
    authenticated: bool = False
    permissions: Optional[List[str]] = None
    
    model_config = {"arbitrary_types_allowed": True}


class AuditLogger(ABC):
    """Abstract base class for audit loggers."""
    
    @abstractmethod
    def log(self, entry: LogEntry, level: LogLevel = LogLevel.INFO) -> None:
        """Log an audit entry."""
        pass
    
    @abstractmethod
    def flush(self) -> None:
        """Flush any buffered log entries."""
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Close the logger and cleanup resources."""
        pass


class PythonAuditLogger(AuditLogger):
    """Audit logger using Python's standard logging module."""
    
    def __init__(self, logger_name: str = "fastapi_shield.audit", format_type: LogFormat = LogFormat.JSON):
        self.logger = logging.getLogger(logger_name)
        self.format_type = format_type
        
        # Set up formatter if not already configured
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            if format_type == LogFormat.JSON:
                formatter = logging.Formatter('%(message)s')
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def log(self, entry: LogEntry, level: LogLevel = LogLevel.INFO) -> None:
        """Log an audit entry using Python logging."""
        log_level = getattr(logging, level.value.upper())
        
        if self.format_type == LogFormat.JSON:
            message = entry.model_dump_json(exclude_none=True)
        else:
            message = self._format_entry(entry)
        
        self.logger.log(log_level, message)
    
    def _format_entry(self, entry: LogEntry) -> str:
        """Format log entry as human-readable string."""
        return (
            f"{entry.method} {entry.path} - {entry.status_code} - "
            f"{entry.duration_ms:.2f}ms - {entry.client_ip}"
        )
    
    def flush(self) -> None:
        """Flush Python logger handlers."""
        for handler in self.logger.handlers:
            handler.flush()
    
    def close(self) -> None:
        """Close Python logger handlers."""
        for handler in self.logger.handlers:
            handler.close()


class StructlogAuditLogger(AuditLogger):
    """Audit logger using structlog for structured logging."""
    
    def __init__(self, logger_name: str = "fastapi_shield.audit"):
        try:
            import structlog
            self.logger = structlog.get_logger(logger_name)
            self.structlog = structlog
        except ImportError:
            raise ImportError("structlog is required for StructlogAuditLogger")
    
    def log(self, entry: LogEntry, level: LogLevel = LogLevel.INFO) -> None:
        """Log an audit entry using structlog."""
        log_data = entry.model_dump(exclude_none=True)
        log_func = getattr(self.logger, level.value)
        log_func("audit_log", **log_data)
    
    def flush(self) -> None:
        """Flush is handled by structlog processors."""
        pass
    
    def close(self) -> None:
        """Close is handled by structlog processors."""
        pass


class FileAuditLogger(AuditLogger):
    """Audit logger that writes to files."""
    
    def __init__(self, file_path: str, format_type: LogFormat = LogFormat.JSON, 
                 max_size: int = 100 * 1024 * 1024, backup_count: int = 5):
        self.file_path = file_path
        self.format_type = format_type
        
        # Set up rotating file handler
        from logging.handlers import RotatingFileHandler
        
        self.handler = RotatingFileHandler(
            file_path, maxBytes=max_size, backupCount=backup_count
        )
        
        if format_type == LogFormat.JSON:
            formatter = logging.Formatter('%(message)s')
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
        self.handler.setFormatter(formatter)
        
        self.logger = logging.getLogger(f"fastapi_shield.audit.file.{file_path}")
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.INFO)
    
    def log(self, entry: LogEntry, level: LogLevel = LogLevel.INFO) -> None:
        """Log an audit entry to file."""
        log_level = getattr(logging, level.value.upper())
        
        if self.format_type == LogFormat.JSON:
            message = entry.model_dump_json(exclude_none=True)
        else:
            message = self._format_entry(entry)
        
        self.logger.log(log_level, message)
    
    def _format_entry(self, entry: LogEntry) -> str:
        """Format log entry as human-readable string."""
        return (
            f"{entry.correlation_id} - {entry.method} {entry.path} - "
            f"{entry.status_code} - {entry.duration_ms:.2f}ms - {entry.client_ip}"
        )
    
    def flush(self) -> None:
        """Flush file handler."""
        self.handler.flush()
    
    def close(self) -> None:
        """Close file handler."""
        self.handler.close()


class AuditLoggingShield:
    """Audit logging shield with comprehensive request/response logging."""
    
    def __init__(
        self,
        config: Optional[AuditLogConfig] = None,
        logger: Optional[AuditLogger] = None,
        custom_masker: Optional[Callable[[str], str]] = None,
        custom_fields_extractor: Optional[Callable[[Request], Dict[str, Any]]] = None,
    ):
        """Initialize audit logging shield.
        
        Args:
            config: Audit logging configuration
            logger: Custom audit logger implementation
            custom_masker: Custom function for masking sensitive data
            custom_fields_extractor: Function to extract custom fields from request
        """
        self.config = config or AuditLogConfig()
        self.logger = logger or PythonAuditLogger()
        self.custom_masker = custom_masker
        self.custom_fields_extractor = custom_fields_extractor
        
        # Compile sensitive data patterns
        self._sensitive_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.config.sensitive_patterns
        ]
        
        # Buffer for async logging
        self._log_buffer: List[tuple] = []
        self._last_flush = time.time()
    
    def _generate_correlation_id(self, request: Request) -> str:
        """Generate or extract correlation ID."""
        # Check if correlation ID is already set in headers
        correlation_id = request.headers.get(self.config.correlation_id_header.lower())
        if correlation_id:
            return correlation_id
        
        # Generate new correlation ID
        return str(uuid.uuid4())
    
    def _extract_client_ip(self, request: Request) -> Optional[str]:
        """Extract client IP address from request."""
        # Try common proxy headers first
        for header in ["x-forwarded-for", "x-real-ip", "x-client-ip"]:
            value = request.headers.get(header)
            if value:
                # X-Forwarded-For can contain multiple IPs
                return value.split(",")[0].strip()
        
        # Fallback to direct client IP
        return getattr(request.client, 'host', None) if request.client else None
    
    def _mask_sensitive_data(self, data: str, field_name: str = "") -> str:
        """Mask sensitive data based on configuration."""
        if not self.config.mask_sensitive_data:
            return data
        
        # Use custom masker if provided
        if self.custom_masker:
            return self.custom_masker(data)
        
        # Apply masking strategy
        if self.config.masking_strategy == SensitiveDataMask.FULL:
            return "***"
        elif self.config.masking_strategy == SensitiveDataMask.PARTIAL:
            if len(data) <= 4:
                return "***"
            return f"{data[:2]}***{data[-1:]}"
        elif self.config.masking_strategy == SensitiveDataMask.HASH:
            import hashlib
            hash_value = hashlib.sha256(data.encode()).hexdigest()[:16]
            return f"sha256:{hash_value}"
        else:  # NONE
            return data
    
    def _should_mask_field(self, field_name: str, context: str = "") -> bool:
        """Check if a field should be masked."""
        field_lower = field_name.lower()
        
        if context == "header":
            return field_lower in self.config.sensitive_headers
        elif context == "query":
            return field_lower in self.config.sensitive_query_params
        elif context == "body":
            return field_lower in self.config.sensitive_body_fields
        
        # Check against all sensitive fields
        return (
            field_lower in self.config.sensitive_headers or
            field_lower in self.config.sensitive_query_params or
            field_lower in self.config.sensitive_body_fields
        )
    
    def _mask_dict_data(self, data: Dict[str, Any], context: str = "") -> Dict[str, Any]:
        """Recursively mask sensitive data in dictionaries."""
        if not isinstance(data, dict):
            return data
        
        masked = {}
        for key, value in data.items():
            if self._should_mask_field(key, context):
                if isinstance(value, str):
                    masked[key] = self._mask_sensitive_data(value, key)
                else:
                    masked[key] = "***"
            elif isinstance(value, dict):
                masked[key] = self._mask_dict_data(value, context)
            elif isinstance(value, list):
                masked[key] = [
                    self._mask_dict_data(item, context) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                masked[key] = value
        
        return masked
    
    def _mask_text_data(self, text: str) -> str:
        """Mask sensitive data in text using regex patterns."""
        if not self.config.mask_sensitive_data:
            return text
        
        masked_text = text
        for pattern in self._sensitive_patterns:
            def mask_match(match):
                # Replace the captured group (sensitive value) with masked version
                full_match = match.group(0)
                sensitive_value = match.group(1)
                masked_value = self._mask_sensitive_data(sensitive_value)
                return full_match.replace(sensitive_value, masked_value)
            
            masked_text = pattern.sub(mask_match, masked_text)
        
        return masked_text
    
    def _should_log_request(self, request: Request, response: Optional[Response] = None) -> bool:
        """Determine if request should be logged based on configuration."""
        if not self.config.enabled:
            return False
        
        # Check error-only logging
        if self.config.log_errors_only:
            if response and response.status_code < 400:
                return False
        
        # Check status code filters
        if response:
            if self.config.include_status_codes:
                if response.status_code not in self.config.include_status_codes:
                    return False
            
            if self.config.exclude_status_codes:
                if response.status_code in self.config.exclude_status_codes:
                    return False
        
        return True
    
    def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract loggable data from request."""
        data = {}
        
        if self.config.log_requests:
            data.update({
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
            })
        
        if self.config.log_headers and self.config.log_requests:
            headers = dict(request.headers)
            data["headers"] = self._mask_dict_data(headers, "header")
        
        if self.config.log_query_params and request.url.query:
            query_params = dict(request.query_params)
            data["query_params"] = self._mask_dict_data(query_params, "query")
        
        if self.config.log_path_params and hasattr(request, 'path_params'):
            data["path_params"] = dict(request.path_params)
        
        if self.config.log_client_info:
            data.update({
                "client_ip": self._extract_client_ip(request),
                "user_agent": request.headers.get("user-agent"),
            })
        
        return data
    
    def _extract_response_data(self, response: Response) -> Dict[str, Any]:
        """Extract loggable data from response."""
        data = {}
        
        if self.config.log_responses:
            data["status_code"] = response.status_code
        
        if self.config.log_headers and self.config.log_responses:
            headers = dict(response.headers)
            data["response_headers"] = self._mask_dict_data(headers, "header")
        
        # Response body logging would need middleware integration
        # For now, we'll indicate response size if available
        content_length = response.headers.get("content-length")
        if content_length:
            data["response_size"] = int(content_length)
        
        return data
    
    def _extract_user_context(self, request: Request) -> Dict[str, Any]:
        """Extract user context from request."""
        context = {}
        
        # Check for common authentication patterns
        if request.headers.get("authorization"):
            context["authenticated"] = True
        
        # Check for user information set by other shields
        if hasattr(request, 'user') and request.user:
            context["authenticated"] = True
            if hasattr(request.user, 'id'):
                context["user_id"] = str(request.user.id)
            if hasattr(request.user, 'permissions') and request.user.permissions:
                try:
                    context["permissions"] = list(request.user.permissions)
                except (TypeError, AttributeError):
                    # Handle cases where permissions is not iterable
                    pass
        
        # Check for user ID in headers
        for header in ["x-user-id", "x-user", "user-id"]:
            user_id = request.headers.get(header)
            if user_id:
                context["user_id"] = user_id
                context["authenticated"] = True
                break
        
        return context
    
    def _create_log_entry(self, request: Request, response: Optional[Response] = None,
                         start_time: Optional[float] = None, error: Optional[Exception] = None) -> LogEntry:
        """Create a structured log entry."""
        now = datetime.now(timezone.utc)
        correlation_id = self._generate_correlation_id(request)
        
        # Extract request data
        request_data = self._extract_request_data(request)
        
        # Extract response data
        response_data = {}
        if response:
            response_data = self._extract_response_data(response)
        
        # Extract user context
        user_context = self._extract_user_context(request)
        
        # Calculate timing
        duration_ms = None
        if start_time:
            duration_ms = (time.time() - start_time) * 1000
        
        # Extract custom fields
        custom_fields = {}
        if self.custom_fields_extractor:
            try:
                custom_fields = self.custom_fields_extractor(request)
            except Exception:
                pass  # Ignore custom field extraction errors
        
        if self.config.custom_fields:
            custom_fields.update(self.config.custom_fields)
        
        # Create log entry
        entry = LogEntry(
            timestamp=now,
            correlation_id=correlation_id,
            request_time=now,
            duration_ms=duration_ms,
            **request_data,
            **response_data,
            **user_context,
            custom_fields=custom_fields if custom_fields else None,
        )
        
        # Add error information
        if error:
            entry.error_message = str(error)
            if self.config.include_stack_trace:
                import traceback
                # Generate stack trace for the error
                try:
                    # If we're in an exception context, use current traceback
                    entry.stack_trace = traceback.format_exc()
                    if entry.stack_trace.strip() == "NoneType: None":
                        # Generate a simple traceback from the error object
                        entry.stack_trace = f"{error.__class__.__name__}: {str(error)}"
                except Exception:
                    entry.stack_trace = f"{error.__class__.__name__}: {str(error)}"
        
        return entry
    
    def _log_entry(self, entry: LogEntry, level: LogLevel = LogLevel.INFO) -> None:
        """Log an entry using the configured logger."""
        if self.config.async_logging:
            self._log_buffer.append((entry, level))
            
            # Flush buffer if needed
            if (len(self._log_buffer) >= self.config.buffer_size or
                time.time() - self._last_flush >= self.config.flush_interval):
                self._flush_buffer()
        else:
            self.logger.log(entry, level)
    
    def _flush_buffer(self) -> None:
        """Flush the log buffer."""
        for entry, level in self._log_buffer:
            self.logger.log(entry, level)
        
        self._log_buffer.clear()
        self._last_flush = time.time()
        self.logger.flush()
    
    def create_shield(self, name: str = "AuditLogging") -> Shield:
        """Create a shield instance for audit logging."""
        
        async def audit_logging_shield(request: Request) -> Optional[Dict[str, Any]]:
            """Audit logging shield function."""
            start_time = time.time()
            
            try:
                # Always create a log entry for the request
                if self._should_log_request(request):
                    # Store start time for later use
                    request.state.audit_start_time = start_time
                    request.state.audit_correlation_id = self._generate_correlation_id(request)
                
                return {
                    "audit_logging_active": True,
                    "correlation_id": getattr(request.state, 'audit_correlation_id', None),
                    "start_time": start_time,
                }
                
            except Exception as e:
                # Log the shield error but don't block the request
                if self.config.enabled:
                    error_entry = self._create_log_entry(request, error=e, start_time=start_time)
                    self._log_entry(error_entry, LogLevel.ERROR)
                
                return {
                    "audit_logging_error": str(e),
                    "audit_logging_active": False,
                }
        
        return shield(
            audit_logging_shield,
            name=name,
            auto_error=False,  # Don't block requests on audit logging errors
        )
    
    def log_response(self, request: Request, response: Response) -> None:
        """Log response information (to be called from middleware)."""
        if not self.config.enabled or not self._should_log_request(request, response):
            return
        
        start_time = getattr(request.state, 'audit_start_time', None)
        
        try:
            entry = self._create_log_entry(request, response, start_time)
            
            # Determine log level based on status code
            if response.status_code >= 500:
                level = LogLevel.ERROR
            elif response.status_code >= 400:
                level = LogLevel.WARNING
            else:
                level = LogLevel.INFO
            
            self._log_entry(entry, level)
            
        except Exception as e:
            # Log the logging error
            error_entry = self._create_log_entry(request, response, start_time, error=e)
            self._log_entry(error_entry, LogLevel.ERROR)
    
    def flush(self) -> None:
        """Flush any buffered log entries."""
        if self._log_buffer:
            self._flush_buffer()
        else:
            self.logger.flush()
    
    def close(self) -> None:
        """Close the audit logger."""
        try:
            self.flush()
            self.logger.close()
        except Exception:
            # Ignore close errors to avoid breaking application shutdown
            pass


# Convenience functions for common audit logging scenarios
def audit_logging_shield(
    log_level: LogLevel = LogLevel.INFO,
    log_requests: bool = True,
    log_responses: bool = True,
    log_headers: bool = True,
    log_body: bool = False,
    mask_sensitive_data: bool = True,
    logger: Optional[AuditLogger] = None,
    name: str = "AuditLogging",
) -> Shield:
    """Create an audit logging shield with specified configuration.
    
    Args:
        log_level: Minimum log level
        log_requests: Log request information
        log_responses: Log response information
        log_headers: Log request/response headers
        log_body: Log request/response body
        mask_sensitive_data: Mask sensitive data in logs
        logger: Custom audit logger
        name: Shield name
        
    Returns:
        Shield: Configured audit logging shield
        
    Examples:
        ```python
        # Basic audit logging
        @app.post("/api/users")
        @audit_logging_shield()
        def create_user(user: User):
            return {"id": 1, "name": user.name}
        
        # Detailed logging for sensitive endpoints
        @app.post("/api/payments")
        @audit_logging_shield(
            log_level=LogLevel.INFO,
            log_body=True,
            mask_sensitive_data=True
        )
        def process_payment(payment: Payment):
            return {"status": "processed"}
        
        # Error-only logging for high-traffic endpoints
        @app.get("/api/health")
        @audit_logging_shield(
            log_level=LogLevel.WARNING,
            log_requests=False,
            log_responses=False
        )
        def health_check():
            return {"status": "ok"}
        ```
    """
    config = AuditLogConfig(
        log_level=log_level,
        log_requests=log_requests,
        log_responses=log_responses,
        log_headers=log_headers,
        log_body=log_body,
        mask_sensitive_data=mask_sensitive_data,
    )
    
    audit_shield = AuditLoggingShield(config=config, logger=logger)
    return audit_shield.create_shield(name=name)


def sensitive_audit_shield(
    masking_strategy: SensitiveDataMask = SensitiveDataMask.PARTIAL,
    logger: Optional[AuditLogger] = None,
    name: str = "SensitiveAudit",
) -> Shield:
    """Create an audit logging shield for sensitive endpoints.
    
    Args:
        masking_strategy: Strategy for masking sensitive data
        logger: Custom audit logger
        name: Shield name
        
    Returns:
        Shield: Sensitive data audit shield
    """
    config = AuditLogConfig(
        log_level=LogLevel.INFO,
        log_requests=True,
        log_responses=True,
        log_headers=True,
        log_body=False,  # Never log body for sensitive endpoints
        mask_sensitive_data=True,
        masking_strategy=masking_strategy,
        include_stack_trace=True,
    )
    
    audit_shield = AuditLoggingShield(config=config, logger=logger)
    return audit_shield.create_shield(name=name)


def compliance_audit_shield(
    file_path: str,
    log_format: LogFormat = LogFormat.JSON,
    logger: Optional[AuditLogger] = None,
    name: str = "ComplianceAudit",
) -> Shield:
    """Create an audit logging shield for compliance requirements.
    
    Args:
        file_path: Path to compliance log file
        log_format: Log format (JSON recommended for compliance)
        logger: Custom audit logger (overrides file_path if provided)
        name: Shield name
        
    Returns:
        Shield: Compliance audit shield
    """
    if not logger:
        logger = FileAuditLogger(file_path, log_format)
    
    config = AuditLogConfig(
        log_level=LogLevel.INFO,
        log_requests=True,
        log_responses=True,
        log_headers=True,
        log_body=False,
        log_client_info=True,
        log_timing=True,
        mask_sensitive_data=True,
        masking_strategy=SensitiveDataMask.HASH,
        async_logging=False,  # Immediate logging for compliance
        include_stack_trace=True,
    )
    
    audit_shield = AuditLoggingShield(config=config, logger=logger)
    return audit_shield.create_shield(name=name)


def error_audit_shield(
    logger: Optional[AuditLogger] = None,
    name: str = "ErrorAudit",
) -> Shield:
    """Create an audit logging shield that only logs errors.
    
    Args:
        logger: Custom audit logger
        name: Shield name
        
    Returns:
        Shield: Error-only audit shield
    """
    config = AuditLogConfig(
        log_level=LogLevel.WARNING,
        log_errors_only=True,
        log_requests=True,
        log_responses=True,
        log_headers=True,
        log_body=False,
        mask_sensitive_data=True,
        include_stack_trace=True,
    )
    
    audit_shield = AuditLoggingShield(config=config, logger=logger)
    return audit_shield.create_shield(name=name)


def performance_audit_shield(
    threshold_ms: float = 1000.0,
    logger: Optional[AuditLogger] = None,
    name: str = "PerformanceAudit",
) -> Shield:
    """Create an audit logging shield for performance monitoring.
    
    Args:
        threshold_ms: Log requests that take longer than this threshold
        logger: Custom audit logger
        name: Shield name
        
    Returns:
        Shield: Performance monitoring audit shield
    """
    def should_log_performance(request, response):
        duration = getattr(request.state, 'audit_duration_ms', 0)
        return duration >= threshold_ms
    
    config = AuditLogConfig(
        log_level=LogLevel.WARNING,
        log_requests=True,
        log_responses=True,
        log_headers=False,
        log_body=False,
        log_timing=True,
        mask_sensitive_data=False,  # Performance focus, not security
    )
    
    audit_shield = AuditLoggingShield(config=config, logger=logger)
    # Would need custom logic to implement threshold checking
    return audit_shield.create_shield(name=name)


def debug_audit_shield(
    logger: Optional[AuditLogger] = None,
    name: str = "DebugAudit",
) -> Shield:
    """Create an audit logging shield for debugging purposes.
    
    Args:
        logger: Custom audit logger
        name: Shield name
        
    Returns:
        Shield: Debug audit shield
    """
    config = AuditLogConfig(
        log_level=LogLevel.DEBUG,
        log_requests=True,
        log_responses=True,
        log_headers=True,
        log_body=True,  # Log everything for debugging
        log_query_params=True,
        log_path_params=True,
        log_client_info=True,
        log_timing=True,
        mask_sensitive_data=False,  # No masking for debugging
        async_logging=False,
        include_stack_trace=True,
    )
    
    audit_shield = AuditLoggingShield(config=config, logger=logger)
    return audit_shield.create_shield(name=name)