"""Content-Type validation shield for FastAPI Shield.

This module provides comprehensive content-type validation to prevent MIME type
confusion attacks, enforce strict content-type policies, and validate file uploads.
It includes protection against MIME type sniffing and supports configurable
validation rules per endpoint.
"""

import mimetypes
import re
from cgi import parse_header
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Set, Union

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field

from fastapi_shield.shield import Shield, shield


class ContentTypePolicy(str, Enum):
    """Content-Type validation policies."""
    STRICT = "strict"          # Exact match required
    PERMISSIVE = "permissive"  # Allow subtypes and parameters
    PATTERN = "pattern"        # Regex pattern matching


class SecurityLevel(str, Enum):
    """Security levels for content-type validation."""
    LOW = "low"        # Basic validation
    MEDIUM = "medium"  # Standard security checks
    HIGH = "high"      # Strict security with MIME sniffing prevention
    PARANOID = "paranoid"  # Maximum security with comprehensive validation


class ContentTypeConfig(BaseModel):
    """Configuration for content-type validation."""
    
    # Allowed content types
    allowed_types: List[str] = Field(default_factory=lambda: ["application/json"])
    
    # Validation policy
    policy: ContentTypePolicy = ContentTypePolicy.STRICT
    
    # Security level
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    
    # Character set validation
    allowed_charsets: Optional[List[str]] = Field(default_factory=lambda: ["utf-8", "utf-16", "ascii"])
    require_charset: bool = False
    
    # File upload validation
    max_file_size: Optional[int] = None  # bytes
    allowed_file_extensions: Optional[List[str]] = None
    forbidden_file_extensions: List[str] = Field(default_factory=lambda: [
        ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js", ".jar"
    ])
    
    # MIME sniffing prevention
    prevent_mime_sniffing: bool = True
    validate_file_signature: bool = True  # Check magic bytes
    
    # Custom validation patterns
    custom_patterns: Optional[List[str]] = None  # Regex patterns
    
    # Boundary validation for multipart
    validate_multipart_boundary: bool = True
    max_boundary_length: int = 70
    
    # Error handling
    custom_error_message: Optional[str] = None
    include_security_headers: bool = True
    
    model_config = {"arbitrary_types_allowed": True}


class ContentTypeValidationResult(BaseModel):
    """Result of content-type validation."""
    
    valid: bool
    content_type: Optional[str] = None
    main_type: Optional[str] = None
    sub_type: Optional[str] = None
    charset: Optional[str] = None
    boundary: Optional[str] = None
    file_extension: Optional[str] = None
    file_signature: Optional[str] = None
    security_issues: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    
    model_config = {"arbitrary_types_allowed": True}


# Common MIME type groups for convenience
MIME_TYPE_GROUPS = {
    "json": ["application/json"],
    "xml": ["application/xml", "text/xml"],
    "text": ["text/plain", "text/html", "text/csv"],
    "images": ["image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"],
    "documents": ["application/pdf", "application/msword", 
                  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    "archives": ["application/zip", "application/x-tar", "application/gzip"],
    "audio": ["audio/mpeg", "audio/wav", "audio/ogg"],
    "video": ["video/mp4", "video/mpeg", "video/quicktime"],
    "form": ["application/x-www-form-urlencoded", "multipart/form-data"],
    "binary": ["application/octet-stream"],
}

# File signature patterns (magic bytes) for common file types
FILE_SIGNATURES = {
    b'\xFF\xD8\xFF': 'image/jpeg',
    b'\x89PNG\r\n\x1A\n': 'image/png',
    b'GIF87a': 'image/gif',
    b'GIF89a': 'image/gif',
    b'%PDF-': 'application/pdf',
    b'PK\x03\x04': 'application/zip',
    b'PK\x05\x06': 'application/zip',
    b'PK\x07\x08': 'application/zip',
    b'\x1F\x8B\x08': 'application/gzip',
    b'BM': 'image/bmp',
    b'RIFF': 'audio/wav',  # Also used by AVI
    b'\x00\x00\x00\x18ftypmp4': 'video/mp4',
    b'\x00\x00\x00\x20ftypmp4': 'video/mp4',
}


class ContentTypeValidator:
    """Content-Type validation with security checks."""
    
    def __init__(self, config: ContentTypeConfig):
        """Initialize content-type validator.
        
        Args:
            config: Content-type validation configuration
        """
        self.config = config
        self._compiled_patterns: Optional[List[Pattern]] = None
        self._initialize_patterns()
    
    def _initialize_patterns(self) -> None:
        """Initialize regex patterns for custom validation."""
        if self.config.custom_patterns:
            self._compiled_patterns = []
            for pattern in self.config.custom_patterns:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    self._compiled_patterns.append(compiled)
                except re.error as e:
                    raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
    
    def _parse_content_type(self, content_type_header: str) -> Dict[str, str]:
        """Parse content-type header into components.
        
        Args:
            content_type_header: Raw content-type header value
            
        Returns:
            Dictionary with parsed components
        """
        if not content_type_header or not content_type_header.strip():
            raise ValueError("Content-type header is empty")
        
        try:
            main_type, params = parse_header(content_type_header)
            
            if not main_type:
                raise ValueError("Content-type header is invalid")
            
            # Split main type into type and subtype
            if '/' in main_type:
                type_part, subtype_part = main_type.split('/', 1)
            else:
                type_part, subtype_part = main_type, ''
            
            return {
                'content_type': main_type.lower(),
                'type': type_part.lower(),
                'subtype': subtype_part.lower(),
                'charset': params.get('charset', '').lower(),
                'boundary': params.get('boundary', ''),
                'params': params
            }
        except Exception as e:
            raise ValueError(f"Invalid content-type header: {e}")
    
    def _validate_charset(self, charset: str) -> List[str]:
        """Validate character set.
        
        Args:
            charset: Character set to validate
            
        Returns:
            List of validation issues
        """
        issues = []
        
        if self.config.require_charset and not charset:
            issues.append("Character set is required but not specified")
        
        if charset and self.config.allowed_charsets:
            if charset not in self.config.allowed_charsets:
                issues.append(f"Character set '{charset}' is not allowed. "
                             f"Allowed: {', '.join(self.config.allowed_charsets)}")
        
        return issues
    
    def _validate_boundary(self, boundary: str) -> List[str]:
        """Validate multipart boundary.
        
        Args:
            boundary: Multipart boundary to validate
            
        Returns:
            List of validation issues
        """
        issues = []
        
        if not self.config.validate_multipart_boundary:
            return issues
        
        if boundary:
            # Check boundary length first
            if len(boundary) > self.config.max_boundary_length:
                issues.append(f"Boundary too long: {len(boundary)} > {self.config.max_boundary_length}")
                return issues  # Return early for critical issues
            
            # Check for potential injection patterns
            suspicious_patterns = ['<', '>', '"', "'", '&', '\n', '\r', '\0']
            for pattern in suspicious_patterns:
                if pattern in boundary:
                    issues.append(f"Boundary contains suspicious character: '{pattern}'")
                    return issues  # Return early for security issues
            
            # Check for suspicious characters (general pattern)
            if not re.match(r'^[a-zA-Z0-9\-_=+/]+$', boundary):
                issues.append("Boundary contains suspicious characters")
        
        return issues
    
    def _check_file_extension(self, content_type: str, filename: Optional[str] = None) -> List[str]:
        """Check file extension against allowed/forbidden lists.
        
        Args:
            content_type: MIME type
            filename: Optional filename for extension checking
            
        Returns:
            List of security issues
        """
        issues = []
        
        if not filename:
            return issues
        
        # Extract extension
        if '.' in filename:
            extension = '.' + filename.split('.')[-1].lower()
        else:
            return issues
        
        # Check forbidden extensions first (security priority)
        if extension in self.config.forbidden_file_extensions:
            issues.append(f"File extension '{extension}' is forbidden for security reasons")
            return issues  # Return early for security issues
        
        # Check allowed extensions if specified
        if self.config.allowed_file_extensions:
            if extension not in self.config.allowed_file_extensions:
                issues.append(f"File extension '{extension}' is not in allowed list")
        
        return issues
    
    def _detect_file_signature(self, content: bytes) -> Optional[str]:
        """Detect file type from magic bytes.
        
        Args:
            content: File content bytes
            
        Returns:
            Detected MIME type or None
        """
        if not content:
            return None
        
        for signature, mime_type in FILE_SIGNATURES.items():
            if content.startswith(signature):
                return mime_type
        
        # Special case for RIFF files (WAV/AVI)
        if content.startswith(b'RIFF') and len(content) > 11:
            if content[8:12] == b'WAVE':
                return 'audio/wav'
            elif content[8:12] == b'AVI ':
                return 'video/avi'
        
        return None
    
    def _validate_file_signature(self, declared_type: str, content: bytes) -> List[str]:
        """Validate file signature against declared content type.
        
        Args:
            declared_type: Declared MIME type
            content: File content
            
        Returns:
            List of security issues
        """
        issues = []
        
        if not self.config.validate_file_signature or not content:
            return issues
        
        detected_type = self._detect_file_signature(content)
        
        if detected_type and detected_type != declared_type:
            # Check for dangerous mismatches
            dangerous_mismatches = [
                ('application/octet-stream', 'image/'),
                ('text/', 'image/'),
                ('application/json', 'image/'),
            ]
            
            for declared_pattern, detected_pattern in dangerous_mismatches:
                if (declared_type.startswith(declared_pattern) and 
                    detected_type.startswith(detected_pattern)):
                    issues.append(f"Dangerous MIME type mismatch: declared '{declared_type}' "
                                 f"but detected '{detected_type}' from file signature")
                    break
            else:
                # Non-dangerous mismatch - just a warning
                issues.append(f"MIME type mismatch: declared '{declared_type}' "
                             f"but detected '{detected_type}' from file signature")
        
        return issues
    
    def _check_mime_sniffing_risks(self, content_type: str, content: bytes) -> List[str]:
        """Check for MIME sniffing security risks.
        
        Args:
            content_type: Declared content type
            content: Content bytes
            
        Returns:
            List of security warnings
        """
        warnings = []
        
        if not self.config.prevent_mime_sniffing:
            return warnings
        
        content_lower = content.lower() if content else b''
        
        # Check for SVG with scripts first (specific case)
        if content_type == 'image/svg+xml' and b'<script' in content_lower:
            warnings.append("SVG contains script elements - potential XSS risk")
            return warnings  # Return early for this specific case
        
        # Check for potentially executable content in non-HTML types
        if not content_type.startswith(('text/html', 'application/xhtml')):
            executable_patterns = [
                b'<script',
                b'javascript:',
                b'data:text/html',
                b'<?xml',
                b'<!DOCTYPE html',
                b'<html',
            ]
            
            for pattern in executable_patterns:
                if pattern in content_lower:
                    warnings.append(f"Content contains potentially executable code: {pattern.decode('utf-8', errors='ignore')}")
                    return warnings  # Return early after finding first issue
        
        return warnings
    
    def _match_custom_patterns(self, content_type: str) -> bool:
        """Check if content type matches custom patterns.
        
        Args:
            content_type: Content type to check
            
        Returns:
            True if matches any custom pattern
        """
        if not self._compiled_patterns:
            return False
        
        return any(pattern.match(content_type) for pattern in self._compiled_patterns)
    
    def _is_type_allowed(self, content_type: str) -> bool:
        """Check if content type is allowed based on policy.
        
        Args:
            content_type: Content type to check
            
        Returns:
            True if allowed
        """
        if self.config.policy == ContentTypePolicy.PATTERN:
            return self._match_custom_patterns(content_type)
        
        for allowed_type in self.config.allowed_types:
            if self.config.policy == ContentTypePolicy.STRICT:
                if content_type == allowed_type:
                    return True
            elif self.config.policy == ContentTypePolicy.PERMISSIVE:
                # Allow subtypes and ignore parameters
                if content_type.startswith(allowed_type.split(';')[0]):
                    return True
        
        return False
    
    async def validate_content_type(
        self, 
        request: Request,
        content: Optional[bytes] = None,
        filename: Optional[str] = None
    ) -> ContentTypeValidationResult:
        """Validate content-type header and content.
        
        Args:
            request: FastAPI request object
            content: Optional content bytes for signature validation
            filename: Optional filename for extension checking
            
        Returns:
            Validation result
        """
        result = ContentTypeValidationResult(valid=False)
        
        try:
            # Get content-type header
            content_type_header = request.headers.get('content-type')
            if not content_type_header:
                result.error_message = "Content-Type header is required"
                return result
            
            # Parse content-type
            try:
                parsed = self._parse_content_type(content_type_header)
                result.content_type = parsed['content_type']
                result.main_type = parsed['type']
                result.sub_type = parsed['subtype']
                result.charset = parsed['charset']
                result.boundary = parsed['boundary']
            except ValueError as e:
                result.error_message = str(e)
                return result
            
            # Check if type is allowed
            if not self._is_type_allowed(result.content_type):
                result.error_message = f"Content-Type '{result.content_type}' is not allowed"
                return result
            
            # Validate charset
            charset_issues = self._validate_charset(result.charset or '')
            result.security_issues.extend(charset_issues)
            
            # Validate boundary for multipart
            if result.content_type.startswith('multipart/'):
                boundary_issues = self._validate_boundary(result.boundary or '')
                result.security_issues.extend(boundary_issues)
            
            # File extension validation
            if filename:
                result.file_extension = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
                extension_issues = self._check_file_extension(result.content_type, filename)
                result.security_issues.extend(extension_issues)
            
            # Content-based validation
            if content:
                # File signature validation
                signature_issues = self._validate_file_signature(result.content_type, content)
                result.security_issues.extend(signature_issues)
                
                # MIME sniffing risks
                sniffing_warnings = self._check_mime_sniffing_risks(result.content_type, content)
                result.warnings.extend(sniffing_warnings)
                
                # Detect file signature
                detected_signature = self._detect_file_signature(content)
                if detected_signature:
                    result.file_signature = detected_signature
            
            # Check security level compliance
            if self.config.security_level == SecurityLevel.PARANOID:
                if result.security_issues or result.warnings:
                    result.error_message = "Paranoid security level: no issues allowed"
                    return result
            elif self.config.security_level == SecurityLevel.HIGH:
                # High security fails on critical security issues and warnings
                critical_keywords = ['dangerous', 'forbidden', 'executable', 'script', 'xss']
                for issue in result.security_issues + result.warnings:
                    if any(keyword in issue.lower() for keyword in critical_keywords):
                        result.error_message = f"High security violation: {issue}"
                        return result
            elif self.config.security_level == SecurityLevel.MEDIUM:
                # Medium security fails on hard security violations but allows warnings
                if result.security_issues:
                    result.error_message = f"Security violation: {result.security_issues[0]}"
                    return result
            
            # Success if we get here
            result.valid = True
            
        except Exception as e:
            result.error_message = f"Validation error: {str(e)}"
        
        return result


class ContentTypeShield:
    """Content-Type validation shield for FastAPI endpoints."""
    
    def __init__(self, config: ContentTypeConfig):
        """Initialize content-type shield.
        
        Args:
            config: Content-type validation configuration
        """
        self.config = config
        self.validator = ContentTypeValidator(config)
    
    def create_shield(self, name: str = "ContentTypeValidation") -> Shield:
        """Create a shield for content-type validation.
        
        Args:
            name: Shield name
            
        Returns:
            Shield instance
        """
        
        async def content_type_shield(request: Request) -> Dict[str, Any]:
            """Content-Type validation shield function."""
            
            # Get content if needed for validation
            content = None
            if (self.config.validate_file_signature or 
                self.config.prevent_mime_sniffing or 
                self.config.security_level in [SecurityLevel.HIGH, SecurityLevel.PARANOID]):
                try:
                    content = await request.body()
                    # Store for potential reuse
                    request._body = content
                except Exception:
                    content = None
            
            # Extract filename from various sources
            filename = None
            
            # Try Content-Disposition header first
            content_disposition = request.headers.get('content-disposition')
            if content_disposition:
                try:
                    _, params = parse_header(content_disposition)
                    filename = params.get('filename')
                except Exception:
                    pass
            
            # Try URL path for filename
            if not filename and request.url.path:
                path_parts = request.url.path.split('/')
                if path_parts and '.' in path_parts[-1]:
                    filename = path_parts[-1]
            
            # Validate content-type
            result = await self.validator.validate_content_type(request, content, filename)
            
            if not result.valid:
                error_message = (self.config.custom_error_message or 
                               result.error_message or 
                               "Content-Type validation failed")
                
                # Add security headers if configured
                headers = {}
                if self.config.include_security_headers:
                    headers.update({
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "DENY",
                        "X-XSS-Protection": "1; mode=block"
                    })
                
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail=error_message,
                    headers=headers if headers else None
                )
            
            # Return validation result and metadata
            return {
                "content_type_valid": True,
                "content_type": result.content_type,
                "main_type": result.main_type,
                "sub_type": result.sub_type,
                "charset": result.charset,
                "validation_result": result,
                "security_warnings": result.warnings,
            }
        
        return shield(
            content_type_shield,
            name=name,
            auto_error=True,
        )


def content_type_shield(
    allowed_types: List[str],
    policy: ContentTypePolicy = ContentTypePolicy.STRICT,
    security_level: SecurityLevel = SecurityLevel.MEDIUM,
    require_charset: bool = False,
    prevent_mime_sniffing: bool = True,
    name: str = "ContentType",
) -> Shield:
    """Create a content-type validation shield.
    
    Args:
        allowed_types: List of allowed content types
        policy: Validation policy (strict, permissive, pattern)
        security_level: Security level for validation
        require_charset: Whether to require charset specification
        prevent_mime_sniffing: Whether to prevent MIME sniffing attacks
        name: Shield name
        
    Returns:
        Content-type validation shield
        
    Examples:
        ```python
        # Basic JSON validation
        @app.post("/api/data")
        @content_type_shield(allowed_types=["application/json"])
        def create_data(data: dict):
            return {"status": "created"}
        
        # Multiple types with permissive policy
        @app.post("/api/upload")
        @content_type_shield(
            allowed_types=["image/jpeg", "image/png"],
            policy=ContentTypePolicy.PERMISSIVE,
            security_level=SecurityLevel.HIGH
        )
        def upload_image(file: bytes):
            return {"uploaded": True}
        
        # Strict validation with charset requirement
        @app.post("/api/text")
        @content_type_shield(
            allowed_types=["text/plain"],
            require_charset=True,
            security_level=SecurityLevel.PARANOID
        )
        def process_text(content: str):
            return {"processed": True}
        ```
    """
    config = ContentTypeConfig(
        allowed_types=allowed_types,
        policy=policy,
        security_level=security_level,
        require_charset=require_charset,
        prevent_mime_sniffing=prevent_mime_sniffing,
    )
    
    shield_instance = ContentTypeShield(config)
    return shield_instance.create_shield(name)


def json_content_type_shield(
    strict: bool = True,
    require_charset: bool = False,
    name: str = "JSONContentType",
) -> Shield:
    """Create a shield for JSON content-type validation.
    
    Args:
        strict: Whether to use strict validation policy
        require_charset: Whether to require charset specification
        name: Shield name
        
    Returns:
        JSON content-type validation shield
        
    Examples:
        ```python
        @app.post("/api/json")
        @json_content_type_shield()
        def handle_json(data: dict):
            return {"received": data}
        
        @app.post("/api/strict-json")
        @json_content_type_shield(strict=True, require_charset=True)
        def handle_strict_json(data: dict):
            return {"processed": True}
        ```
    """
    return content_type_shield(
        allowed_types=["application/json"],
        policy=ContentTypePolicy.STRICT if strict else ContentTypePolicy.PERMISSIVE,
        security_level=SecurityLevel.MEDIUM,
        require_charset=require_charset,
        name=name,
    )


def file_upload_content_type_shield(
    allowed_types: Optional[List[str]] = None,
    allowed_extensions: Optional[List[str]] = None,
    max_file_size: Optional[int] = None,
    security_level: SecurityLevel = SecurityLevel.HIGH,
    name: str = "FileUploadContentType",
) -> Shield:
    """Create a shield for file upload content-type validation.
    
    Args:
        allowed_types: List of allowed MIME types (default: common image types)
        allowed_extensions: List of allowed file extensions
        max_file_size: Maximum file size in bytes
        security_level: Security level for validation
        name: Shield name
        
    Returns:
        File upload content-type validation shield
        
    Examples:
        ```python
        @app.post("/upload/image")
        @file_upload_content_type_shield(
            allowed_types=["image/jpeg", "image/png"],
            allowed_extensions=[".jpg", ".jpeg", ".png"],
            max_file_size=5*1024*1024  # 5MB
        )
        def upload_image(file: UploadFile):
            return {"filename": file.filename}
        
        @app.post("/upload/document")
        @file_upload_content_type_shield(
            allowed_types=["application/pdf", "application/msword"],
            security_level=SecurityLevel.PARANOID
        )
        def upload_document(file: UploadFile):
            return {"uploaded": True}
        ```
    """
    if allowed_types is None:
        allowed_types = MIME_TYPE_GROUPS["images"]
    
    config = ContentTypeConfig(
        allowed_types=allowed_types,
        policy=ContentTypePolicy.STRICT,
        security_level=security_level,
        allowed_file_extensions=allowed_extensions,
        max_file_size=max_file_size,
        prevent_mime_sniffing=True,
        validate_file_signature=True,
    )
    
    shield_instance = ContentTypeShield(config)
    return shield_instance.create_shield(name)


def form_content_type_shield(
    allow_multipart: bool = True,
    allow_urlencoded: bool = True,
    security_level: SecurityLevel = SecurityLevel.MEDIUM,
    name: str = "FormContentType",
) -> Shield:
    """Create a shield for form content-type validation.
    
    Args:
        allow_multipart: Whether to allow multipart/form-data
        allow_urlencoded: Whether to allow application/x-www-form-urlencoded
        security_level: Security level for validation
        name: Shield name
        
    Returns:
        Form content-type validation shield
        
    Examples:
        ```python
        @app.post("/form/submit")
        @form_content_type_shield()
        def submit_form(data: dict):
            return {"submitted": True}
        
        @app.post("/form/multipart-only")
        @form_content_type_shield(
            allow_multipart=True,
            allow_urlencoded=False
        )
        def multipart_form(files: List[UploadFile]):
            return {"files_received": len(files)}
        ```
    """
    allowed_types = []
    if allow_multipart:
        allowed_types.append("multipart/form-data")
    if allow_urlencoded:
        allowed_types.append("application/x-www-form-urlencoded")
    
    config = ContentTypeConfig(
        allowed_types=allowed_types,
        policy=ContentTypePolicy.STRICT,
        security_level=security_level,
        validate_multipart_boundary=True,
    )
    
    shield_instance = ContentTypeShield(config)
    return shield_instance.create_shield(name)


def api_content_type_shield(
    allow_json: bool = True,
    allow_xml: bool = False,
    allow_form: bool = False,
    security_level: SecurityLevel = SecurityLevel.MEDIUM,
    name: str = "APIContentType",
) -> Shield:
    """Create a shield for API content-type validation.
    
    Args:
        allow_json: Whether to allow application/json
        allow_xml: Whether to allow XML types
        allow_form: Whether to allow form data
        security_level: Security level for validation
        name: Shield name
        
    Returns:
        API content-type validation shield
        
    Examples:
        ```python
        @app.post("/api/endpoint")
        @api_content_type_shield()
        def api_endpoint(data: dict):
            return {"processed": data}
        
        @app.post("/api/flexible")
        @api_content_type_shield(
            allow_json=True,
            allow_xml=True,
            allow_form=True
        )
        def flexible_api(request: Request):
            return {"content_type": request.headers.get("content-type")}
        ```
    """
    allowed_types = []
    if allow_json:
        allowed_types.extend(MIME_TYPE_GROUPS["json"])
    if allow_xml:
        allowed_types.extend(MIME_TYPE_GROUPS["xml"])
    if allow_form:
        allowed_types.extend(MIME_TYPE_GROUPS["form"])
    
    if not allowed_types:
        allowed_types = ["application/json"]  # Default fallback
    
    config = ContentTypeConfig(
        allowed_types=allowed_types,
        policy=ContentTypePolicy.STRICT,
        security_level=security_level,
        prevent_mime_sniffing=True,
    )
    
    shield_instance = ContentTypeShield(config)
    return shield_instance.create_shield(name)