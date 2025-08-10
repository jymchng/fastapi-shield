"""Request size limit shield for FastAPI Shield.

This module provides comprehensive request size limiting to prevent DoS attacks,
resource exhaustion, and memory abuse. It supports configurable limits per content
type, early validation before parsing, and memory-efficient stream processing.
"""

import asyncio
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from fastapi_shield.shield import Shield, shield


class SizeUnit(str, Enum):
    """Units for size specification."""
    BYTES = "bytes"
    KB = "KB"
    MB = "MB"  
    GB = "GB"


class SizeContentTypeCategory(str, Enum):
    """Content type categories for size limits."""
    JSON = "json"
    FORM_DATA = "form_data"
    MULTIPART = "multipart"
    TEXT = "text"
    BINARY = "binary"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    DEFAULT = "default"


class SizeCheckMode(str, Enum):
    """Modes for size checking."""
    HEADER_ONLY = "header_only"     # Check Content-Length header only
    STREAMING = "streaming"         # Stream and check during reading
    MEMORY_EFFICIENT = "memory_efficient"  # Balanced approach
    STRICT = "strict"              # Full validation with temporary storage


class RequestSizeLimitConfig(BaseModel):
    """Configuration for request size limiting."""
    
    # Global size limits
    max_request_size: Optional[int] = Field(default=16 * 1024 * 1024)  # 16MB default
    max_content_length: Optional[int] = None  # Separate content-length limit
    
    # Per-content-type limits (in bytes)
    content_type_limits: Dict[SizeContentTypeCategory, int] = Field(default_factory=lambda: {
        SizeContentTypeCategory.JSON: 1 * 1024 * 1024,      # 1MB for JSON
        SizeContentTypeCategory.FORM_DATA: 512 * 1024,       # 512KB for form data
        SizeContentTypeCategory.MULTIPART: 50 * 1024 * 1024, # 50MB for file uploads
        SizeContentTypeCategory.TEXT: 256 * 1024,            # 256KB for text
        SizeContentTypeCategory.BINARY: 10 * 1024 * 1024,    # 10MB for binary
        SizeContentTypeCategory.IMAGE: 5 * 1024 * 1024,      # 5MB for images
        SizeContentTypeCategory.VIDEO: 100 * 1024 * 1024,    # 100MB for video
        SizeContentTypeCategory.AUDIO: 20 * 1024 * 1024,     # 20MB for audio
        SizeContentTypeCategory.DOCUMENT: 10 * 1024 * 1024,  # 10MB for documents
        SizeContentTypeCategory.ARCHIVE: 50 * 1024 * 1024,   # 50MB for archives
    })
    
    # Size checking behavior
    check_mode: SizeCheckMode = SizeCheckMode.MEMORY_EFFICIENT
    check_content_length_header: bool = True
    allow_chunked_encoding: bool = True
    
    # Streaming configuration
    chunk_size: int = Field(default=8192, ge=1024)  # 8KB chunks
    max_read_time: float = Field(default=30.0, gt=0)  # 30 seconds max read time
    
    # URL and query parameters limits
    max_url_length: Optional[int] = Field(default=2048)
    max_query_params_size: Optional[int] = Field(default=8192)
    max_single_param_size: Optional[int] = Field(default=1024)
    max_param_count: Optional[int] = Field(default=100)
    
    # Error handling
    custom_error_message: Optional[str] = None
    include_size_info: bool = True
    log_violations: bool = True
    
    # Performance options
    enable_size_tracking: bool = True
    enable_rate_limiting: bool = False  # Future integration
    
    @field_validator('content_type_limits')
    @classmethod
    def validate_content_type_limits(cls, v):
        """Validate content type limits are positive."""
        for category, limit in v.items():
            if limit <= 0:
                raise ValueError(f"Size limit for {category} must be positive")
        return v
    
    @field_validator('chunk_size')
    @classmethod
    def validate_chunk_size(cls, v):
        """Validate chunk size is reasonable."""
        if v > 1024 * 1024:  # 1MB
            raise ValueError("Chunk size should not exceed 1MB")
        return v


class SizeViolation(BaseModel):
    """Information about a size limit violation."""
    
    violation_type: str
    limit: int
    actual_size: int
    content_type: Optional[str] = None
    category: Optional[SizeContentTypeCategory] = None
    message: str
    timestamp: float = Field(default_factory=time.time)


class RequestSizeTracker:
    """Tracks request size during processing."""
    
    def __init__(self, config: RequestSizeLimitConfig):
        """Initialize size tracker.
        
        Args:
            config: Size limit configuration
        """
        self.config = config
        self.bytes_read = 0
        self.start_time = time.time()
        self.violations: List[SizeViolation] = []
        self.content_type_category: Optional[SizeContentTypeCategory] = None
        self.estimated_size: Optional[int] = None
        self.is_chunked = False
    
    def set_content_info(self, content_type: str, content_length: Optional[int]):
        """Set content type and length information.
        
        Args:
            content_type: Request content type
            content_length: Content length from header
        """
        self.content_type_category = self._categorize_content_type(content_type)
        self.estimated_size = content_length
        self.is_chunked = content_length is None
    
    def _categorize_content_type(self, content_type: str) -> SizeContentTypeCategory:
        """Categorize content type for size limits.
        
        Args:
            content_type: Content type string
            
        Returns:
            Content type category
        """
        content_type = content_type.lower()
        
        if 'application/json' in content_type:
            return SizeContentTypeCategory.JSON
        elif 'application/x-www-form-urlencoded' in content_type:
            return SizeContentTypeCategory.FORM_DATA
        elif 'multipart/form-data' in content_type:
            return SizeContentTypeCategory.MULTIPART
        elif content_type.startswith('text/'):
            return SizeContentTypeCategory.TEXT
        elif content_type.startswith('image/'):
            return SizeContentTypeCategory.IMAGE
        elif content_type.startswith('video/'):
            return SizeContentTypeCategory.VIDEO
        elif content_type.startswith('audio/'):
            return SizeContentTypeCategory.AUDIO
        elif content_type in ['application/pdf', 'application/msword', 
                              'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
            return SizeContentTypeCategory.DOCUMENT
        elif content_type in ['application/zip', 'application/x-tar', 'application/gzip']:
            return SizeContentTypeCategory.ARCHIVE
        elif content_type == 'application/octet-stream':
            return SizeContentTypeCategory.BINARY
        else:
            return SizeContentTypeCategory.DEFAULT
    
    def get_applicable_limit(self) -> int:
        """Get the applicable size limit for current content type.
        
        Returns:
            Size limit in bytes
        """
        if self.content_type_category and self.content_type_category in self.config.content_type_limits:
            category_limit = self.config.content_type_limits[self.content_type_category]
        else:
            category_limit = self.config.content_type_limits.get(
                SizeContentTypeCategory.DEFAULT, 
                self.config.max_request_size or 16 * 1024 * 1024
            )
        
        # Use the smaller of global and category limits
        if self.config.max_request_size:
            return min(category_limit, self.config.max_request_size)
        
        return category_limit
    
    def check_content_length_header(self, content_length: int) -> Optional[SizeViolation]:
        """Check if content length header exceeds limits.
        
        Args:
            content_length: Content length from header
            
        Returns:
            Size violation if limit exceeded
        """
        applicable_limit = self.get_applicable_limit()
        
        if content_length > applicable_limit:
            violation = SizeViolation(
                violation_type="content_length_header",
                limit=applicable_limit,
                actual_size=content_length,
                content_type=self.content_type_category.value if self.content_type_category else None,
                category=self.content_type_category,
                message=f"Content-Length header ({content_length} bytes) exceeds limit ({applicable_limit} bytes)"
            )
            self.violations.append(violation)
            return violation
        
        return None
    
    def add_bytes(self, byte_count: int) -> Optional[SizeViolation]:
        """Add bytes read and check limits.
        
        Args:
            byte_count: Number of bytes read
            
        Returns:
            Size violation if limit exceeded
        """
        self.bytes_read += byte_count
        applicable_limit = self.get_applicable_limit()
        
        if self.bytes_read > applicable_limit:
            violation = SizeViolation(
                violation_type="streaming_limit",
                limit=applicable_limit,
                actual_size=self.bytes_read,
                content_type=self.content_type_category.value if self.content_type_category else None,
                category=self.content_type_category,
                message=f"Request size ({self.bytes_read} bytes) exceeds limit ({applicable_limit} bytes) during streaming"
            )
            self.violations.append(violation)
            return violation
        
        return None
    
    def check_timeout(self) -> Optional[SizeViolation]:
        """Check if read operation has timed out.
        
        Returns:
            Timeout violation if exceeded
        """
        elapsed = time.time() - self.start_time
        
        if elapsed > self.config.max_read_time:
            violation = SizeViolation(
                violation_type="read_timeout",
                limit=int(self.config.max_read_time),
                actual_size=int(elapsed),
                message=f"Request read timeout ({elapsed:.1f}s) exceeds limit ({self.config.max_read_time}s)"
            )
            self.violations.append(violation)
            return violation
        
        return None
    
    def get_progress_info(self) -> Dict[str, Any]:
        """Get progress information for monitoring.
        
        Returns:
            Dictionary with progress details
        """
        applicable_limit = self.get_applicable_limit()
        elapsed = time.time() - self.start_time
        
        return {
            "bytes_read": self.bytes_read,
            "applicable_limit": applicable_limit,
            "percentage": (self.bytes_read / applicable_limit * 100) if applicable_limit > 0 else 0,
            "estimated_size": self.estimated_size,
            "is_chunked": self.is_chunked,
            "content_category": self.content_type_category.value if self.content_type_category else None,
            "elapsed_time": elapsed,
            "read_rate": self.bytes_read / elapsed if elapsed > 0 else 0,
            "violations_count": len(self.violations)
        }


def convert_size_to_bytes(size: Union[int, str]) -> int:
    """Convert size specification to bytes.
    
    Args:
        size: Size as integer (bytes) or string with unit
        
    Returns:
        Size in bytes
        
    Examples:
        >>> convert_size_to_bytes("1MB")
        1048576
        >>> convert_size_to_bytes("512KB")
        524288
        >>> convert_size_to_bytes(1024)
        1024
    """
    if isinstance(size, int):
        return size
    
    if isinstance(size, str):
        size = size.strip().upper()
        
        # Extract number and unit
        number_str = ""
        unit = ""
        
        for char in size:
            if char.isdigit() or char == ".":
                number_str += char
            else:
                unit = size[len(number_str):].strip()
                break
        
        if not number_str:
            raise ValueError(f"Invalid size specification: {size}")
        
        try:
            number = float(number_str)
        except ValueError:
            raise ValueError(f"Invalid number in size specification: {size}")
        
        # Convert based on unit
        multipliers = {
            "": 1,
            "B": 1,
            "BYTES": 1,
            "KB": 1024,
            "MB": 1024 * 1024,
            "GB": 1024 * 1024 * 1024,
        }
        
        if unit not in multipliers:
            raise ValueError(f"Unknown size unit: {unit}")
        
        return int(number * multipliers[unit])
    
    raise ValueError(f"Size must be int or string, got {type(size)}")


def format_bytes(byte_count: int) -> str:
    """Format byte count as human readable string.
    
    Args:
        byte_count: Number of bytes
        
    Returns:
        Formatted string
        
    Examples:
        >>> format_bytes(1024)
        '1.0 KB'
        >>> format_bytes(1536)
        '1.5 KB'
        >>> format_bytes(1048576)
        '1.0 MB'
    """
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if byte_count < 1024.0:
            if unit == 'bytes':
                return f"{int(byte_count)} {unit}"
            else:
                return f"{byte_count:.1f} {unit}"
        byte_count /= 1024.0
    
    return f"{byte_count:.1f} PB"


class RequestSizeLimitShield:
    """Request size limiting shield for FastAPI endpoints."""
    
    def __init__(self, config: RequestSizeLimitConfig):
        """Initialize request size limit shield.
        
        Args:
            config: Request size limit configuration
        """
        self.config = config
    
    async def _validate_url_size(self, request: Request) -> None:
        """Validate URL and query parameter sizes.
        
        Args:
            request: FastAPI request object
            
        Raises:
            HTTPException: If URL or parameters exceed limits
        """
        # Check URL length
        if self.config.max_url_length:
            url_str = str(request.url)
            if len(url_str) > self.config.max_url_length:
                raise HTTPException(
                    status_code=status.HTTP_414_REQUEST_URI_TOO_LONG,
                    detail=f"URL length ({len(url_str)}) exceeds maximum allowed ({self.config.max_url_length})"
                )
        
        # Check query parameters
        if request.url.query and (self.config.max_query_params_size or 
                                  self.config.max_single_param_size or 
                                  self.config.max_param_count):
            
            query_size = len(request.url.query)
            
            if self.config.max_query_params_size and query_size > self.config.max_query_params_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Query parameters size ({query_size}) exceeds limit ({self.config.max_query_params_size})"
                )
            
            # Parse and check individual parameters
            try:
                parsed_params = parse_qs(request.url.query, keep_blank_values=True)
                
                if self.config.max_param_count and len(parsed_params) > self.config.max_param_count:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Too many query parameters ({len(parsed_params)}) - limit is {self.config.max_param_count}"
                    )
                
                if self.config.max_single_param_size:
                    for key, values in parsed_params.items():
                        if len(key) > self.config.max_single_param_size:
                            raise HTTPException(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail=f"Query parameter name too long ({len(key)} > {self.config.max_single_param_size})"
                            )
                        
                        for value in values:
                            if len(value) > self.config.max_single_param_size:
                                raise HTTPException(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    detail=f"Query parameter value too long ({len(value)} > {self.config.max_single_param_size})"
                                )
            
            except Exception as e:
                if isinstance(e, HTTPException):
                    raise
                # Ignore query parsing errors for malformed queries
                pass
    
    async def _stream_and_validate_body(self, request: Request, tracker: RequestSizeTracker) -> bytes:
        """Stream request body and validate size limits.
        
        Args:
            request: FastAPI request object
            tracker: Size tracker instance
            
        Returns:
            Request body bytes
            
        Raises:
            HTTPException: If size limits are exceeded
        """
        body_parts = []
        
        async def receive_with_size_check():
            """Receive request body with size checking."""
            while True:
                # Check for timeout
                timeout_violation = tracker.check_timeout()
                if timeout_violation:
                    raise HTTPException(
                        status_code=status.HTTP_408_REQUEST_TIMEOUT,
                        detail=timeout_violation.message
                    )
                
                # Receive chunk
                message = await request.receive()
                
                if message["type"] == "http.request":
                    body_chunk = message.get("body", b"")
                    more_body = message.get("more_body", False)
                    
                    if body_chunk:
                        # Check size limit
                        violation = tracker.add_bytes(len(body_chunk))
                        if violation:
                            detail = self.config.custom_error_message or violation.message
                            if self.config.include_size_info:
                                detail += f" (received: {format_bytes(violation.actual_size)}, limit: {format_bytes(violation.limit)})"
                            
                            raise HTTPException(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail=detail
                            )
                        
                        body_parts.append(body_chunk)
                    
                    if not more_body:
                        break
                
                elif message["type"] == "http.disconnect":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Client disconnected during request"
                    )
        
        # Stream body with size validation
        await receive_with_size_check()
        
        return b"".join(body_parts)
    
    def create_shield(self, name: str = "RequestSizeLimit") -> Shield:
        """Create a shield for request size limiting.
        
        Args:
            name: Shield name
            
        Returns:
            Shield instance
        """
        
        async def request_size_limit_shield(request: Request) -> Dict[str, Any]:
            """Request size limit shield function."""
            
            # Validate URL and query parameters
            await self._validate_url_size(request)
            
            # Get content type and length information
            content_type = request.headers.get("content-type", "application/octet-stream")
            content_length_header = request.headers.get("content-length")
            content_length = None
            
            if content_length_header:
                try:
                    content_length = int(content_length_header)
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid Content-Length header"
                    )
            
            # Initialize size tracker
            tracker = RequestSizeTracker(self.config)
            tracker.set_content_info(content_type, content_length)
            
            # Check Content-Length header if present
            if (self.config.check_content_length_header and 
                content_length is not None):
                
                violation = tracker.check_content_length_header(content_length)
                if violation:
                    detail = self.config.custom_error_message or violation.message
                    if self.config.include_size_info:
                        detail += f" (declared: {format_bytes(violation.actual_size)}, limit: {format_bytes(violation.limit)})"
                    
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=detail
                    )
            
            # Handle different check modes
            body_handled = False
            
            if self.config.check_mode == SizeCheckMode.HEADER_ONLY:
                # Only check Content-Length header, don't stream body
                if content_length is None and not self.config.allow_chunked_encoding:
                    raise HTTPException(
                        status_code=status.HTTP_411_LENGTH_REQUIRED,
                        detail="Content-Length header required"
                    )
            
            elif self.config.check_mode in [SizeCheckMode.STREAMING, SizeCheckMode.MEMORY_EFFICIENT, SizeCheckMode.STRICT]:
                # Stream and validate body
                if hasattr(request, '_body'):
                    # Body already read
                    body = request._body
                    tracker.add_bytes(len(body))
                else:
                    # Stream body with validation
                    body = await self._stream_and_validate_body(request, tracker)
                    # Store for potential reuse
                    request._body = body
                
                body_handled = True
            
            # Return validation result and metadata
            progress_info = tracker.get_progress_info()
            
            result = {
                "size_validation_passed": True,
                "content_type_category": tracker.content_type_category.value if tracker.content_type_category else None,
                "applicable_limit": tracker.get_applicable_limit(),
                "estimated_size": tracker.estimated_size,
                "actual_size": tracker.bytes_read,
                "body_handled": body_handled,
                "is_chunked": tracker.is_chunked,
                "progress_info": progress_info,
            }
            
            # Add size tracking data if enabled
            if self.config.enable_size_tracking:
                result["size_tracker"] = tracker
            
            return result
        
        return shield(
            request_size_limit_shield,
            name=name,
            auto_error=True,
        )


def request_size_limit_shield(
    max_size: Union[int, str],
    content_type_limits: Optional[Dict[Union[str, SizeContentTypeCategory], Union[int, str]]] = None,
    check_mode: SizeCheckMode = SizeCheckMode.MEMORY_EFFICIENT,
    custom_error_message: Optional[str] = None,
    name: str = "RequestSizeLimit",
) -> Shield:
    """Create a request size limit shield.
    
    Args:
        max_size: Maximum request size (int bytes or string like "1MB")
        content_type_limits: Per-content-type size limits
        check_mode: How to check sizes (header_only, streaming, etc.)
        custom_error_message: Custom error message
        name: Shield name
        
    Returns:
        Request size limit shield
        
    Examples:
        ```python
        # Basic size limit
        @app.post("/api/data")
        @request_size_limit_shield(max_size="1MB")
        def upload_data(data: dict):
            return {"uploaded": True}
        
        # Different limits per content type
        @app.post("/api/files")
        @request_size_limit_shield(
            max_size="10MB",
            content_type_limits={
                            SizeContentTypeCategory.JSON: "512KB",
            SizeContentTypeCategory.MULTIPART: "50MB"
            }
        )
        def upload_files(files: List[UploadFile]):
            return {"count": len(files)}
        
        # Header-only checking (fast but less secure)
        @app.post("/api/quick")
        @request_size_limit_shield(
            max_size="256KB", 
            check_mode=SizeCheckMode.HEADER_ONLY
        )
        def quick_upload(data: str):
            return {"received": len(data)}
        ```
    """
    max_size_bytes = convert_size_to_bytes(max_size)
    
    # Convert content type limits to bytes
    converted_limits = {}
    if content_type_limits:
        for content_type, limit in content_type_limits.items():
            if isinstance(content_type, str):
                # Convert string to SizeContentTypeCategory
                content_type = SizeContentTypeCategory(content_type)
            converted_limits[content_type] = convert_size_to_bytes(limit)
    
    config = RequestSizeLimitConfig(
        max_request_size=max_size_bytes,
        content_type_limits=converted_limits if converted_limits else {},
        check_mode=check_mode,
        custom_error_message=custom_error_message,
    )
    
    shield_instance = RequestSizeLimitShield(config)
    return shield_instance.create_shield(name)


def json_size_limit_shield(
    max_size: Union[int, str] = "1MB",
    name: str = "JSONSizeLimit",
) -> Shield:
    """Create a shield for JSON request size limiting.
    
    Args:
        max_size: Maximum JSON size
        name: Shield name
        
    Returns:
        JSON size limit shield
        
    Examples:
        ```python
        @app.post("/api/json")
        @json_size_limit_shield(max_size="512KB")
        def handle_json(data: dict):
            return {"processed": len(str(data))}
        ```
    """
    return request_size_limit_shield(
        max_size=max_size,
        content_type_limits={SizeContentTypeCategory.JSON: max_size},
        check_mode=SizeCheckMode.STREAMING,
        name=name,
    )


def file_upload_size_limit_shield(
    max_file_size: Union[int, str] = "10MB",
    max_total_size: Union[int, str] = "50MB",
    name: str = "FileUploadSizeLimit",
) -> Shield:
    """Create a shield for file upload size limiting.
    
    Args:
        max_file_size: Maximum individual file size
        max_total_size: Maximum total upload size
        name: Shield name
        
    Returns:
        File upload size limit shield
        
    Examples:
        ```python
        @app.post("/upload/files")
        @file_upload_size_limit_shield(
            max_file_size="5MB",
            max_total_size="25MB"
        )
        def upload_files(files: List[UploadFile]):
            return {"uploaded": len(files)}
        ```
    """
    return request_size_limit_shield(
        max_size=max_total_size,
        content_type_limits={
            SizeContentTypeCategory.MULTIPART: max_total_size,
            SizeContentTypeCategory.IMAGE: max_file_size,
            SizeContentTypeCategory.VIDEO: max_file_size,
            SizeContentTypeCategory.AUDIO: max_file_size,
            SizeContentTypeCategory.DOCUMENT: max_file_size,
        },
        check_mode=SizeCheckMode.STREAMING,
        name=name,
    )


def api_size_limit_shield(
    json_size: Union[int, str] = "1MB",
    form_size: Union[int, str] = "512KB",
    file_size: Union[int, str] = "10MB",
    name: str = "APISizeLimit",
) -> Shield:
    """Create a shield for general API size limiting.
    
    Args:
        json_size: Maximum JSON payload size
        form_size: Maximum form data size
        file_size: Maximum file upload size
        name: Shield name
        
    Returns:
        API size limit shield
        
    Examples:
        ```python
        @app.post("/api/endpoint")
        @api_size_limit_shield(
            json_size="2MB",
            form_size="1MB", 
            file_size="20MB"
        )
        def api_endpoint(request: Request):
            return {"status": "processed"}
        ```
    """
    max_size = max(
        convert_size_to_bytes(json_size),
        convert_size_to_bytes(form_size), 
        convert_size_to_bytes(file_size)
    )
    
    return request_size_limit_shield(
        max_size=max_size,
        content_type_limits={
            SizeContentTypeCategory.JSON: json_size,
            SizeContentTypeCategory.FORM_DATA: form_size,
            SizeContentTypeCategory.MULTIPART: file_size,
        },
        check_mode=SizeCheckMode.MEMORY_EFFICIENT,
        name=name,
    )


def strict_size_limit_shield(
    max_size: Union[int, str],
    require_content_length: bool = True,
    name: str = "StrictSizeLimit",
) -> Shield:
    """Create a strict request size limit shield.
    
    Args:
        max_size: Maximum request size
        require_content_length: Whether to require Content-Length header
        name: Shield name
        
    Returns:
        Strict size limit shield
        
    Examples:
        ```python
        @app.post("/api/strict")
        @strict_size_limit_shield(
            max_size="256KB",
            require_content_length=True
        )
        def strict_endpoint(data: str):
            return {"processed": True}
        ```
    """
    config = RequestSizeLimitConfig(
        max_request_size=convert_size_to_bytes(max_size),
        check_mode=SizeCheckMode.STRICT,
        check_content_length_header=True,
        allow_chunked_encoding=not require_content_length,
    )
    
    shield_instance = RequestSizeLimitShield(config)
    return shield_instance.create_shield(name)