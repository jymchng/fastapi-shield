"""Response postprocessing framework for FastAPI Shield.

This module provides comprehensive response postprocessing capabilities, allowing shields
to modify responses after endpoint execution. It supports header injection and modification,
response body transformation, content filtering and sanitization, compression, and
security header automation.

The postprocessing system works by:
1. Capturing the response from endpoint execution
2. Applying configured postprocessors in sequence
3. Returning the modified response

Key Components:
    - ResponsePostprocessor: Abstract base for all postprocessors
    - HeaderProcessor: Manipulates response headers
    - BodyTransformer: Transforms response body content
    - ContentFilter: Filters and sanitizes response content
    - CompressionProcessor: Handles response compression and encoding
    - SecurityHeaderProcessor: Automatically injects security headers
    - PostprocessingShield: Enhanced shield with postprocessing capabilities
"""

import gzip
import json
import re
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Union, Pattern, Tuple, Set
from urllib.parse import quote

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.encoders import jsonable_encoder
from starlette.responses import StreamingResponse

from fastapi_shield.shield import Shield
from fastapi_shield.typing import EndPointFunc


class PostprocessingAction(Enum):
    """Actions that can be taken during postprocessing."""
    CONTINUE = "continue"
    REPLACE = "replace"
    BLOCK = "block"
    TRANSFORM = "transform"


class CompressionMethod(Enum):
    """Supported compression methods."""
    GZIP = "gzip"
    DEFLATE = "deflate"
    NONE = "none"


class ContentType(Enum):
    """Supported content types for processing."""
    JSON = "application/json"
    HTML = "text/html"
    TEXT = "text/plain"
    XML = "application/xml"
    CSS = "text/css"
    JAVASCRIPT = "application/javascript"


@dataclass
class PostprocessingResult:
    """Result of a postprocessing operation."""
    action: PostprocessingAction
    response: Optional[Response] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[Any] = None
    reason: Optional[str] = None


@dataclass
class SecurityHeaderConfig:
    """Configuration for security headers."""
    # Content Security Policy
    csp_policy: Optional[str] = None
    csp_report_only: bool = False
    
    # HTTP Strict Transport Security
    hsts_max_age: int = 31536000  # 1 year
    hsts_include_subdomains: bool = True
    hsts_preload: bool = False
    
    # X-Frame-Options
    frame_options: str = "DENY"  # DENY, SAMEORIGIN, ALLOW-FROM
    
    # X-Content-Type-Options
    content_type_options: str = "nosniff"
    
    # X-XSS-Protection
    xss_protection: str = "1; mode=block"
    
    # Referrer Policy
    referrer_policy: str = "strict-origin-when-cross-origin"
    
    # Permissions Policy (formerly Feature Policy)
    permissions_policy: Optional[str] = None
    
    # Custom headers
    custom_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class CompressionConfig:
    """Configuration for response compression."""
    method: CompressionMethod = CompressionMethod.GZIP
    min_size: int = 1024  # Minimum response size to compress
    level: int = 6  # Compression level (1-9)
    content_types: Set[str] = field(default_factory=lambda: {
        "text/plain", "text/html", "text/css", "text/javascript",
        "application/json", "application/javascript", "application/xml"
    })


@dataclass
class FilterRule:
    """Content filtering rule."""
    pattern: Union[str, Pattern[str]]
    replacement: str = ""
    flags: int = 0
    content_types: Set[str] = field(default_factory=lambda: {"text/html", "text/plain"})


class ResponsePostprocessor(ABC):
    """Abstract base class for response postprocessors."""
    
    def __init__(self, name: str, enabled: bool = True):
        """Initialize the postprocessor.
        
        Args:
            name: Name of the postprocessor
            enabled: Whether the postprocessor is enabled
        """
        self.name = name
        self.enabled = enabled
    
    @abstractmethod
    async def process(self, request: Request, response: Response, 
                     context: Dict[str, Any]) -> PostprocessingResult:
        """Process the response.
        
        Args:
            request: The original request
            response: The response to process
            context: Processing context from shield
            
        Returns:
            PostprocessingResult with the processing result
        """
        pass
    
    def is_applicable(self, request: Request, response: Response) -> bool:
        """Check if this postprocessor should be applied.
        
        Args:
            request: The request
            response: The response
            
        Returns:
            True if processor should be applied
        """
        return self.enabled


class HeaderProcessor(ResponsePostprocessor):
    """Postprocessor for header manipulation."""
    
    def __init__(self, name: str = "HeaderProcessor", enabled: bool = True,
                 add_headers: Optional[Dict[str, str]] = None,
                 remove_headers: Optional[List[str]] = None,
                 modify_headers: Optional[Dict[str, Callable[[str], str]]] = None):
        """Initialize header processor.
        
        Args:
            name: Name of the processor
            enabled: Whether the processor is enabled
            add_headers: Headers to add to the response
            remove_headers: Headers to remove from the response
            modify_headers: Headers to modify (header_name -> transformation_func)
        """
        super().__init__(name, enabled)
        self.add_headers = add_headers or {}
        self.remove_headers = remove_headers or []
        self.modify_headers = modify_headers or {}
    
    async def process(self, request: Request, response: Response,
                     context: Dict[str, Any]) -> PostprocessingResult:
        """Process headers."""
        if not self.enabled:
            return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        headers = dict(response.headers)
        
        # Add new headers
        headers.update(self.add_headers)
        
        # Remove headers
        for header_name in self.remove_headers:
            headers.pop(header_name.lower(), None)
        
        # Modify existing headers
        for header_name, transform_func in self.modify_headers.items():
            header_key = header_name.lower()
            # Find the actual header key (case-insensitive)
            actual_key = None
            for key in headers:
                if key.lower() == header_key:
                    actual_key = key
                    break
            
            if actual_key:
                headers[header_key] = transform_func(headers[actual_key])
                if actual_key != header_key:
                    del headers[actual_key]
        
        return PostprocessingResult(
            action=PostprocessingAction.TRANSFORM,
            headers=headers
        )


class SecurityHeaderProcessor(ResponsePostprocessor):
    """Postprocessor for automatic security header injection."""
    
    def __init__(self, name: str = "SecurityHeaderProcessor", enabled: bool = True,
                 config: Optional[SecurityHeaderConfig] = None):
        """Initialize security header processor.
        
        Args:
            name: Name of the processor
            enabled: Whether the processor is enabled
            config: Security header configuration
        """
        super().__init__(name, enabled)
        self.config = config or SecurityHeaderConfig()
    
    async def process(self, request: Request, response: Response,
                     context: Dict[str, Any]) -> PostprocessingResult:
        """Process security headers."""
        if not self.enabled:
            return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        headers = dict(response.headers)
        
        # Content Security Policy
        if self.config.csp_policy:
            header_name = "Content-Security-Policy-Report-Only" if self.config.csp_report_only else "Content-Security-Policy"
            headers[header_name] = self.config.csp_policy
        
        # HTTP Strict Transport Security
        hsts_value = f"max-age={self.config.hsts_max_age}"
        if self.config.hsts_include_subdomains:
            hsts_value += "; includeSubDomains"
        if self.config.hsts_preload:
            hsts_value += "; preload"
        headers["Strict-Transport-Security"] = hsts_value
        
        # X-Frame-Options
        headers["X-Frame-Options"] = self.config.frame_options
        
        # X-Content-Type-Options
        headers["X-Content-Type-Options"] = self.config.content_type_options
        
        # X-XSS-Protection
        headers["X-XSS-Protection"] = self.config.xss_protection
        
        # Referrer Policy
        headers["Referrer-Policy"] = self.config.referrer_policy
        
        # Permissions Policy
        if self.config.permissions_policy:
            headers["Permissions-Policy"] = self.config.permissions_policy
        
        # Custom headers
        headers.update(self.config.custom_headers)
        
        return PostprocessingResult(
            action=PostprocessingAction.TRANSFORM,
            headers=headers
        )


class BodyTransformer(ResponsePostprocessor):
    """Postprocessor for response body transformation."""
    
    def __init__(self, name: str = "BodyTransformer", enabled: bool = True,
                 transformers: Optional[Dict[str, Callable[[Any], Any]]] = None,
                 json_transformers: Optional[List[Callable[[Dict[str, Any]], Dict[str, Any]]]] = None):
        """Initialize body transformer.
        
        Args:
            name: Name of the processor
            enabled: Whether the processor is enabled
            transformers: Content type specific transformers
            json_transformers: JSON-specific transformation functions
        """
        super().__init__(name, enabled)
        self.transformers = transformers or {}
        self.json_transformers = json_transformers or []
    
    async def process(self, request: Request, response: Response,
                     context: Dict[str, Any]) -> PostprocessingResult:
        """Transform response body."""
        if not self.enabled:
            return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        content_type = response.headers.get("content-type", "").split(";")[0].lower()
        
        # Get response body
        if hasattr(response, 'body'):
            body = response.body
        else:
            # For streaming responses or responses without body attribute
            return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        # Apply transformers
        transformed = False
        transformed_body = body
        
        # Handle JSON transformations
        if content_type == "application/json" and self.json_transformers:
            try:
                if isinstance(body, bytes):
                    data = json.loads(body.decode())
                elif isinstance(body, str):
                    data = json.loads(body)
                else:
                    data = body
                
                # Apply JSON transformers
                for transformer in self.json_transformers:
                    data = transformer(data)
                
                transformed_body = json.dumps(jsonable_encoder(data))
                transformed = True
            except Exception as e:
                # If transformation fails, continue without transformation
                return PostprocessingResult(
                    action=PostprocessingAction.CONTINUE,
                    reason=f"JSON transformation failed: {str(e)}"
                )
        
        # Apply content type specific transformers
        if content_type in self.transformers:
            try:
                if content_type == "application/json" and transformed:
                    # Already transformed by JSON transformers, now apply general transformer
                    data = json.loads(transformed_body)
                    data = self.transformers[content_type](data)
                    transformed_body = json.dumps(jsonable_encoder(data))
                else:
                    # Apply transformer to raw body
                    if isinstance(transformed_body, bytes):
                        body_str = transformed_body.decode()
                    else:
                        body_str = str(transformed_body)
                    
                    transformed_body = self.transformers[content_type](body_str)
                
                transformed = True
            except Exception as e:
                # If transformation fails, continue without transformation
                return PostprocessingResult(
                    action=PostprocessingAction.CONTINUE,
                    reason=f"Body transformation failed: {str(e)}"
                )
        
        if transformed:
            return PostprocessingResult(
                action=PostprocessingAction.TRANSFORM,
                body=transformed_body
            )
        
        return PostprocessingResult(action=PostprocessingAction.CONTINUE)


class ContentFilter(ResponsePostprocessor):
    """Postprocessor for content filtering and sanitization."""
    
    def __init__(self, name: str = "ContentFilter", enabled: bool = True,
                 filter_rules: Optional[List[FilterRule]] = None,
                 blocked_patterns: Optional[List[Union[str, Pattern[str]]]] = None,
                 sanitize_html: bool = False):
        """Initialize content filter.
        
        Args:
            name: Name of the processor
            enabled: Whether the processor is enabled
            filter_rules: List of filtering rules to apply
            blocked_patterns: Patterns that trigger response blocking
            sanitize_html: Whether to sanitize HTML content
        """
        super().__init__(name, enabled)
        self.filter_rules = filter_rules or []
        self.blocked_patterns = [
            re.compile(pattern) if isinstance(pattern, str) else pattern
            for pattern in (blocked_patterns or [])
        ]
        self.sanitize_html = sanitize_html
        
        # Compile filter rule patterns
        for rule in self.filter_rules:
            if isinstance(rule.pattern, str):
                rule.pattern = re.compile(rule.pattern, rule.flags)
    
    async def process(self, request: Request, response: Response,
                     context: Dict[str, Any]) -> PostprocessingResult:
        """Filter and sanitize content."""
        if not self.enabled:
            return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        content_type = response.headers.get("content-type", "").split(";")[0].lower()
        
        # Get response body
        if hasattr(response, 'body'):
            body = response.body
        else:
            return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        if isinstance(body, bytes):
            body_str = body.decode()
        else:
            body_str = str(body)
        
        # Check for blocked patterns
        for pattern in self.blocked_patterns:
            if pattern.search(body_str):
                return PostprocessingResult(
                    action=PostprocessingAction.BLOCK,
                    reason=f"Content blocked by pattern: {pattern.pattern}"
                )
        
        # Apply filter rules
        filtered_content = body_str
        for rule in self.filter_rules:
            if content_type in rule.content_types:
                filtered_content = rule.pattern.sub(rule.replacement, filtered_content)
        
        # HTML sanitization
        if self.sanitize_html and content_type in {"text/html", "application/xhtml+xml"}:
            filtered_content = self._sanitize_html(filtered_content)
        
        if filtered_content != body_str:
            return PostprocessingResult(
                action=PostprocessingAction.TRANSFORM,
                body=filtered_content
            )
        
        return PostprocessingResult(action=PostprocessingAction.CONTINUE)
    
    def _sanitize_html(self, html_content: str) -> str:
        """Basic HTML sanitization."""
        # Remove potentially dangerous tags and attributes
        dangerous_tags = [
            r'<script[^>]*>.*?</script>',
            r'<iframe[^>]*>.*?</iframe>',
            r'<object[^>]*>.*?</object>',
            r'<embed[^>]*>.*?</embed>',
        ]
        
        sanitized = html_content
        for tag_pattern in dangerous_tags:
            sanitized = re.sub(tag_pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove dangerous attributes
        dangerous_attrs = [
            r'on\w+\s*=\s*["\'][^"\']*["\']',  # onclick, onload, etc.
            r'javascript\s*:',
            r'data\s*:\s*text/html',
        ]
        
        for attr_pattern in dangerous_attrs:
            sanitized = re.sub(attr_pattern, '', sanitized, flags=re.IGNORECASE)
        
        return sanitized


class CompressionProcessor(ResponsePostprocessor):
    """Postprocessor for response compression and encoding."""
    
    def __init__(self, name: str = "CompressionProcessor", enabled: bool = True,
                 config: Optional[CompressionConfig] = None):
        """Initialize compression processor.
        
        Args:
            name: Name of the processor
            enabled: Whether the processor is enabled
            config: Compression configuration
        """
        super().__init__(name, enabled)
        self.config = config or CompressionConfig()
    
    def is_applicable(self, request: Request, response: Response) -> bool:
        """Check if compression should be applied."""
        if not super().is_applicable(request, response):
            return False
        
        # Check if client accepts compression
        accept_encoding = request.headers.get("accept-encoding", "").lower()
        if self.config.method == CompressionMethod.GZIP and "gzip" not in accept_encoding:
            return False
        if self.config.method == CompressionMethod.DEFLATE and "deflate" not in accept_encoding:
            return False
        
        # Check content type
        content_type = response.headers.get("content-type", "").split(";")[0].lower()
        if content_type not in self.config.content_types:
            return False
        
        # Check if already compressed
        if response.headers.get("content-encoding"):
            return False
        
        return True
    
    async def process(self, request: Request, response: Response,
                     context: Dict[str, Any]) -> PostprocessingResult:
        """Compress response."""
        if not self.is_applicable(request, response):
            return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        # Get response body
        if hasattr(response, 'body'):
            body = response.body
        else:
            return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        if isinstance(body, str):
            body = body.encode('utf-8')
        elif not isinstance(body, bytes):
            # Handle non-string, non-bytes objects (like Mock objects)
            try:
                body_str = str(body)
                body = body_str.encode('utf-8')
            except Exception:
                return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        # Check minimum size
        try:
            if len(body) < self.config.min_size:
                return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        except TypeError:
            # Handle objects without len() method
            return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        # Compress the body
        try:
            if self.config.method == CompressionMethod.GZIP:
                compressed_body = gzip.compress(body, compresslevel=self.config.level)
                encoding = "gzip"
            elif self.config.method == CompressionMethod.DEFLATE:
                compressed_body = zlib.compress(body, level=self.config.level)
                encoding = "deflate"
            else:
                return PostprocessingResult(action=PostprocessingAction.CONTINUE)
            
            # Update headers
            headers = dict(response.headers)
            headers["content-encoding"] = encoding
            headers["content-length"] = str(len(compressed_body))
            
            return PostprocessingResult(
                action=PostprocessingAction.TRANSFORM,
                body=compressed_body,
                headers=headers
            )
        except Exception as e:
            return PostprocessingResult(
                action=PostprocessingAction.CONTINUE,
                reason=f"Compression failed: {str(e)}"
            )


class PostprocessingShield(Shield):
    """Enhanced shield with response postprocessing capabilities."""
    
    def __init__(self, shield_func, postprocessors: Optional[List[ResponsePostprocessor]] = None,
                 **kwargs):
        """Initialize postprocessing shield.
        
        Args:
            shield_func: The shield function
            postprocessors: List of postprocessors to apply
            **kwargs: Additional arguments passed to Shield
        """
        super().__init__(shield_func, **kwargs)
        self.postprocessors = postprocessors or []
    
    def add_postprocessor(self, postprocessor: ResponsePostprocessor) -> None:
        """Add a postprocessor to this shield."""
        self.postprocessors.append(postprocessor)
    
    def remove_postprocessor(self, name: str) -> bool:
        """Remove a postprocessor by name."""
        for i, processor in enumerate(self.postprocessors):
            if processor.name == name:
                del self.postprocessors[i]
                return True
        return False
    
    async def _apply_postprocessors(self, request: Request, response: Response,
                                   context: Dict[str, Any]) -> Response:
        """Apply all postprocessors to the response."""
        current_response = response
        
        for processor in self.postprocessors:
            try:
                result = await processor.process(request, current_response, context)
                
                if result.action == PostprocessingAction.BLOCK:
                    # Create error response
                    error_response = JSONResponse(
                        status_code=403,
                        content={"error": "Response blocked by content filter", 
                                "reason": result.reason}
                    )
                    return error_response
                
                elif result.action == PostprocessingAction.REPLACE:
                    if result.response:
                        current_response = result.response
                
                elif result.action == PostprocessingAction.TRANSFORM:
                    # Apply transformations
                    if result.headers:
                        # Create new response with updated headers
                        if hasattr(current_response, 'body'):
                            content = result.body if result.body is not None else current_response.body
                        else:
                            content = result.body
                        
                        # Ensure content is properly encoded
                        if isinstance(content, str):
                            content = content.encode('utf-8')
                        
                        new_response = Response(
                            content=content,
                            status_code=current_response.status_code,
                            headers=result.headers,
                            media_type=current_response.headers.get("content-type")
                        )
                        current_response = new_response
                    elif result.body is not None:
                        # Update body only
                        content = result.body
                        
                        # Ensure content is properly encoded
                        if isinstance(content, str):
                            content = content.encode('utf-8')
                        
                        new_response = Response(
                            content=content,
                            status_code=current_response.status_code,
                            headers=dict(current_response.headers),
                            media_type=current_response.headers.get("content-type")
                        )
                        current_response = new_response
                
            except Exception as e:
                # Continue processing if a postprocessor fails
                continue
        
        return current_response
    
    def __call__(self, endpoint: EndPointFunc) -> EndPointFunc:
        """Apply the postprocessing shield to an endpoint."""
        original_wrapper = super().__call__(endpoint)
        
        @wraps(original_wrapper)
        async def postprocessing_wrapper(*args, **kwargs):
            # Execute the original shielded endpoint
            response = await original_wrapper(*args, **kwargs)
            
            # Apply postprocessors if we have a valid response
            if isinstance(response, Response):
                request = kwargs.get('request')
                if request:
                    context = {"endpoint": endpoint, "args": args, "kwargs": kwargs}
                    response = await self._apply_postprocessors(request, response, context)
            elif response is not None and not isinstance(response, Response):
                # Convert non-Response objects to Response for postprocessing
                if isinstance(response, dict):
                    temp_response = JSONResponse(content=response)
                elif isinstance(response, str):
                    temp_response = PlainTextResponse(content=response)
                else:
                    temp_response = Response(content=str(response))
                
                request = kwargs.get('request')
                if request:
                    context = {"endpoint": endpoint, "args": args, "kwargs": kwargs}
                    response = await self._apply_postprocessors(request, temp_response, context)
            
            return response
        
        return postprocessing_wrapper


def postprocessing_shield(
    shield_func=None,
    /,
    postprocessors: Optional[List[ResponsePostprocessor]] = None,
    **kwargs
) -> Union[PostprocessingShield, Callable[[Any], PostprocessingShield]]:
    """Factory function for creating postprocessing shields.
    
    Args:
        shield_func: The shield function (optional)
        postprocessors: List of postprocessors to apply
        **kwargs: Additional arguments passed to PostprocessingShield
        
    Returns:
        PostprocessingShield instance or decorator function
    """
    if shield_func is None:
        return lambda func: postprocessing_shield(func, postprocessors=postprocessors, **kwargs)
    
    return PostprocessingShield(shield_func, postprocessors=postprocessors, **kwargs)


# Convenience functions for common postprocessors

def create_security_headers_processor(
    csp_policy: Optional[str] = None,
    hsts_max_age: int = 31536000,
    custom_headers: Optional[Dict[str, str]] = None
) -> SecurityHeaderProcessor:
    """Create a security headers processor with common configuration."""
    config = SecurityHeaderConfig(
        csp_policy=csp_policy,
        hsts_max_age=hsts_max_age,
        custom_headers=custom_headers or {}
    )
    return SecurityHeaderProcessor(config=config)


def create_compression_processor(
    method: CompressionMethod = CompressionMethod.GZIP,
    min_size: int = 1024,
    level: int = 6
) -> CompressionProcessor:
    """Create a compression processor with specified configuration."""
    config = CompressionConfig(method=method, min_size=min_size, level=level)
    return CompressionProcessor(config=config)


def create_content_filter(
    blocked_patterns: Optional[List[str]] = None,
    sanitize_html: bool = True
) -> ContentFilter:
    """Create a content filter with basic security rules."""
    return ContentFilter(
        blocked_patterns=blocked_patterns or [],
        sanitize_html=sanitize_html
    )