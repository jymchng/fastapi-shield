"""Request preprocessing system for FastAPI Shield.

This module provides comprehensive request preprocessing capabilities including
header manipulation, body transformation, URL rewriting, query parameter modification,
and request routing/redirection.
"""

import asyncio
import json
import re
import urllib.parse
from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Set, Tuple, Union, Callable, Type,
    Pattern, Awaitable, AsyncIterator
)
import logging
from collections import defaultdict, deque

from fastapi import Request, Response, HTTPException, status
from fastapi.datastructures import Headers, QueryParams
from starlette.datastructures import MutableHeaders
from starlette.requests import Request as StarletteRequest
from starlette.responses import RedirectResponse
from starlette.types import Scope, Receive, Send

from fastapi_shield.shield import Shield

logger = logging.getLogger(__name__)


class PreprocessingAction(str, Enum):
    """Actions that can be performed during preprocessing."""
    CONTINUE = "continue"
    REDIRECT = "redirect"
    BLOCK = "block"
    MODIFY = "modify"
    FORWARD = "forward"


class PreprocessingPriority(int, Enum):
    """Priority levels for preprocessing operations."""
    LOWEST = 1
    LOW = 25
    NORMAL = 50
    HIGH = 75
    HIGHEST = 100


class TransformationScope(str, Enum):
    """Scope of transformation operations."""
    HEADERS = "headers"
    BODY = "body"
    URL = "url"
    QUERY_PARAMS = "query_params"
    PATH = "path"
    METHOD = "method"
    ALL = "all"


class BodyFormat(str, Enum):
    """Supported body formats for transformation."""
    JSON = "json"
    XML = "xml"
    FORM = "form"
    TEXT = "text"
    BINARY = "binary"
    MULTIPART = "multipart"


@dataclass
class PreprocessingResult:
    """Result of a preprocessing operation."""
    action: PreprocessingAction
    modified_request: Optional[Request] = None
    redirect_url: Optional[str] = None
    response: Optional[Response] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize performance metrics."""
        if not self.performance_metrics:
            self.performance_metrics = {
                "processing_time_ms": 0.0,
                "memory_usage_bytes": 0,
                "transformations_applied": 0
            }


@dataclass
class HeaderRule:
    """Rule for header manipulation."""
    action: str  # add, remove, modify, replace
    header_name: str
    header_value: Optional[str] = None
    condition: Optional[Callable[[Headers], bool]] = None
    pattern: Optional[Pattern] = None
    replacement: Optional[str] = None
    case_sensitive: bool = True


@dataclass
class BodyTransformation:
    """Body transformation configuration."""
    source_format: BodyFormat
    target_format: BodyFormat
    transformation_function: Callable[[Any], Any]
    condition: Optional[Callable[[bytes], bool]] = None
    preserve_encoding: bool = True
    max_size_bytes: Optional[int] = None


@dataclass
class URLRewriteRule:
    """URL rewriting rule."""
    pattern: Pattern
    replacement: str
    redirect: bool = False
    permanent: bool = False
    condition: Optional[Callable[[str], bool]] = None
    preserve_query: bool = True
    case_sensitive: bool = True


@dataclass
class QueryParamRule:
    """Query parameter manipulation rule."""
    action: str  # add, remove, modify, replace
    param_name: str
    param_value: Optional[str] = None
    condition: Optional[Callable[[QueryParams], bool]] = None
    pattern: Optional[Pattern] = None
    replacement: Optional[str] = None


@dataclass
class PreprocessingConfig:
    """Configuration for request preprocessing."""
    enabled: bool = True
    max_processing_time_ms: float = 1000.0
    max_body_size_bytes: int = 10 * 1024 * 1024  # 10MB
    enable_caching: bool = True
    cache_ttl_seconds: int = 300
    enable_metrics: bool = True
    enable_logging: bool = True
    fail_on_error: bool = False
    priority: PreprocessingPriority = PreprocessingPriority.NORMAL
    scopes: Set[TransformationScope] = field(default_factory=lambda: {TransformationScope.ALL})


class RequestPreprocessor(ABC):
    """Abstract base class for request preprocessors."""
    
    def __init__(
        self,
        name: str,
        priority: PreprocessingPriority = PreprocessingPriority.NORMAL,
        enabled: bool = True
    ):
        self.name = name
        self.priority = priority
        self.enabled = enabled
        self.metrics = {
            "requests_processed": 0,
            "requests_modified": 0,
            "requests_blocked": 0,
            "requests_redirected": 0,
            "total_processing_time_ms": 0.0,
            "errors_encountered": 0
        }
    
    @abstractmethod
    async def process(self, request: Request) -> PreprocessingResult:
        """Process the request and return the result."""
        pass
    
    def reset_metrics(self):
        """Reset preprocessing metrics."""
        for key in self.metrics:
            self.metrics[key] = 0 if isinstance(self.metrics[key], int) else 0.0
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get preprocessing metrics."""
        return {
            "name": self.name,
            "priority": self.priority.value,
            "enabled": self.enabled,
            **self.metrics
        }


class HeaderManipulator(RequestPreprocessor):
    """Preprocessor for header manipulation."""
    
    def __init__(
        self,
        name: str = "HeaderManipulator",
        priority: PreprocessingPriority = PreprocessingPriority.NORMAL,
        enabled: bool = True
    ):
        super().__init__(name, priority, enabled)
        self.rules: List[HeaderRule] = []
    
    def add_rule(self, rule: HeaderRule):
        """Add a header manipulation rule."""
        self.rules.append(rule)
    
    def add_header_rule(
        self,
        action: str,
        header_name: str,
        header_value: Optional[str] = None,
        condition: Optional[Callable[[Headers], bool]] = None,
        pattern: Optional[Union[str, Pattern]] = None,
        replacement: Optional[str] = None,
        case_sensitive: bool = True
    ):
        """Add a header rule with convenience method."""
        if isinstance(pattern, str):
            flags = 0 if case_sensitive else re.IGNORECASE
            pattern = re.compile(pattern, flags)
        
        rule = HeaderRule(
            action=action,
            header_name=header_name,
            header_value=header_value,
            condition=condition,
            pattern=pattern,
            replacement=replacement,
            case_sensitive=case_sensitive
        )
        self.add_rule(rule)
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Process header manipulation rules."""
        if not self.enabled:
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)
        
        start_time = datetime.now()
        self.metrics["requests_processed"] += 1
        
        try:
            # Create a new scope with mutable headers
            scope = dict(request.scope)
            headers = {k.lower(): v for k, v in request.headers.items()}
            modified = False
            
            for rule in self.rules:
                if rule.condition and not rule.condition(Headers(headers)):
                    continue
                
                header_key = rule.header_name.lower()
                
                if rule.action == "add":
                    if rule.header_value is not None:
                        headers[header_key] = rule.header_value
                        modified = True
                
                elif rule.action == "remove":
                    if header_key in headers:
                        del headers[header_key]
                        modified = True
                
                elif rule.action == "modify" and rule.pattern and rule.replacement:
                    if header_key in headers:
                        old_value = headers[header_key]
                        new_value = rule.pattern.sub(rule.replacement, old_value)
                        if new_value != old_value:
                            headers[header_key] = new_value
                            modified = True
                
                elif rule.action == "replace":
                    if header_key in headers and rule.header_value is not None:
                        headers[header_key] = rule.header_value
                        modified = True
            
            if modified:
                # Update scope headers
                scope["headers"] = [
                    (key.encode(), value.encode())
                    for key, value in headers.items()
                ]
                
                # Create new request with modified headers
                modified_request = Request(scope, request.receive)
                self.metrics["requests_modified"] += 1
                
                result = PreprocessingResult(
                    action=PreprocessingAction.MODIFY,
                    modified_request=modified_request
                )
            else:
                result = PreprocessingResult(action=PreprocessingAction.CONTINUE)
            
            # Update metrics
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            self.metrics["total_processing_time_ms"] += processing_time
            result.performance_metrics["processing_time_ms"] = processing_time
            
            return result
            
        except Exception as e:
            self.metrics["errors_encountered"] += 1
            logger.error(f"Error in header manipulation: {e}")
            
            if hasattr(self, 'fail_on_error') and getattr(self, 'fail_on_error'):
                raise
            
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)


class BodyTransformer(RequestPreprocessor):
    """Preprocessor for body transformation."""
    
    def __init__(
        self,
        name: str = "BodyTransformer",
        priority: PreprocessingPriority = PreprocessingPriority.NORMAL,
        enabled: bool = True,
        max_body_size: int = 10 * 1024 * 1024
    ):
        super().__init__(name, priority, enabled)
        self.transformations: List[BodyTransformation] = []
        self.max_body_size = max_body_size
    
    def add_transformation(self, transformation: BodyTransformation):
        """Add a body transformation."""
        self.transformations.append(transformation)
    
    def add_json_transformation(
        self,
        transformation_function: Callable[[Dict], Dict],
        condition: Optional[Callable[[bytes], bool]] = None,
        max_size_bytes: Optional[int] = None
    ):
        """Add JSON transformation with convenience method."""
        transformation = BodyTransformation(
            source_format=BodyFormat.JSON,
            target_format=BodyFormat.JSON,
            transformation_function=transformation_function,
            condition=condition,
            max_size_bytes=max_size_bytes
        )
        self.add_transformation(transformation)
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Process body transformations."""
        if not self.enabled:
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)
        
        start_time = datetime.now()
        self.metrics["requests_processed"] += 1
        
        try:
            # Check if request has body
            if not hasattr(request, '_body') and request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
            else:
                body = getattr(request, '_body', b'')
            
            if not body:
                return PreprocessingResult(action=PreprocessingAction.CONTINUE)
            
            # Check body size
            if len(body) > self.max_body_size:
                logger.warning(f"Body size {len(body)} exceeds limit {self.max_body_size}")
                return PreprocessingResult(action=PreprocessingAction.CONTINUE)
            
            modified_body = body
            content_type = request.headers.get("content-type", "").lower()
            
            for transformation in self.transformations:
                # Check transformation size limit
                if transformation.max_size_bytes and len(modified_body) > transformation.max_size_bytes:
                    continue
                
                # Check condition
                if transformation.condition and not transformation.condition(modified_body):
                    continue
                
                # Apply transformation based on format
                if transformation.source_format == BodyFormat.JSON and "json" in content_type:
                    try:
                        data = json.loads(modified_body.decode('utf-8'))
                        transformed_data = transformation.transformation_function(data)
                        modified_body = json.dumps(transformed_data).encode('utf-8')
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        logger.warning(f"JSON transformation failed: {e}")
                        continue
                
                elif transformation.source_format == BodyFormat.TEXT:
                    try:
                        text = modified_body.decode('utf-8')
                        transformed_text = transformation.transformation_function(text)
                        modified_body = transformed_text.encode('utf-8')
                    except UnicodeDecodeError as e:
                        logger.warning(f"Text transformation failed: {e}")
                        continue
                
                elif transformation.source_format == BodyFormat.FORM and "form" in content_type:
                    try:
                        # Parse form data
                        form_data = urllib.parse.parse_qs(modified_body.decode('utf-8'))
                        transformed_data = transformation.transformation_function(form_data)
                        modified_body = urllib.parse.urlencode(transformed_data, doseq=True).encode('utf-8')
                    except (UnicodeDecodeError, ValueError) as e:
                        logger.warning(f"Form transformation failed: {e}")
                        continue
            
            if modified_body != body:
                # Create new request with modified body
                scope = dict(request.scope)
                
                async def receive():
                    return {
                        "type": "http.request",
                        "body": modified_body,
                        "more_body": False
                    }
                
                modified_request = Request(scope, receive)
                # Cache the body on the request
                modified_request._body = modified_body
                
                self.metrics["requests_modified"] += 1
                
                result = PreprocessingResult(
                    action=PreprocessingAction.MODIFY,
                    modified_request=modified_request
                )
            else:
                result = PreprocessingResult(action=PreprocessingAction.CONTINUE)
            
            # Update metrics
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            self.metrics["total_processing_time_ms"] += processing_time
            result.performance_metrics["processing_time_ms"] = processing_time
            result.performance_metrics["transformations_applied"] = len([
                t for t in self.transformations 
                if not t.condition or t.condition(body)
            ])
            
            return result
            
        except Exception as e:
            self.metrics["errors_encountered"] += 1
            logger.error(f"Error in body transformation: {e}")
            
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)


class URLRewriter(RequestPreprocessor):
    """Preprocessor for URL rewriting and redirection."""
    
    def __init__(
        self,
        name: str = "URLRewriter",
        priority: PreprocessingPriority = PreprocessingPriority.HIGH,
        enabled: bool = True
    ):
        super().__init__(name, priority, enabled)
        self.rules: List[URLRewriteRule] = []
    
    def add_rule(self, rule: URLRewriteRule):
        """Add a URL rewrite rule."""
        self.rules.append(rule)
    
    def add_rewrite_rule(
        self,
        pattern: Union[str, Pattern],
        replacement: str,
        redirect: bool = False,
        permanent: bool = False,
        condition: Optional[Callable[[str], bool]] = None,
        preserve_query: bool = True,
        case_sensitive: bool = True
    ):
        """Add URL rewrite rule with convenience method."""
        if isinstance(pattern, str):
            flags = 0 if case_sensitive else re.IGNORECASE
            pattern = re.compile(pattern, flags)
        
        rule = URLRewriteRule(
            pattern=pattern,
            replacement=replacement,
            redirect=redirect,
            permanent=permanent,
            condition=condition,
            preserve_query=preserve_query,
            case_sensitive=case_sensitive
        )
        self.add_rule(rule)
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Process URL rewriting rules."""
        if not self.enabled:
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)
        
        start_time = datetime.now()
        self.metrics["requests_processed"] += 1
        
        try:
            original_path = request.url.path
            original_query = str(request.query_params)
            full_url = str(request.url)
            
            for rule in self.rules:
                if rule.condition and not rule.condition(original_path):
                    continue
                
                # Check if pattern matches
                match = rule.pattern.search(original_path)
                if not match:
                    continue
                
                # Apply replacement
                new_path = rule.pattern.sub(rule.replacement, original_path)
                
                if rule.redirect:
                    # Build redirect URL
                    redirect_url = new_path
                    if rule.preserve_query and original_query:
                        redirect_url = f"{new_path}?{original_query}"
                    
                    status_code = status.HTTP_301_MOVED_PERMANENTLY if rule.permanent else status.HTTP_302_FOUND
                    response = RedirectResponse(url=redirect_url, status_code=status_code)
                    
                    self.metrics["requests_redirected"] += 1
                    
                    result = PreprocessingResult(
                        action=PreprocessingAction.REDIRECT,
                        redirect_url=redirect_url,
                        response=response
                    )
                else:
                    # Modify request path
                    scope = dict(request.scope)
                    scope["path"] = new_path
                    
                    # Update raw_path for consistency
                    query_part = f"?{original_query}" if original_query and rule.preserve_query else ""
                    scope["raw_path"] = f"{new_path}{query_part}".encode()
                    
                    modified_request = Request(scope, request.receive)
                    
                    self.metrics["requests_modified"] += 1
                    
                    result = PreprocessingResult(
                        action=PreprocessingAction.MODIFY,
                        modified_request=modified_request
                    )
                
                # Update metrics
                processing_time = (datetime.now() - start_time).total_seconds() * 1000
                self.metrics["total_processing_time_ms"] += processing_time
                result.performance_metrics["processing_time_ms"] = processing_time
                
                return result
            
            # No rules matched
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)
            
        except Exception as e:
            self.metrics["errors_encountered"] += 1
            logger.error(f"Error in URL rewriting: {e}")
            
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)


class QueryParamManipulator(RequestPreprocessor):
    """Preprocessor for query parameter manipulation."""
    
    def __init__(
        self,
        name: str = "QueryParamManipulator",
        priority: PreprocessingPriority = PreprocessingPriority.NORMAL,
        enabled: bool = True
    ):
        super().__init__(name, priority, enabled)
        self.rules: List[QueryParamRule] = []
    
    def add_rule(self, rule: QueryParamRule):
        """Add a query parameter manipulation rule."""
        self.rules.append(rule)
    
    def add_param_rule(
        self,
        action: str,
        param_name: str,
        param_value: Optional[str] = None,
        condition: Optional[Callable[[QueryParams], bool]] = None,
        pattern: Optional[Union[str, Pattern]] = None,
        replacement: Optional[str] = None
    ):
        """Add query parameter rule with convenience method."""
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        
        rule = QueryParamRule(
            action=action,
            param_name=param_name,
            param_value=param_value,
            condition=condition,
            pattern=pattern,
            replacement=replacement
        )
        self.add_rule(rule)
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Process query parameter manipulation rules."""
        if not self.enabled:
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)
        
        start_time = datetime.now()
        self.metrics["requests_processed"] += 1
        
        try:
            query_params = dict(request.query_params)
            original_params = query_params.copy()
            modified = False
            
            for rule in self.rules:
                if rule.condition and not rule.condition(QueryParams(query_params)):
                    continue
                
                if rule.action == "add":
                    if rule.param_value is not None:
                        query_params[rule.param_name] = rule.param_value
                        modified = True
                
                elif rule.action == "remove":
                    if rule.param_name in query_params:
                        del query_params[rule.param_name]
                        modified = True
                
                elif rule.action == "modify" and rule.pattern and rule.replacement:
                    if rule.param_name in query_params:
                        old_value = query_params[rule.param_name]
                        new_value = rule.pattern.sub(rule.replacement, old_value)
                        if new_value != old_value:
                            query_params[rule.param_name] = new_value
                            modified = True
                
                elif rule.action == "replace":
                    if rule.param_name in query_params and rule.param_value is not None:
                        query_params[rule.param_name] = rule.param_value
                        modified = True
            
            if modified:
                # Build new query string
                query_string = urllib.parse.urlencode(query_params)
                
                # Update scope
                scope = dict(request.scope)
                scope["query_string"] = query_string.encode()
                
                # Update raw_path to include new query string
                path = scope.get("path", "/")
                scope["raw_path"] = f"{path}?{query_string}".encode() if query_string else path.encode()
                
                modified_request = Request(scope, request.receive)
                
                self.metrics["requests_modified"] += 1
                
                result = PreprocessingResult(
                    action=PreprocessingAction.MODIFY,
                    modified_request=modified_request
                )
            else:
                result = PreprocessingResult(action=PreprocessingAction.CONTINUE)
            
            # Update metrics
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            self.metrics["total_processing_time_ms"] += processing_time
            result.performance_metrics["processing_time_ms"] = processing_time
            
            return result
            
        except Exception as e:
            self.metrics["errors_encountered"] += 1
            logger.error(f"Error in query parameter manipulation: {e}")
            
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)


class ConditionalPreprocessor(RequestPreprocessor):
    """Preprocessor that applies other preprocessors based on conditions."""
    
    def __init__(
        self,
        name: str = "ConditionalPreprocessor",
        priority: PreprocessingPriority = PreprocessingPriority.NORMAL,
        enabled: bool = True
    ):
        super().__init__(name, priority, enabled)
        self.conditional_processors: List[Tuple[Callable[[Request], bool], RequestPreprocessor]] = []
    
    def add_conditional_processor(
        self,
        condition: Callable[[Request], bool],
        processor: RequestPreprocessor
    ):
        """Add a conditional processor."""
        self.conditional_processors.append((condition, processor))
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Process conditional preprocessors."""
        if not self.enabled:
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)
        
        start_time = datetime.now()
        self.metrics["requests_processed"] += 1
        
        try:
            for condition, processor in self.conditional_processors:
                if condition(request):
                    result = await processor.process(request)
                    
                    # Update combined metrics
                    if result.action != PreprocessingAction.CONTINUE:
                        if result.action == PreprocessingAction.MODIFY:
                            self.metrics["requests_modified"] += 1
                        elif result.action == PreprocessingAction.BLOCK:
                            self.metrics["requests_blocked"] += 1
                        elif result.action == PreprocessingAction.REDIRECT:
                            self.metrics["requests_redirected"] += 1
                    
                    processing_time = (datetime.now() - start_time).total_seconds() * 1000
                    self.metrics["total_processing_time_ms"] += processing_time
                    
                    return result
            
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)
            
        except Exception as e:
            self.metrics["errors_encountered"] += 1
            logger.error(f"Error in conditional preprocessing: {e}")
            
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)


class PreprocessingPipeline:
    """Pipeline for orchestrating multiple request preprocessors."""
    
    def __init__(
        self,
        name: str = "DefaultPipeline",
        config: Optional[PreprocessingConfig] = None
    ):
        self.name = name
        self.config = config or PreprocessingConfig()
        self.processors: List[RequestPreprocessor] = []
        self.cache: Dict[str, PreprocessingResult] = {}
        self.pipeline_metrics = {
            "requests_processed": 0,
            "requests_cached": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "total_processing_time_ms": 0.0,
            "pipeline_errors": 0
        }
    
    def add_processor(self, processor: RequestPreprocessor):
        """Add a preprocessor to the pipeline."""
        self.processors.append(processor)
        # Sort by priority (highest first)
        self.processors.sort(key=lambda p: p.priority.value, reverse=True)
    
    def remove_processor(self, name: str) -> bool:
        """Remove a preprocessor by name."""
        for i, processor in enumerate(self.processors):
            if processor.name == name:
                del self.processors[i]
                return True
        return False
    
    def get_processor(self, name: str) -> Optional[RequestPreprocessor]:
        """Get a preprocessor by name."""
        for processor in self.processors:
            if processor.name == name:
                return processor
        return None
    
    def _get_cache_key(self, request: Request) -> str:
        """Generate cache key for request."""
        return f"{request.method}:{request.url.path}:{hash(str(request.headers))}"
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Process request through the pipeline."""
        start_time = datetime.now()
        self.pipeline_metrics["requests_processed"] += 1
        
        try:
            # Check cache if enabled
            cache_key = None
            if self.config.enable_caching:
                cache_key = self._get_cache_key(request)
                if cache_key in self.cache:
                    self.pipeline_metrics["cache_hits"] += 1
                    self.pipeline_metrics["requests_cached"] += 1
                    return self.cache[cache_key]
                else:
                    self.pipeline_metrics["cache_misses"] += 1
            
            current_request = request
            final_result = PreprocessingResult(action=PreprocessingAction.CONTINUE)
            
            for processor in self.processors:
                if not processor.enabled:
                    continue
                
                result = await processor.process(current_request)
                
                if result.action == PreprocessingAction.BLOCK:
                    final_result = result
                    break
                elif result.action == PreprocessingAction.REDIRECT:
                    final_result = result
                    break
                elif result.action == PreprocessingAction.MODIFY and result.modified_request:
                    current_request = result.modified_request
                    final_result = result
                
                # Combine performance metrics
                for key, value in result.performance_metrics.items():
                    if key in final_result.performance_metrics:
                        if isinstance(value, (int, float)):
                            final_result.performance_metrics[key] += value
                    else:
                        final_result.performance_metrics[key] = value
            
            # Update final request if modified
            if current_request != request:
                final_result.modified_request = current_request
                if final_result.action == PreprocessingAction.CONTINUE:
                    final_result.action = PreprocessingAction.MODIFY
            
            # Cache result if enabled
            if self.config.enable_caching and cache_key and final_result.action != PreprocessingAction.BLOCK:
                self.cache[cache_key] = final_result
            
            # Update metrics
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            self.pipeline_metrics["total_processing_time_ms"] += processing_time
            final_result.performance_metrics["total_pipeline_time_ms"] = processing_time
            
            return final_result
            
        except Exception as e:
            self.pipeline_metrics["pipeline_errors"] += 1
            logger.error(f"Error in preprocessing pipeline: {e}")
            
            if self.config.fail_on_error:
                raise
            
            return PreprocessingResult(action=PreprocessingAction.CONTINUE)
    
    def clear_cache(self):
        """Clear the preprocessing cache."""
        self.cache.clear()
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get pipeline metrics."""
        processor_metrics = [p.get_metrics() for p in self.processors]
        
        return {
            "pipeline_name": self.name,
            "pipeline_metrics": self.pipeline_metrics,
            "processor_count": len(self.processors),
            "processors": processor_metrics,
            "cache_size": len(self.cache),
            "config": {
                "enabled": self.config.enabled,
                "max_processing_time_ms": self.config.max_processing_time_ms,
                "enable_caching": self.config.enable_caching,
                "cache_ttl_seconds": self.config.cache_ttl_seconds
            }
        }
    
    def reset_metrics(self):
        """Reset all metrics."""
        for key in self.pipeline_metrics:
            self.pipeline_metrics[key] = 0 if isinstance(self.pipeline_metrics[key], int) else 0.0
        
        for processor in self.processors:
            processor.reset_metrics()


class PreprocessingShield(Shield):
    """Shield that applies request preprocessing."""
    
    def __init__(
        self,
        pipeline: PreprocessingPipeline,
        name: str = "PreprocessingShield",
        auto_error: bool = True
    ):
        self.pipeline = pipeline
        super().__init__(self._preprocess_request, name=name, auto_error=auto_error)
    
    async def _preprocess_request(self, request: Request) -> Union[Request, Response, bool]:
        """Preprocess the request through the pipeline."""
        result = await self.pipeline.process(request)
        
        if result.action == PreprocessingAction.BLOCK:
            if result.response:
                return result.response
            return False
        elif result.action == PreprocessingAction.REDIRECT:
            if result.response:
                return result.response
            return RedirectResponse(url=result.redirect_url)
        elif result.action == PreprocessingAction.MODIFY:
            return result.modified_request or request
        else:
            return request


# Convenience functions for creating common preprocessors

def create_header_security_preprocessor() -> HeaderManipulator:
    """Create a preprocessor for security headers."""
    processor = HeaderManipulator(name="SecurityHeaders", priority=PreprocessingPriority.HIGH)
    
    # Add security headers
    processor.add_header_rule("add", "X-Content-Type-Options", "nosniff")
    processor.add_header_rule("add", "X-Frame-Options", "DENY")
    processor.add_header_rule("add", "X-XSS-Protection", "1; mode=block")
    processor.add_header_rule("add", "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    
    # Remove potentially dangerous headers
    processor.add_header_rule("remove", "Server")
    processor.add_header_rule("remove", "X-Powered-By")
    
    return processor


def create_cors_preprocessor(
    allowed_origins: List[str],
    allowed_methods: List[str] = None,
    allowed_headers: List[str] = None
) -> HeaderManipulator:
    """Create a CORS preprocessor."""
    processor = HeaderManipulator(name="CORS", priority=PreprocessingPriority.HIGH)
    
    if allowed_methods is None:
        allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    
    if allowed_headers is None:
        allowed_headers = ["Content-Type", "Authorization"]
    
    # Add CORS headers
    processor.add_header_rule("add", "Access-Control-Allow-Origin", ",".join(allowed_origins))
    processor.add_header_rule("add", "Access-Control-Allow-Methods", ",".join(allowed_methods))
    processor.add_header_rule("add", "Access-Control-Allow-Headers", ",".join(allowed_headers))
    processor.add_header_rule("add", "Access-Control-Allow-Credentials", "true")
    
    return processor


def create_json_validator_preprocessor(
    schema: Dict[str, Any],
    block_invalid: bool = True
) -> BodyTransformer:
    """Create a JSON validation preprocessor."""
    processor = BodyTransformer(name="JSONValidator", priority=PreprocessingPriority.NORMAL)
    
    def validate_json(data: Dict) -> Dict:
        # Simple validation - in production, use jsonschema
        if not isinstance(data, dict):
            if block_invalid:
                raise ValueError("Invalid JSON structure")
        return data
    
    processor.add_json_transformation(validate_json)
    
    return processor


def create_url_normalizer_preprocessor() -> URLRewriter:
    """Create a URL normalizer preprocessor."""
    processor = URLRewriter(name="URLNormalizer", priority=PreprocessingPriority.HIGHEST)
    
    # Remove double slashes
    processor.add_rewrite_rule(r"/+", "/", case_sensitive=False)
    
    # Remove trailing slashes (except root)
    processor.add_rewrite_rule(r"^(.+)/$", r"\1", case_sensitive=False)
    
    return processor


def create_api_version_preprocessor(default_version: str = "v1") -> QueryParamManipulator:
    """Create an API version preprocessor."""
    processor = QueryParamManipulator(name="APIVersion", priority=PreprocessingPriority.HIGH)
    
    # Add default version if not present
    def needs_version(params: QueryParams) -> bool:
        return "version" not in params and "v" not in params
    
    processor.add_param_rule("add", "version", default_version, condition=needs_version)
    
    return processor


def create_preprocessing_pipeline(
    security_headers: bool = True,
    cors_origins: Optional[List[str]] = None,
    url_normalization: bool = True,
    api_versioning: Optional[str] = None
) -> PreprocessingPipeline:
    """Create a common preprocessing pipeline."""
    pipeline = PreprocessingPipeline(name="CommonPreprocessing")
    
    if url_normalization:
        pipeline.add_processor(create_url_normalizer_preprocessor())
    
    if security_headers:
        pipeline.add_processor(create_header_security_preprocessor())
    
    if cors_origins:
        pipeline.add_processor(create_cors_preprocessor(cors_origins))
    
    if api_versioning:
        pipeline.add_processor(create_api_version_preprocessor(api_versioning))
    
    return pipeline


# FastAPI integration
def setup_preprocessing_middleware(app, pipeline: PreprocessingPipeline):
    """Set up preprocessing middleware for FastAPI application."""
    from fastapi.middleware.base import BaseHTTPMiddleware
    
    class RequestPreprocessingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            result = await pipeline.process(request)
            
            if result.action == PreprocessingAction.BLOCK and result.response:
                return result.response
            elif result.action == PreprocessingAction.REDIRECT and result.response:
                return result.response
            elif result.action == PreprocessingAction.MODIFY and result.modified_request:
                request = result.modified_request
            
            response = await call_next(request)
            return response
    
    app.add_middleware(RequestPreprocessingMiddleware)
    return app