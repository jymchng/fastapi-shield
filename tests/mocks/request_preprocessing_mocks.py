"""Mock classes and utilities for testing request preprocessing."""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable, Pattern, Union
from unittest.mock import MagicMock, AsyncMock

from fastapi import Request, Response
from fastapi.datastructures import Headers, QueryParams
from starlette.datastructures import URL
from starlette.requests import Request as StarletteRequest

from fastapi_shield.request_preprocessing import (
    PreprocessingResult, PreprocessingAction, PreprocessingPriority,
    TransformationScope, BodyFormat, HeaderRule, BodyTransformation,
    URLRewriteRule, QueryParamRule, PreprocessingConfig,
    RequestPreprocessor
)


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(
        self,
        method: str = "GET",
        url_path: str = "/test",
        query_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
        host: str = "testserver",
        port: int = 80,
        scheme: str = "http"
    ):
        self.method = method
        self.query_params = QueryParams(query_params or {})
        self.headers = Headers(headers or {})
        self._body = body
        self._host = host
        self._port = port
        self._scheme = scheme
        self._url_path = url_path
        
        # Create URL
        query_string = "&".join(f"{k}={v}" for k, v in (query_params or {}).items())
        url_string = f"{scheme}://{host}:{port}{url_path}"
        if query_string:
            url_string += f"?{query_string}"
        self.url = URL(url_string)
        
        # Create scope
        self.scope = {
            "type": "http",
            "method": method,
            "path": url_path,
            "raw_path": url_path.encode(),
            "query_string": query_string.encode(),
            "headers": [
                (k.lower().encode(), v.encode()) 
                for k, v in (headers or {}).items()
            ],
            "server": (host, port),
            "scheme": scheme
        }
        
        # Mock receive function
        self._body_sent = False
        
    async def receive(self):
        """Mock receive function."""
        if not self._body_sent:
            self._body_sent = True
            return {
                "type": "http.request",
                "body": self._body,
                "more_body": False
            }
        return {
            "type": "http.disconnect"
        }
    
    async def body(self) -> bytes:
        """Get request body."""
        return self._body
    
    async def json(self) -> Any:
        """Get request body as JSON."""
        return json.loads(self._body.decode())
    
    async def form(self) -> Dict[str, Any]:
        """Get request body as form data."""
        import urllib.parse
        return urllib.parse.parse_qs(self._body.decode())


class MockResponse:
    """Mock FastAPI response for testing."""
    
    def __init__(
        self,
        content: Any = None,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        media_type: Optional[str] = None
    ):
        self.content = content
        self.status_code = status_code
        self.headers = headers or {}
        self.media_type = media_type


class MockHeaderManipulator:
    """Mock header manipulator for testing."""
    
    def __init__(self):
        self.rules = []
        self.enabled = True
        self.name = "MockHeaderManipulator"
        self.priority = PreprocessingPriority.NORMAL
        self.metrics = {
            "requests_processed": 0,
            "requests_modified": 0,
            "requests_blocked": 0,
            "requests_redirected": 0,
            "total_processing_time_ms": 0.0,
            "errors_encountered": 0
        }
    
    def add_rule(self, rule: HeaderRule):
        """Add header rule."""
        self.rules.append(rule)
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Mock process method."""
        self.metrics["requests_processed"] += 1
        
        # Simple mock logic
        if "mock-block" in request.headers:
            self.metrics["requests_blocked"] += 1
            return PreprocessingResult(action=PreprocessingAction.BLOCK)
        
        if "mock-modify" in request.headers:
            self.metrics["requests_modified"] += 1
            # Create modified request
            headers = dict(request.headers)
            headers["x-mock-modified"] = "true"
            
            scope = dict(request.scope)
            scope["headers"] = [
                (k.lower().encode(), v.encode()) for k, v in headers.items()
            ]
            
            modified_request = Request(scope, request.receive)
            return PreprocessingResult(
                action=PreprocessingAction.MODIFY,
                modified_request=modified_request
            )
        
        return PreprocessingResult(action=PreprocessingAction.CONTINUE)
    
    def get_metrics(self):
        """Get metrics."""
        return {
            "name": self.name,
            "priority": self.priority.value,
            "enabled": self.enabled,
            **self.metrics
        }
    
    def reset_metrics(self):
        """Reset metrics."""
        for key in self.metrics:
            self.metrics[key] = 0 if isinstance(self.metrics[key], int) else 0.0


class MockBodyTransformer:
    """Mock body transformer for testing."""
    
    def __init__(self):
        self.transformations = []
        self.enabled = True
        self.name = "MockBodyTransformer"
        self.priority = PreprocessingPriority.NORMAL
        self.max_body_size = 10 * 1024 * 1024
        self.metrics = {
            "requests_processed": 0,
            "requests_modified": 0,
            "requests_blocked": 0,
            "requests_redirected": 0,
            "total_processing_time_ms": 0.0,
            "errors_encountered": 0
        }
    
    def add_transformation(self, transformation: BodyTransformation):
        """Add transformation."""
        self.transformations.append(transformation)
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Mock process method."""
        self.metrics["requests_processed"] += 1
        
        body = await request.body()
        
        if b"mock-transform" in body:
            self.metrics["requests_modified"] += 1
            
            # Create modified body
            modified_body = body.replace(b"mock-transform", b"transformed")
            
            # Create modified request
            scope = dict(request.scope)
            
            async def receive():
                return {
                    "type": "http.request",
                    "body": modified_body,
                    "more_body": False
                }
            
            modified_request = Request(scope, receive)
            modified_request._body = modified_body
            
            return PreprocessingResult(
                action=PreprocessingAction.MODIFY,
                modified_request=modified_request
            )
        
        return PreprocessingResult(action=PreprocessingAction.CONTINUE)
    
    def get_metrics(self):
        """Get metrics."""
        return {
            "name": self.name,
            "priority": self.priority.value,
            "enabled": self.enabled,
            **self.metrics
        }
    
    def reset_metrics(self):
        """Reset metrics."""
        for key in self.metrics:
            self.metrics[key] = 0 if isinstance(self.metrics[key], int) else 0.0


class MockURLRewriter:
    """Mock URL rewriter for testing."""
    
    def __init__(self):
        self.rules = []
        self.enabled = True
        self.name = "MockURLRewriter"
        self.priority = PreprocessingPriority.HIGH
        self.metrics = {
            "requests_processed": 0,
            "requests_modified": 0,
            "requests_blocked": 0,
            "requests_redirected": 0,
            "total_processing_time_ms": 0.0,
            "errors_encountered": 0
        }
    
    def add_rule(self, rule: URLRewriteRule):
        """Add rewrite rule."""
        self.rules.append(rule)
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Mock process method."""
        self.metrics["requests_processed"] += 1
        
        path = request.url.path
        
        if path.startswith("/mock-redirect"):
            self.metrics["requests_redirected"] += 1
            from starlette.responses import RedirectResponse
            response = RedirectResponse(url="/redirected", status_code=302)
            return PreprocessingResult(
                action=PreprocessingAction.REDIRECT,
                redirect_url="/redirected",
                response=response
            )
        
        if path.startswith("/mock-rewrite"):
            self.metrics["requests_modified"] += 1
            new_path = path.replace("/mock-rewrite", "/rewritten")
            
            scope = dict(request.scope)
            scope["path"] = new_path
            scope["raw_path"] = new_path.encode()
            
            modified_request = Request(scope, request.receive)
            return PreprocessingResult(
                action=PreprocessingAction.MODIFY,
                modified_request=modified_request
            )
        
        return PreprocessingResult(action=PreprocessingAction.CONTINUE)
    
    def get_metrics(self):
        """Get metrics."""
        return {
            "name": self.name,
            "priority": self.priority.value,
            "enabled": self.enabled,
            **self.metrics
        }
    
    def reset_metrics(self):
        """Reset metrics."""
        for key in self.metrics:
            self.metrics[key] = 0 if isinstance(self.metrics[key], int) else 0.0


class MockQueryParamManipulator:
    """Mock query parameter manipulator for testing."""
    
    def __init__(self):
        self.rules = []
        self.enabled = True
        self.name = "MockQueryParamManipulator"
        self.priority = PreprocessingPriority.NORMAL
        self.metrics = {
            "requests_processed": 0,
            "requests_modified": 0,
            "requests_blocked": 0,
            "requests_redirected": 0,
            "total_processing_time_ms": 0.0,
            "errors_encountered": 0
        }
    
    def add_rule(self, rule: QueryParamRule):
        """Add query param rule."""
        self.rules.append(rule)
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Mock process method."""
        self.metrics["requests_processed"] += 1
        
        query_params = dict(request.query_params)
        
        if "mock-modify" in query_params:
            self.metrics["requests_modified"] += 1
            
            # Add mock parameter
            query_params["modified"] = "true"
            
            # Build new query string
            import urllib.parse
            query_string = urllib.parse.urlencode(query_params)
            
            # Update scope
            scope = dict(request.scope)
            scope["query_string"] = query_string.encode()
            
            path = scope.get("path", "/")
            scope["raw_path"] = f"{path}?{query_string}".encode() if query_string else path.encode()
            
            modified_request = Request(scope, request.receive)
            return PreprocessingResult(
                action=PreprocessingAction.MODIFY,
                modified_request=modified_request
            )
        
        return PreprocessingResult(action=PreprocessingAction.CONTINUE)
    
    def get_metrics(self):
        """Get metrics."""
        return {
            "name": self.name,
            "priority": self.priority.value,
            "enabled": self.enabled,
            **self.metrics
        }
    
    def reset_metrics(self):
        """Reset metrics."""
        for key in self.metrics:
            self.metrics[key] = 0 if isinstance(self.metrics[key], int) else 0.0


class MockPreprocessingPipeline:
    """Mock preprocessing pipeline for testing."""
    
    def __init__(self, name: str = "MockPipeline"):
        self.name = name
        self.processors = []
        self.cache = {}
        self.config = PreprocessingConfig()
        self.pipeline_metrics = {
            "requests_processed": 0,
            "requests_cached": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "total_processing_time_ms": 0.0,
            "pipeline_errors": 0
        }
    
    def add_processor(self, processor):
        """Add processor to pipeline."""
        self.processors.append(processor)
        self.processors.sort(key=lambda p: p.priority.value, reverse=True)
    
    def remove_processor(self, name: str) -> bool:
        """Remove processor by name."""
        for i, processor in enumerate(self.processors):
            if processor.name == name:
                del self.processors[i]
                return True
        return False
    
    def get_processor(self, name: str):
        """Get processor by name."""
        for processor in self.processors:
            if processor.name == name:
                return processor
        return None
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Mock process method."""
        self.pipeline_metrics["requests_processed"] += 1
        
        # Simple mock logic
        if request.url.path == "/mock-block":
            return PreprocessingResult(action=PreprocessingAction.BLOCK)
        
        if request.url.path == "/mock-redirect":
            from starlette.responses import RedirectResponse
            response = RedirectResponse(url="/redirected")
            return PreprocessingResult(
                action=PreprocessingAction.REDIRECT,
                redirect_url="/redirected",
                response=response
            )
        
        # Process through mock processors
        current_request = request
        for processor in self.processors:
            if not processor.enabled:
                continue
            
            result = await processor.process(current_request)
            
            if result.action == PreprocessingAction.BLOCK:
                return result
            elif result.action == PreprocessingAction.REDIRECT:
                return result
            elif result.action == PreprocessingAction.MODIFY and result.modified_request:
                current_request = result.modified_request
        
        if current_request != request:
            return PreprocessingResult(
                action=PreprocessingAction.MODIFY,
                modified_request=current_request
            )
        
        return PreprocessingResult(action=PreprocessingAction.CONTINUE)
    
    def clear_cache(self):
        """Clear cache."""
        self.cache.clear()
    
    def get_metrics(self):
        """Get metrics."""
        return {
            "pipeline_name": self.name,
            "pipeline_metrics": self.pipeline_metrics,
            "processor_count": len(self.processors),
            "processors": [p.get_metrics() for p in self.processors],
            "cache_size": len(self.cache)
        }
    
    def reset_metrics(self):
        """Reset metrics."""
        for key in self.pipeline_metrics:
            self.pipeline_metrics[key] = 0 if isinstance(self.pipeline_metrics[key], int) else 0.0
        
        for processor in self.processors:
            processor.reset_metrics()


def create_mock_request(
    method: str = "GET",
    path: str = "/test",
    query_params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Union[str, bytes, Dict] = "",
    json_body: Optional[Dict] = None
) -> MockRequest:
    """Create a mock request with convenience parameters."""
    if json_body:
        body = json.dumps(json_body).encode()
        if not headers:
            headers = {}
        headers["content-type"] = "application/json"
    elif isinstance(body, str):
        body = body.encode()
    elif isinstance(body, dict):
        import urllib.parse
        body = urllib.parse.urlencode(body).encode()
        if not headers:
            headers = {}
        headers["content-type"] = "application/x-www-form-urlencoded"
    
    return MockRequest(
        method=method,
        url_path=path,
        query_params=query_params,
        headers=headers,
        body=body
    )


def create_mock_json_request(
    path: str = "/test",
    data: Optional[Dict] = None,
    method: str = "POST"
) -> MockRequest:
    """Create a mock JSON request."""
    return create_mock_request(
        method=method,
        path=path,
        json_body=data or {"test": "data"}
    )


def create_mock_form_request(
    path: str = "/test",
    data: Optional[Dict] = None,
    method: str = "POST"
) -> MockRequest:
    """Create a mock form request."""
    return create_mock_request(
        method=method,
        path=path,
        body=data or {"field1": "value1", "field2": "value2"}
    )


class MockRequestPreprocessor(RequestPreprocessor):
    """Mock request preprocessor for testing."""
    
    def __init__(
        self,
        name: str = "MockProcessor",
        priority: PreprocessingPriority = PreprocessingPriority.NORMAL,
        enabled: bool = True,
        mock_action: PreprocessingAction = PreprocessingAction.CONTINUE
    ):
        super().__init__(name, priority, enabled)
        self.mock_action = mock_action
        self.process_calls = []
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Mock process method."""
        self.process_calls.append(request)
        self.metrics["requests_processed"] += 1
        
        if self.mock_action == PreprocessingAction.BLOCK:
            self.metrics["requests_blocked"] += 1
            return PreprocessingResult(action=PreprocessingAction.BLOCK)
        elif self.mock_action == PreprocessingAction.REDIRECT:
            self.metrics["requests_redirected"] += 1
            from starlette.responses import RedirectResponse
            response = RedirectResponse(url="/mock-redirect")
            return PreprocessingResult(
                action=PreprocessingAction.REDIRECT,
                redirect_url="/mock-redirect",
                response=response
            )
        elif self.mock_action == PreprocessingAction.MODIFY:
            self.metrics["requests_modified"] += 1
            # Create a slightly modified request
            headers = dict(request.headers)
            headers["x-mock-processed"] = "true"
            
            scope = dict(request.scope)
            scope["headers"] = [
                (k.lower().encode(), v.encode()) for k, v in headers.items()
            ]
            
            modified_request = Request(scope, request.receive)
            return PreprocessingResult(
                action=PreprocessingAction.MODIFY,
                modified_request=modified_request
            )
        
        return PreprocessingResult(action=PreprocessingAction.CONTINUE)


class MockFailingPreprocessor(RequestPreprocessor):
    """Mock preprocessor that always fails for testing error handling."""
    
    def __init__(
        self,
        name: str = "FailingProcessor",
        priority: PreprocessingPriority = PreprocessingPriority.NORMAL,
        enabled: bool = True,
        exception_to_raise: Exception = Exception("Mock failure")
    ):
        super().__init__(name, priority, enabled)
        self.exception_to_raise = exception_to_raise
    
    async def process(self, request: Request) -> PreprocessingResult:
        """Mock process that always fails."""
        self.metrics["requests_processed"] += 1
        self.metrics["errors_encountered"] += 1
        raise self.exception_to_raise


def create_test_preprocessing_pipeline() -> MockPreprocessingPipeline:
    """Create a test preprocessing pipeline with mock processors."""
    pipeline = MockPreprocessingPipeline("TestPipeline")
    
    # Add mock processors
    pipeline.add_processor(MockHeaderManipulator())
    pipeline.add_processor(MockBodyTransformer())
    pipeline.add_processor(MockURLRewriter())
    pipeline.add_processor(MockQueryParamManipulator())
    
    return pipeline


def create_test_header_rules() -> List[HeaderRule]:
    """Create test header rules."""
    return [
        HeaderRule(
            action="add",
            header_name="X-Test-Header",
            header_value="test-value"
        ),
        HeaderRule(
            action="remove",
            header_name="X-Remove-Me"
        ),
        HeaderRule(
            action="modify",
            header_name="X-Modify-Me",
            pattern=re.compile(r"old"),
            replacement="new"
        ),
        HeaderRule(
            action="replace",
            header_name="X-Replace-Me",
            header_value="replaced-value"
        )
    ]


def create_test_body_transformations() -> List[BodyTransformation]:
    """Create test body transformations."""
    
    def uppercase_json(data: Dict) -> Dict:
        """Transform JSON to uppercase values."""
        if isinstance(data, dict):
            return {k: v.upper() if isinstance(v, str) else v for k, v in data.items()}
        return data
    
    def add_timestamp(data: Dict) -> Dict:
        """Add timestamp to JSON data."""
        data["timestamp"] = datetime.now().isoformat()
        return data
    
    return [
        BodyTransformation(
            source_format=BodyFormat.JSON,
            target_format=BodyFormat.JSON,
            transformation_function=uppercase_json
        ),
        BodyTransformation(
            source_format=BodyFormat.JSON,
            target_format=BodyFormat.JSON,
            transformation_function=add_timestamp
        )
    ]


def create_test_url_rewrite_rules() -> List[URLRewriteRule]:
    """Create test URL rewrite rules."""
    return [
        URLRewriteRule(
            pattern=re.compile(r"^/old-path(.*)$"),
            replacement=r"/new-path\1",
            redirect=False
        ),
        URLRewriteRule(
            pattern=re.compile(r"^/redirect-me(.*)$"),
            replacement=r"/redirected\1",
            redirect=True,
            permanent=False
        ),
        URLRewriteRule(
            pattern=re.compile(r"^/permanent-redirect(.*)$"),
            replacement=r"/moved\1",
            redirect=True,
            permanent=True
        )
    ]


def create_test_query_param_rules() -> List[QueryParamRule]:
    """Create test query parameter rules."""
    return [
        QueryParamRule(
            action="add",
            param_name="default_param",
            param_value="default_value"
        ),
        QueryParamRule(
            action="remove",
            param_name="remove_me"
        ),
        QueryParamRule(
            action="modify",
            param_name="modify_me",
            pattern=re.compile(r"old"),
            replacement="new"
        ),
        QueryParamRule(
            action="replace",
            param_name="replace_me",
            param_value="replaced_value"
        )
    ]


class PerformanceTestHelper:
    """Helper class for performance testing."""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.memory_usage = {}
    
    def start_timing(self):
        """Start timing."""
        self.start_time = datetime.now()
    
    def stop_timing(self):
        """Stop timing."""
        self.end_time = datetime.now()
    
    def get_duration_ms(self) -> float:
        """Get duration in milliseconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return 0.0
    
    def measure_memory(self, label: str):
        """Measure memory usage."""
        import psutil
        import os
        process = psutil.Process(os.getpid())
        self.memory_usage[label] = process.memory_info().rss
    
    def get_memory_diff(self, start_label: str, end_label: str) -> int:
        """Get memory difference between two measurements."""
        return self.memory_usage.get(end_label, 0) - self.memory_usage.get(start_label, 0)


def create_large_request_body(size_kb: int = 100) -> bytes:
    """Create large request body for testing."""
    content = "x" * (size_kb * 1024)
    return content.encode()


def create_complex_json_body(depth: int = 5, items_per_level: int = 10) -> Dict:
    """Create complex JSON body for testing."""
    def create_level(current_depth: int) -> Dict:
        if current_depth <= 0:
            return {"value": f"data_{current_depth}"}
        
        level_data = {}
        for i in range(items_per_level):
            key = f"item_{i}"
            if i % 3 == 0 and current_depth > 1:
                level_data[key] = create_level(current_depth - 1)
            else:
                level_data[key] = f"value_{current_depth}_{i}"
        
        return level_data
    
    return create_level(depth)