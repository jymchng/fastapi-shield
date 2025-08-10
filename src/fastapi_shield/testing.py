"""Shield Testing Framework for FastAPI Shield.

This module provides comprehensive testing utilities for shield development,
testing, and validation including mock objects, assertion helpers, test data
generators, and integration with pytest and FastAPI TestClient.
"""

import asyncio
import json
import random
import string
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple, Type
from unittest.mock import Mock, AsyncMock
from urllib.parse import urlencode, parse_qs

import pytest
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.testclient import TestClient
from starlette.datastructures import Headers, QueryParams, URL
from starlette.requests import Request as StarletteRequest

from fastapi_shield.shield import Shield


class RequestMethod(str, Enum):
    """HTTP request methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ShieldTestResultStatus(str, Enum):
    """Shield test result status enumeration."""
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class ShieldTestExecutionResult:
    """Shield test execution result."""
    status: ShieldTestResultStatus
    message: str = ""
    execution_time: float = 0.0
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None
    exception: Optional[Exception] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'status': self.status.value,
            'message': self.message,
            'execution_time': self.execution_time,
            'request_data': self.request_data,
            'response_data': self.response_data,
            'exception': str(self.exception) if self.exception else None,
            'metadata': self.metadata
        }


@dataclass
class ShieldTestResult:
    """Shield-specific test result."""
    shield_name: str
    test_name: str
    result: ShieldTestExecutionResult
    shield_output: Any = None
    blocked: bool = False
    allowed: bool = True
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        # Convert shield_output to JSON serializable format
        shield_output_serializable = self.shield_output
        if hasattr(self.shield_output, '__dict__'):
            # Handle complex objects like FastAPI Response objects
            shield_output_serializable = str(self.shield_output)
        elif hasattr(self.shield_output, 'status_code'):
            # Handle Response-like objects
            shield_output_serializable = {
                'status_code': getattr(self.shield_output, 'status_code', None),
                'content': str(getattr(self.shield_output, 'body', '')),
                'type': type(self.shield_output).__name__
            }
        
        return {
            'shield_name': self.shield_name,
            'test_name': self.test_name,
            'result': self.result.to_dict(),
            'shield_output': shield_output_serializable,
            'blocked': self.blocked,
            'allowed': self.allowed,
            'performance_metrics': self.performance_metrics
        }


class MockRequest:
    """Mock request object for shield testing."""
    
    def __init__(
        self,
        method: str = "GET",
        url: str = "http://testserver/",
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        path_params: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        form_data: Optional[Dict[str, Any]] = None,
        body: Optional[bytes] = None,
        client_host: str = "127.0.0.1",
        client_port: int = 12345,
        user_agent: str = "TestClient/1.0"
    ):
        self.method = method.upper()
        self.url = URL(url)
        self.headers = Headers(headers or {})
        self.query_params = QueryParams(query_params or {})
        self.path_params = path_params or {}
        self.cookies = cookies or {}
        self.client = Mock()
        self.client.host = client_host
        self.client.port = client_port
        self.state = Mock()
        
        # Add default headers
        if user_agent and "user-agent" not in self.headers:
            self._headers_dict = dict(self.headers)
            self._headers_dict["user-agent"] = user_agent
            self.headers = Headers(self._headers_dict)
        
        # Handle body data
        if json_data:
            self._json_data = json_data
            self._body = json.dumps(json_data).encode('utf-8')
            if "content-type" not in self.headers:
                self._headers_dict = dict(self.headers)
                self._headers_dict["content-type"] = "application/json"
                self.headers = Headers(self._headers_dict)
        elif form_data:
            self._form_data = form_data
            self._body = urlencode(form_data).encode('utf-8')
            if "content-type" not in self.headers:
                self._headers_dict = dict(self.headers)
                self._headers_dict["content-type"] = "application/x-www-form-urlencoded"
                self.headers = Headers(self._headers_dict)
        elif body:
            self._body = body if isinstance(body, bytes) else body.encode('utf-8')
        else:
            self._body = b""
    
    async def json(self) -> Dict[str, Any]:
        """Get JSON data from request."""
        if hasattr(self, '_json_data'):
            return self._json_data
        
        if self._body:
            try:
                return json.loads(self._body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        
        return {}
    
    async def body(self) -> bytes:
        """Get raw body data."""
        return getattr(self, '_body', b"")
    
    async def form(self) -> Dict[str, Any]:
        """Get form data from request."""
        if hasattr(self, '_form_data'):
            return self._form_data
        
        if self._body and self.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            try:
                form_str = self._body.decode('utf-8')
                return dict(parse_qs(form_str, keep_blank_values=True))
            except UnicodeDecodeError:
                pass
        
        return {}


class MockResponse:
    """Mock response object for shield testing."""
    
    def __init__(
        self,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        media_type: str = "application/json"
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self.media_type = media_type
        
        if isinstance(content, dict):
            self.content = json.dumps(content).encode('utf-8')
            self.headers.setdefault("content-type", "application/json")
        elif isinstance(content, str):
            self.content = content.encode('utf-8')
            self.headers.setdefault("content-type", "text/plain")
        elif isinstance(content, bytes):
            self.content = content
        else:
            self.content = b""
        
        self.headers.setdefault("content-length", str(len(self.content)))
    
    def json(self) -> Dict[str, Any]:
        """Get JSON content from response."""
        try:
            return json.loads(self.content.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}


class TestDataGenerator:
    """Generator for test data and scenarios."""
    
    @staticmethod
    def random_string(length: int = 10, charset: str = None) -> str:
        """Generate random string."""
        if charset is None:
            charset = string.ascii_letters + string.digits
        return ''.join(random.choices(charset, k=length))
    
    @staticmethod
    def random_email() -> str:
        """Generate random email address."""
        username = TestDataGenerator.random_string(8)
        domain = TestDataGenerator.random_string(6)
        return f"{username}@{domain}.com"
    
    @staticmethod
    def random_url(scheme: str = "https", host: str = None, path: str = None) -> str:
        """Generate random URL."""
        if host is None:
            host = f"{TestDataGenerator.random_string(8)}.com"
        if path is None:
            path = f"/{TestDataGenerator.random_string(6)}"
        return f"{scheme}://{host}{path}"
    
    @staticmethod
    def random_json_data(depth: int = 2, max_keys: int = 5) -> Dict[str, Any]:
        """Generate random JSON data."""
        data = {}
        num_keys = random.randint(1, max_keys)
        
        for _ in range(num_keys):
            key = TestDataGenerator.random_string(6)
            
            if depth > 0 and random.choice([True, False]):
                # Nested object
                data[key] = TestDataGenerator.random_json_data(depth - 1, max_keys)
            else:
                # Simple value
                value_type = random.choice(['string', 'int', 'float', 'bool', 'list'])
                
                if value_type == 'string':
                    data[key] = TestDataGenerator.random_string()
                elif value_type == 'int':
                    data[key] = random.randint(1, 1000)
                elif value_type == 'float':
                    data[key] = round(random.uniform(1.0, 100.0), 2)
                elif value_type == 'bool':
                    data[key] = random.choice([True, False])
                elif value_type == 'list':
                    data[key] = [TestDataGenerator.random_string(4) for _ in range(3)]
        
        return data
    
    @staticmethod
    def generate_test_requests(count: int = 10) -> List[MockRequest]:
        """Generate list of test requests."""
        requests = []
        
        for _ in range(count):
            method = random.choice(list(RequestMethod))
            url = TestDataGenerator.random_url()
            
            headers = {
                "user-agent": f"TestAgent/{random.randint(1, 10)}.0",
                "accept": "application/json",
                "x-request-id": str(uuid.uuid4())
            }
            
            query_params = {}
            if random.choice([True, False]):
                for _ in range(random.randint(1, 3)):
                    key = TestDataGenerator.random_string(6)
                    value = TestDataGenerator.random_string(8)
                    query_params[key] = value
            
            json_data = None
            if method in [RequestMethod.POST, RequestMethod.PUT, RequestMethod.PATCH]:
                if random.choice([True, False]):
                    json_data = TestDataGenerator.random_json_data()
            
            request = MockRequest(
                method=method.value,
                url=url,
                headers=headers,
                query_params=query_params,
                json_data=json_data
            )
            
            requests.append(request)
        
        return requests


class ShieldAssertion:
    """Assertion helpers for shield testing."""
    
    @staticmethod
    def assert_shield_blocks(result: Any, message: str = "Shield should block request"):
        """Assert that shield blocks the request."""
        if result is None:
            raise AssertionError(f"{message}: Shield returned None (allowed request)")
    
    @staticmethod
    def assert_shield_allows(result: Any, message: str = "Shield should allow request"):
        """Assert that shield allows the request."""
        if result is not None:
            raise AssertionError(f"{message}: Shield returned {result} (blocked request)")
    
    @staticmethod
    def assert_response_status(response: MockResponse, expected_status: int, message: str = None):
        """Assert response status code."""
        if message is None:
            message = f"Expected status {expected_status}, got {response.status_code}"
        assert response.status_code == expected_status, message
    
    @staticmethod
    def assert_response_contains(response: MockResponse, expected_content: str, message: str = None):
        """Assert response contains specific content."""
        content = response.content.decode('utf-8') if response.content else ""
        if message is None:
            message = f"Expected content '{expected_content}' not found in response"
        assert expected_content in content, message
    
    @staticmethod
    def assert_response_json(response: MockResponse, expected_json: Dict[str, Any], message: str = None):
        """Assert response JSON matches expected data."""
        actual_json = response.json()
        if message is None:
            message = f"Expected JSON {expected_json}, got {actual_json}"
        assert actual_json == expected_json, message
    
    @staticmethod
    def assert_execution_time(execution_time: float, max_time: float, message: str = None):
        """Assert execution time is within limits."""
        if message is None:
            message = f"Execution time {execution_time:.3f}s exceeds limit {max_time:.3f}s"
        assert execution_time <= max_time, message


class ShieldTestRunner:
    """Test runner for executing shield tests."""
    
    def __init__(self, shield: Shield, test_name: str = "shield_test"):
        self.shield = shield
        self.test_name = test_name
        self.results: List[ShieldTestResult] = []
    
    async def run_single_test(self, request: MockRequest, expected_outcome: str = "allow") -> ShieldTestResult:
        """Run a single shield test."""
        start_time = time.perf_counter()
        shield_output = None
        blocked = False
        allowed = True
        exception = None
        
        try:
            # Execute shield
            if hasattr(self.shield, '_shield_function'):
                shield_output = await self.shield._shield_function(request)
            else:
                # Try calling shield directly
                shield_output = await self.shield(request)
            
            blocked = shield_output is not None
            allowed = not blocked
            
            # Determine test result
            if expected_outcome == "allow" and allowed:
                status = ShieldTestResultStatus.PASSED
                message = "Shield correctly allowed request"
            elif expected_outcome == "block" and blocked:
                status = ShieldTestResultStatus.PASSED
                message = "Shield correctly blocked request"
            elif expected_outcome == "allow" and blocked:
                status = ShieldTestResultStatus.FAILED
                message = f"Shield unexpectedly blocked request: {shield_output}"
            elif expected_outcome == "block" and allowed:
                status = ShieldTestResultStatus.FAILED
                message = "Shield unexpectedly allowed request"
            else:
                status = ShieldTestResultStatus.PASSED
                message = f"Shield execution completed with output: {shield_output}"
        
        except Exception as e:
            exception = e
            status = ShieldTestResultStatus.ERROR
            message = f"Shield execution failed: {str(e)}"
        
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        
        result = ShieldTestExecutionResult(
            status=status,
            message=message,
            execution_time=execution_time,
            request_data={
                'method': request.method,
                'url': str(request.url),
                'headers': dict(request.headers),
                'query_params': dict(request.query_params)
            },
            exception=exception
        )
        
        shield_result = ShieldTestResult(
            shield_name=type(self.shield).__name__,
            test_name=self.test_name,
            result=result,
            shield_output=shield_output,
            blocked=blocked,
            allowed=allowed,
            performance_metrics={'execution_time': execution_time}
        )
        
        self.results.append(shield_result)
        return shield_result
    
    async def run_multiple_tests(
        self, 
        requests: List[MockRequest], 
        expected_outcomes: List[str] = None
    ) -> List[ShieldTestResult]:
        """Run multiple shield tests."""
        if expected_outcomes is None:
            expected_outcomes = ["allow"] * len(requests)
        
        results = []
        
        for i, request in enumerate(requests):
            expected = expected_outcomes[i] if i < len(expected_outcomes) else "allow"
            result = await self.run_single_test(request, expected)
            results.append(result)
        
        return results
    
    async def run_performance_test(
        self, 
        request: MockRequest, 
        iterations: int = 100
    ) -> Dict[str, float]:
        """Run performance test on shield."""
        execution_times = []
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            
            try:
                if hasattr(self.shield, '_shield_function'):
                    await self.shield._shield_function(request)
                else:
                    await self.shield(request)
            except Exception:
                pass  # Continue with performance measurement
            
            end_time = time.perf_counter()
            execution_times.append(end_time - start_time)
        
        return {
            'min_time': min(execution_times),
            'max_time': max(execution_times),
            'avg_time': sum(execution_times) / len(execution_times),
            'total_time': sum(execution_times),
            'iterations': iterations
        }
    
    def get_test_summary(self) -> Dict[str, Any]:
        """Get summary of test results."""
        if not self.results:
            return {"total": 0, "passed": 0, "failed": 0, "errors": 0, "blocked": 0, "allowed": 0}
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r.result.status == ShieldTestResultStatus.PASSED)
        failed = sum(1 for r in self.results if r.result.status == ShieldTestResultStatus.FAILED)
        errors = sum(1 for r in self.results if r.result.status == ShieldTestResultStatus.ERROR)
        blocked = sum(1 for r in self.results if r.blocked)
        allowed = sum(1 for r in self.results if r.allowed)
        
        avg_execution_time = sum(r.result.execution_time for r in self.results) / total
        
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "blocked": blocked,
            "allowed": allowed,
            "pass_rate": (passed / total) * 100 if total > 0 else 0,
            "avg_execution_time": avg_execution_time
        }


class ShieldTestSuite:
    """Test suite for comprehensive shield testing."""
    
    def __init__(self, name: str = "Shield Test Suite"):
        self.name = name
        self.shields: List[Shield] = []
        self.test_cases: List[Dict[str, Any]] = []
        self.results: List[ShieldTestResult] = []
    
    def add_shield(self, shield: Shield) -> 'ShieldTestSuite':
        """Add shield to test suite."""
        self.shields.append(shield)
        return self
    
    def add_test_case(
        self, 
        name: str, 
        request: MockRequest, 
        expected_outcome: str = "allow",
        description: str = ""
    ) -> 'ShieldTestSuite':
        """Add test case to suite."""
        self.test_cases.append({
            'name': name,
            'request': request,
            'expected_outcome': expected_outcome,
            'description': description
        })
        return self
    
    def add_generated_test_cases(self, count: int = 10) -> 'ShieldTestSuite':
        """Add generated test cases to suite."""
        requests = TestDataGenerator.generate_test_requests(count)
        
        for i, request in enumerate(requests):
            self.add_test_case(
                name=f"generated_test_{i}",
                request=request,
                expected_outcome="allow",
                description=f"Generated test case {i}"
            )
        
        return self
    
    async def run_all_tests(self) -> List[ShieldTestResult]:
        """Run all tests in the suite."""
        all_results = []
        
        for shield in self.shields:
            runner = ShieldTestRunner(shield, f"{self.name}_tests")
            
            for test_case in self.test_cases:
                result = await runner.run_single_test(
                    test_case['request'],
                    test_case['expected_outcome']
                )
                result.test_name = test_case['name']
                all_results.append(result)
        
        self.results.extend(all_results)
        return all_results
    
    def get_suite_summary(self) -> Dict[str, Any]:
        """Get summary of all test results."""
        if not self.results:
            return {
                "suite_name": self.name,
                "shields_tested": len(self.shields),
                "test_cases": len(self.test_cases),
                "total_results": 0
            }
        
        shield_summaries = defaultdict(lambda: {"passed": 0, "failed": 0, "errors": 0})
        
        for result in self.results:
            shield_name = result.shield_name
            status = result.result.status
            
            if status == ShieldTestResultStatus.PASSED:
                shield_summaries[shield_name]["passed"] += 1
            elif status == ShieldTestResultStatus.FAILED:
                shield_summaries[shield_name]["failed"] += 1
            elif status == ShieldTestResultStatus.ERROR:
                shield_summaries[shield_name]["errors"] += 1
        
        total_passed = sum(s["passed"] for s in shield_summaries.values())
        total_failed = sum(s["failed"] for s in shield_summaries.values())
        total_errors = sum(s["errors"] for s in shield_summaries.values())
        total_tests = len(self.results)
        
        return {
            "suite_name": self.name,
            "shields_tested": len(self.shields),
            "test_cases": len(self.test_cases),
            "total_results": total_tests,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "total_errors": total_errors,
            "overall_pass_rate": (total_passed / total_tests) * 100 if total_tests > 0 else 0,
            "shield_summaries": dict(shield_summaries)
        }


class FastAPIShieldTester:
    """Integration tester for FastAPI applications with shields."""
    
    def __init__(self, app: FastAPI):
        self.app = app
        self.client = TestClient(app)
        self.test_results: List[Dict[str, Any]] = []
    
    @contextmanager
    def test_context(self):
        """Context manager for test execution."""
        start_time = time.perf_counter()
        
        try:
            yield self.client
        finally:
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            
            self.test_results.append({
                'execution_time': execution_time,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
    
    def test_endpoint_with_shield(
        self,
        method: str,
        url: str,
        expected_status: int = 200,
        **kwargs
    ) -> Dict[str, Any]:
        """Test endpoint with shield protection."""
        with self.test_context() as client:
            response = getattr(client, method.lower())(url, **kwargs)
            
            result = {
                'method': method,
                'url': url,
                'status_code': response.status_code,
                'expected_status': expected_status,
                'passed': response.status_code == expected_status,
                'response_data': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text,
                'headers': dict(response.headers)
            }
            
            return result
    
    def run_endpoint_tests(self, test_scenarios: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run multiple endpoint tests."""
        results = []
        
        for scenario in test_scenarios:
            method = scenario.get('method', 'GET')
            url = scenario.get('url', '/')
            expected_status = scenario.get('expected_status', 200)
            kwargs = scenario.get('kwargs', {})
            
            result = self.test_endpoint_with_shield(method, url, expected_status, **kwargs)
            result['scenario_name'] = scenario.get('name', f"{method} {url}")
            results.append(result)
        
        return results


class PerformanceTestRunner:
    """Performance testing utilities for shields."""
    
    @staticmethod
    async def measure_shield_performance(
        shield: Shield,
        requests: List[MockRequest],
        concurrent: bool = False
    ) -> Dict[str, Any]:
        """Measure shield performance metrics."""
        if concurrent:
            return await PerformanceTestRunner._measure_concurrent_performance(shield, requests)
        else:
            return await PerformanceTestRunner._measure_sequential_performance(shield, requests)
    
    @staticmethod
    async def _measure_sequential_performance(
        shield: Shield,
        requests: List[MockRequest]
    ) -> Dict[str, Any]:
        """Measure sequential performance."""
        execution_times = []
        successful_executions = 0
        failed_executions = 0
        blocked_requests = 0
        
        start_time = time.perf_counter()
        
        for request in requests:
            request_start = time.perf_counter()
            
            try:
                if hasattr(shield, '_shield_function'):
                    result = await shield._shield_function(request)
                else:
                    result = await shield(request)
                
                if result is not None:
                    blocked_requests += 1
                
                successful_executions += 1
                
            except Exception:
                failed_executions += 1
            
            request_end = time.perf_counter()
            execution_times.append(request_end - request_start)
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        return {
            'total_requests': len(requests),
            'successful_executions': successful_executions,
            'failed_executions': failed_executions,
            'blocked_requests': blocked_requests,
            'total_time': total_time,
            'average_time_per_request': sum(execution_times) / len(execution_times) if execution_times else 0,
            'min_time': min(execution_times) if execution_times else 0,
            'max_time': max(execution_times) if execution_times else 0,
            'requests_per_second': len(requests) / total_time if total_time > 0 else 0,
            'concurrent': False
        }
    
    @staticmethod
    async def _measure_concurrent_performance(
        shield: Shield,
        requests: List[MockRequest]
    ) -> Dict[str, Any]:
        """Measure concurrent performance."""
        async def execute_request(request):
            request_start = time.perf_counter()
            
            try:
                if hasattr(shield, '_shield_function'):
                    result = await shield._shield_function(request)
                else:
                    result = await shield(request)
                
                request_end = time.perf_counter()
                return {
                    'success': True,
                    'blocked': result is not None,
                    'execution_time': request_end - request_start
                }
                
            except Exception as e:
                request_end = time.perf_counter()
                return {
                    'success': False,
                    'blocked': False,
                    'execution_time': request_end - request_start,
                    'error': str(e)
                }
        
        start_time = time.perf_counter()
        
        # Execute all requests concurrently
        results = await asyncio.gather(*[execute_request(req) for req in requests])
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        successful_executions = sum(1 for r in results if r['success'])
        failed_executions = sum(1 for r in results if not r['success'])
        blocked_requests = sum(1 for r in results if r['blocked'])
        execution_times = [r['execution_time'] for r in results]
        
        return {
            'total_requests': len(requests),
            'successful_executions': successful_executions,
            'failed_executions': failed_executions,
            'blocked_requests': blocked_requests,
            'total_time': total_time,
            'average_time_per_request': sum(execution_times) / len(execution_times) if execution_times else 0,
            'min_time': min(execution_times) if execution_times else 0,
            'max_time': max(execution_times) if execution_times else 0,
            'requests_per_second': len(requests) / total_time if total_time > 0 else 0,
            'concurrent': True
        }


class ShieldTestReporter:
    """Test result reporter and formatter."""
    
    @staticmethod
    def generate_text_report(results: List[ShieldTestResult]) -> str:
        """Generate text-based test report."""
        if not results:
            return "No test results available.\n"
        
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("SHIELD TEST REPORT")
        report_lines.append("=" * 60)
        report_lines.append("")
        
        # Group results by shield
        shield_results = defaultdict(list)
        for result in results:
            shield_results[result.shield_name].append(result)
        
        for shield_name, shield_tests in shield_results.items():
            report_lines.append(f"Shield: {shield_name}")
            report_lines.append("-" * 40)
            
            for test in shield_tests:
                status_symbol = "✓" if test.result.status == ShieldTestResultStatus.PASSED else "✗"
                report_lines.append(f"{status_symbol} {test.test_name}: {test.result.message}")
                report_lines.append(f"   Execution time: {test.result.execution_time:.3f}s")
                
                if test.result.status != ShieldTestResultStatus.PASSED:
                    if test.result.exception:
                        report_lines.append(f"   Error: {test.result.exception}")
            
            report_lines.append("")
        
        # Summary
        total = len(results)
        passed = sum(1 for r in results if r.result.status == ShieldTestResultStatus.PASSED)
        failed = sum(1 for r in results if r.result.status == ShieldTestResultStatus.FAILED)
        errors = sum(1 for r in results if r.result.status == ShieldTestResultStatus.ERROR)
        
        report_lines.append("SUMMARY")
        report_lines.append("-" * 20)
        report_lines.append(f"Total tests: {total}")
        report_lines.append(f"Passed: {passed}")
        report_lines.append(f"Failed: {failed}")
        report_lines.append(f"Errors: {errors}")
        report_lines.append(f"Pass rate: {(passed/total)*100:.1f}%" if total > 0 else "Pass rate: 0.0%")
        
        return "\n".join(report_lines)
    
    @staticmethod
    def generate_json_report(results: List[ShieldTestResult]) -> str:
        """Generate JSON test report."""
        report_data = {
            'test_report': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'total_tests': len(results),
                'results': [result.to_dict() for result in results]
            }
        }
        
        return json.dumps(report_data, indent=2)
    
    @staticmethod
    def save_report(results: List[ShieldTestResult], filename: str, format: str = "text"):
        """Save test report to file."""
        if format == "json":
            content = ShieldTestReporter.generate_json_report(results)
        else:
            content = ShieldTestReporter.generate_text_report(results)
        
        with open(filename, 'w') as f:
            f.write(content)


# Pytest integration utilities

class ShieldTestCase:
    """Base class for shield test cases with pytest integration."""
    
    @pytest.fixture
    def mock_request(self) -> MockRequest:
        """Fixture for basic mock request."""
        return MockRequest()
    
    @pytest.fixture
    def mock_requests(self) -> List[MockRequest]:
        """Fixture for multiple mock requests."""
        return TestDataGenerator.generate_test_requests(5)
    
    @pytest.fixture
    def test_runner(self, shield) -> ShieldTestRunner:
        """Fixture for shield test runner."""
        return ShieldTestRunner(shield)
    
    @pytest.mark.asyncio
    async def test_shield_allows_valid_request(self, shield, mock_request):
        """Test that shield allows valid requests."""
        runner = ShieldTestRunner(shield)
        result = await runner.run_single_test(mock_request, "allow")
        assert result.result.status == ShieldTestResultStatus.PASSED
    
    @pytest.mark.asyncio
    async def test_shield_performance(self, shield, mock_request):
        """Test shield performance."""
        runner = ShieldTestRunner(shield)
        metrics = await runner.run_performance_test(mock_request, iterations=10)
        
        # Basic performance assertions
        assert metrics['avg_time'] < 1.0  # Should complete within 1 second on average
        assert metrics['min_time'] >= 0   # Minimum time should be non-negative


# Convenience functions for quick testing

def create_test_request(
    method: str = "GET",
    url: str = "http://testserver/",
    headers: Dict[str, str] = None,
    json_data: Dict[str, Any] = None
) -> MockRequest:
    """Create a mock request for testing."""
    return MockRequest(
        method=method,
        url=url,
        headers=headers,
        json_data=json_data
    )


def create_test_suite(name: str = "Test Suite") -> ShieldTestSuite:
    """Create a new shield test suite."""
    return ShieldTestSuite(name)


async def quick_test_shield(
    shield: Shield, 
    request: MockRequest = None, 
    expected_outcome: str = "allow"
) -> ShieldTestResult:
    """Quick test of a shield with a single request."""
    if request is None:
        request = create_test_request()
    
    runner = ShieldTestRunner(shield, "quick_test")
    return await runner.run_single_test(request, expected_outcome)


async def performance_test_shield(
    shield: Shield,
    request: MockRequest = None,
    iterations: int = 100
) -> Dict[str, float]:
    """Quick performance test of a shield."""
    if request is None:
        request = create_test_request()
    
    runner = ShieldTestRunner(shield, "performance_test")
    return await runner.run_performance_test(request, iterations)


def assert_shield_blocks(result: Any, message: str = None):
    """Quick assertion that shield blocks request."""
    ShieldAssertion.assert_shield_blocks(result, message or "Shield should block request")


def assert_shield_allows(result: Any, message: str = None):
    """Quick assertion that shield allows request."""
    ShieldAssertion.assert_shield_allows(result, message or "Shield should allow request")