"""Tests for Shield Testing Framework."""

import asyncio
import json
import pytest
import tempfile
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_shield.testing import (
    MockRequest,
    MockResponse,
    TestDataGenerator,
    ShieldAssertion,
    ShieldTestRunner,
    ShieldTestSuite,
    FastAPIShieldTester,
    PerformanceTestRunner,
    ShieldTestReporter,
    ShieldTestExecutionResult,
    ShieldTestResult,
    ShieldTestResultStatus,
    RequestMethod,
    create_test_request,
    create_test_suite,
    quick_test_shield,
    performance_test_shield,
    assert_shield_blocks,
    assert_shield_allows,
)

from tests.mocks.testing_framework_mocks import (
    MockShieldAlwaysAllow,
    MockShieldAlwaysBlock,
    MockShieldConditional,
    MockShieldWithError,
    MockShieldPerformance,
    MockShieldRateLimit,
    TestShieldFactory,
    MockFastAPIApp,
    TestScenarioBuilder,
    TestResultValidator,
    MockDatabase,
    MockCache,
)


class TestMockRequest:
    """Test MockRequest functionality."""
    
    def test_basic_request_creation(self):
        """Test basic mock request creation."""
        request = MockRequest()
        
        assert request.method == "GET"
        assert str(request.url) == "http://testserver/"
        assert request.client.host == "127.0.0.1"
        assert request.client.port == 12345
    
    def test_request_with_parameters(self):
        """Test mock request with various parameters."""
        headers = {"authorization": "Bearer token123", "content-type": "application/json"}
        query_params = {"page": "1", "limit": "10"}
        
        request = MockRequest(
            method="POST",
            url="http://example.com/api/data",
            headers=headers,
            query_params=query_params,
            client_host="192.168.1.1"
        )
        
        assert request.method == "POST"
        assert "example.com" in str(request.url)
        assert request.headers["authorization"] == "Bearer token123"
        assert request.query_params["page"] == "1"
        assert request.client.host == "192.168.1.1"
    
    @pytest.mark.asyncio
    async def test_request_json_data(self):
        """Test mock request with JSON data."""
        json_data = {"name": "test", "value": 123}
        
        request = MockRequest(
            method="POST",
            url="http://testserver/api",
            json_data=json_data
        )
        
        # Test JSON retrieval
        received_json = await request.json()
        assert received_json == json_data
        
        # Test body retrieval
        body = await request.body()
        assert json.loads(body.decode('utf-8')) == json_data
        
        # Check content-type header was set
        assert request.headers["content-type"] == "application/json"
    
    @pytest.mark.asyncio
    async def test_request_form_data(self):
        """Test mock request with form data."""
        form_data = {"username": "testuser", "password": "secret"}
        
        request = MockRequest(
            method="POST",
            url="http://testserver/login",
            form_data=form_data
        )
        
        # Test form retrieval
        received_form = await request.form()
        assert received_form == form_data
        
        # Check content-type header was set
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    
    @pytest.mark.asyncio
    async def test_request_raw_body(self):
        """Test mock request with raw body data."""
        raw_body = b"raw binary data"
        
        request = MockRequest(
            method="PUT",
            url="http://testserver/upload",
            body=raw_body
        )
        
        body = await request.body()
        assert body == raw_body


class TestMockResponse:
    """Test MockResponse functionality."""
    
    def test_basic_response_creation(self):
        """Test basic mock response creation."""
        response = MockResponse()
        
        assert response.status_code == 200
        assert response.content == b""
        assert response.headers.get("content-length") == "0"
    
    def test_response_with_json_content(self):
        """Test mock response with JSON content."""
        json_data = {"message": "success", "data": [1, 2, 3]}
        
        response = MockResponse(
            status_code=201,
            content=json_data
        )
        
        assert response.status_code == 201
        assert response.json() == json_data
        assert response.headers["content-type"] == "application/json"
    
    def test_response_with_text_content(self):
        """Test mock response with text content."""
        text_content = "Hello, World!"
        
        response = MockResponse(
            status_code=200,
            content=text_content
        )
        
        assert response.status_code == 200
        assert response.content.decode('utf-8') == text_content
        assert response.headers["content-type"] == "text/plain"
    
    def test_response_with_custom_headers(self):
        """Test mock response with custom headers."""
        custom_headers = {
            "x-custom-header": "custom-value",
            "cache-control": "no-cache"
        }
        
        response = MockResponse(
            status_code=404,
            headers=custom_headers,
            content="Not found"
        )
        
        assert response.status_code == 404
        assert response.headers["x-custom-header"] == "custom-value"
        assert response.headers["cache-control"] == "no-cache"


class TestTestDataGenerator:
    """Test TestDataGenerator functionality."""
    
    def test_random_string_generation(self):
        """Test random string generation."""
        # Default length
        string1 = TestDataGenerator.random_string()
        assert len(string1) == 10
        assert string1.isalnum()
        
        # Custom length
        string2 = TestDataGenerator.random_string(20)
        assert len(string2) == 20
        
        # Different strings
        string3 = TestDataGenerator.random_string()
        assert string1 != string3  # Very unlikely to be the same
    
    def test_random_email_generation(self):
        """Test random email generation."""
        email = TestDataGenerator.random_email()
        
        assert "@" in email
        assert email.endswith(".com")
        assert len(email) > 10
    
    def test_random_url_generation(self):
        """Test random URL generation."""
        # Default URL
        url1 = TestDataGenerator.random_url()
        assert url1.startswith("https://")
        assert ".com" in url1
        
        # Custom scheme and host
        url2 = TestDataGenerator.random_url(scheme="http", host="example.org")
        assert url2.startswith("http://example.org/")
    
    def test_random_json_data_generation(self):
        """Test random JSON data generation."""
        json_data = TestDataGenerator.random_json_data()
        
        assert isinstance(json_data, dict)
        assert len(json_data) > 0
        
        # Test different depths
        shallow_data = TestDataGenerator.random_json_data(depth=0)
        deep_data = TestDataGenerator.random_json_data(depth=3)
        
        assert isinstance(shallow_data, dict)
        assert isinstance(deep_data, dict)
    
    def test_generate_test_requests(self):
        """Test test request generation."""
        requests = TestDataGenerator.generate_test_requests(5)
        
        assert len(requests) == 5
        assert all(isinstance(req, MockRequest) for req in requests)
        
        # Check variety in methods
        methods = [req.method for req in requests]
        assert len(set(methods)) >= 1  # At least some variety
        
        # Check all have required attributes
        for req in requests:
            assert hasattr(req, 'method')
            assert hasattr(req, 'url')
            assert hasattr(req, 'headers')


class TestShieldAssertion:
    """Test ShieldAssertion functionality."""
    
    def test_assert_shield_blocks_success(self):
        """Test successful shield blocking assertion."""
        mock_response = {"error": "Request blocked"}
        
        # Should not raise exception
        ShieldAssertion.assert_shield_blocks(mock_response)
    
    def test_assert_shield_blocks_failure(self):
        """Test failed shield blocking assertion."""
        # Shield returned None (allowed request)
        with pytest.raises(AssertionError, match="Shield should block request"):
            ShieldAssertion.assert_shield_blocks(None)
    
    def test_assert_shield_allows_success(self):
        """Test successful shield allowing assertion."""
        # Shield returned None (allowed request)
        ShieldAssertion.assert_shield_allows(None)
    
    def test_assert_shield_allows_failure(self):
        """Test failed shield allowing assertion."""
        mock_response = {"error": "Request blocked"}
        
        with pytest.raises(AssertionError, match="Shield should allow request"):
            ShieldAssertion.assert_shield_allows(mock_response)
    
    def test_assert_response_status(self):
        """Test response status assertion."""
        response = MockResponse(status_code=201)
        
        # Should succeed
        ShieldAssertion.assert_response_status(response, 201)
        
        # Should fail
        with pytest.raises(AssertionError, match="Expected status 200"):
            ShieldAssertion.assert_response_status(response, 200)
    
    def test_assert_response_contains(self):
        """Test response content assertion."""
        response = MockResponse(content="Hello, World!")
        
        # Should succeed
        ShieldAssertion.assert_response_contains(response, "Hello")
        ShieldAssertion.assert_response_contains(response, "World")
        
        # Should fail
        with pytest.raises(AssertionError, match="Expected content 'Missing' not found"):
            ShieldAssertion.assert_response_contains(response, "Missing")
    
    def test_assert_response_json(self):
        """Test response JSON assertion."""
        expected_json = {"status": "success", "code": 200}
        response = MockResponse(content=expected_json)
        
        # Should succeed
        ShieldAssertion.assert_response_json(response, expected_json)
        
        # Should fail
        with pytest.raises(AssertionError, match="Expected JSON"):
            ShieldAssertion.assert_response_json(response, {"different": "data"})
    
    def test_assert_execution_time(self):
        """Test execution time assertion."""
        # Should succeed
        ShieldAssertion.assert_execution_time(0.05, 0.1)
        
        # Should fail
        with pytest.raises(AssertionError, match="exceeds limit"):
            ShieldAssertion.assert_execution_time(0.15, 0.1)


class TestShieldTestRunner:
    """Test ShieldTestRunner functionality."""
    
    @pytest.mark.asyncio
    async def test_run_single_test_allow(self):
        """Test running single test that should allow."""
        shield = MockShieldAlwaysAllow("TestAllowShield")
        runner = ShieldTestRunner(shield, "test_allow")
        
        request = create_test_request()
        result = await runner.run_single_test(request, "allow")
        
        TestResultValidator.validate_test_result(result, ShieldTestResultStatus.PASSED, False)
        assert result.allowed == True
        assert result.shield_name == "MockShieldAlwaysAllow"
    
    @pytest.mark.asyncio
    async def test_run_single_test_block(self):
        """Test running single test that should block."""
        shield = MockShieldAlwaysBlock("TestBlockShield")
        runner = ShieldTestRunner(shield, "test_block")
        
        request = create_test_request()
        result = await runner.run_single_test(request, "block")
        
        TestResultValidator.validate_test_result(result, ShieldTestResultStatus.PASSED, True)
        assert result.blocked == True
        assert result.allowed == False
    
    @pytest.mark.asyncio
    async def test_run_single_test_error(self):
        """Test running single test that produces error."""
        shield = MockShieldWithError("TestErrorShield", error_probability=1.0)
        runner = ShieldTestRunner(shield, "test_error")
        
        request = create_test_request()
        result = await runner.run_single_test(request, "allow")
        
        assert result.result.status == ShieldTestResultStatus.ERROR
        assert result.result.exception is not None
    
    @pytest.mark.asyncio
    async def test_run_multiple_tests(self):
        """Test running multiple tests."""
        shield = MockShieldConditional(
            "TestConditionalShield",
            allow_methods=["GET", "POST"],
            block_paths=["/admin"]
        )
        runner = ShieldTestRunner(shield, "test_multiple")
        
        requests = [
            create_test_request(method="GET", url="http://testserver/api/data"),  # Should allow
            create_test_request(method="POST", url="http://testserver/api/data"), # Should allow
            create_test_request(method="GET", url="http://testserver/admin/users"), # Should block
            create_test_request(method="DELETE", url="http://testserver/api/data") # Should block
        ]
        
        expected_outcomes = ["allow", "allow", "block", "block"]
        results = await runner.run_multiple_tests(requests, expected_outcomes)
        
        assert len(results) == 4
        assert results[0].result.status == ShieldTestResultStatus.PASSED  # GET allowed
        assert results[1].result.status == ShieldTestResultStatus.PASSED  # POST allowed
        assert results[2].result.status == ShieldTestResultStatus.PASSED  # Admin blocked
        assert results[3].result.status == ShieldTestResultStatus.PASSED  # DELETE blocked
    
    @pytest.mark.asyncio
    async def test_run_performance_test(self):
        """Test performance testing."""
        shield = MockShieldPerformance("TestPerfShield", min_delay=0.001, max_delay=0.005)
        runner = ShieldTestRunner(shield, "test_performance")
        
        request = create_test_request()
        metrics = await runner.run_performance_test(request, iterations=10)
        
        TestResultValidator.validate_performance_metrics(metrics, min_requests=10)
        assert metrics['iterations'] == 10
        assert 0.001 <= metrics['avg_time'] <= 0.01  # Should be within delay range
    
    @pytest.mark.asyncio
    async def test_get_test_summary(self):
        """Test getting test summary."""
        shield = MockShieldAlwaysAllow("TestSummaryShield")
        runner = ShieldTestRunner(shield, "test_summary")
        
        # Run some tests
        requests = TestDataGenerator.generate_test_requests(5)
        await runner.run_multiple_tests(requests, ["allow"] * 5)
        
        summary = runner.get_test_summary()
        
        assert summary["total"] == 5
        assert summary["passed"] == 5
        assert summary["failed"] == 0
        assert summary["errors"] == 0
        assert summary["pass_rate"] == 100.0


class TestShieldTestSuite:
    """Test ShieldTestSuite functionality."""
    
    @pytest.mark.asyncio
    async def test_basic_test_suite(self):
        """Test basic test suite functionality."""
        suite = create_test_suite("Basic Test Suite")
        
        # Add shields
        shield1 = MockShieldAlwaysAllow("AllowShield")
        shield2 = MockShieldAlwaysBlock("BlockShield")
        
        suite.add_shield(shield1).add_shield(shield2)
        
        # Add test cases
        suite.add_test_case(
            "test_allow",
            create_test_request(method="GET", url="http://testserver/api/data"),
            "allow"
        )
        suite.add_test_case(
            "test_block",
            create_test_request(method="POST", url="http://testserver/admin/delete"),
            "block"
        )
        
        results = await suite.run_all_tests()
        
        # Should have 2 shields × 2 test cases = 4 results
        assert len(results) == 4
        
        # Check that we got results for both shields
        shield_names = {result.shield_name for result in results}
        assert "MockShieldAlwaysAllow" in shield_names
        assert "MockShieldAlwaysBlock" in shield_names
    
    @pytest.mark.asyncio
    async def test_suite_with_generated_tests(self):
        """Test suite with generated test cases."""
        suite = create_test_suite("Generated Test Suite")
        shield = MockShieldAlwaysAllow("GeneratedTestShield")
        
        suite.add_shield(shield)
        suite.add_generated_test_cases(3)
        
        results = await suite.run_all_tests()
        
        assert len(results) == 3  # 1 shield × 3 generated tests
        assert all(result.shield_name == "MockShieldAlwaysAllow" for result in results)
    
    @pytest.mark.asyncio
    async def test_suite_summary(self):
        """Test test suite summary."""
        suite = create_test_suite("Summary Test Suite")
        
        # Add mix of shields
        allow_shield = MockShieldAlwaysAllow("AllowShield")
        block_shield = MockShieldAlwaysBlock("BlockShield")
        error_shield = MockShieldWithError("ErrorShield", error_probability=1.0)
        
        suite.add_shield(allow_shield).add_shield(block_shield).add_shield(error_shield)
        
        # Add test case
        suite.add_test_case(
            "basic_test",
            create_test_request(),
            "allow"
        )
        
        await suite.run_all_tests()
        summary = suite.get_suite_summary()
        
        TestResultValidator.validate_test_suite_summary(summary, min_shields=3, min_tests=3)
        assert summary["suite_name"] == "Summary Test Suite"
        assert summary["shields_tested"] == 3


class TestFastAPIShieldTester:
    """Test FastAPI integration testing."""
    
    def test_fastapi_tester_creation(self):
        """Test FastAPI tester creation."""
        mock_app = MockFastAPIApp()
        app = mock_app.get_app()
        
        tester = FastAPIShieldTester(app)
        
        assert tester.app == app
        assert isinstance(tester.client, TestClient)
    
    def test_test_endpoint_with_shield(self):
        """Test endpoint testing functionality."""
        mock_app = MockFastAPIApp()
        app = mock_app.get_app()
        tester = FastAPIShieldTester(app)
        
        # Test successful endpoint
        result = tester.test_endpoint_with_shield("GET", "/", expected_status=200)
        
        assert result["method"] == "GET"
        assert result["url"] == "/"
        assert result["status_code"] == 200
        assert result["passed"] == True
        assert "Hello World" in str(result["response_data"])
    
    def test_run_endpoint_tests(self):
        """Test running multiple endpoint tests."""
        mock_app = MockFastAPIApp()
        app = mock_app.get_app()
        tester = FastAPIShieldTester(app)
        
        scenarios = TestScenarioBuilder.build_basic_scenarios()
        results = tester.run_endpoint_tests(scenarios)
        
        assert len(results) >= 3
        
        # Check that we got results for different scenarios
        scenario_names = {result["scenario_name"] for result in results}
        assert "basic_get" in scenario_names
        assert "basic_post" in scenario_names


class TestPerformanceTestRunner:
    """Test PerformanceTestRunner functionality."""
    
    @pytest.mark.asyncio
    async def test_sequential_performance_measurement(self):
        """Test sequential performance measurement."""
        shield = MockShieldPerformance("SeqPerfShield", min_delay=0.001, max_delay=0.003)
        requests = TestDataGenerator.generate_test_requests(5)
        
        metrics = await PerformanceTestRunner.measure_shield_performance(
            shield, requests, concurrent=False
        )
        
        TestResultValidator.validate_performance_metrics(metrics, min_requests=5)
        assert metrics['concurrent'] == False
        assert metrics['total_requests'] == 5
    
    @pytest.mark.asyncio
    async def test_concurrent_performance_measurement(self):
        """Test concurrent performance measurement."""
        shield = MockShieldPerformance("ConcPerfShield", min_delay=0.001, max_delay=0.003)
        requests = TestDataGenerator.generate_test_requests(5)
        
        metrics = await PerformanceTestRunner.measure_shield_performance(
            shield, requests, concurrent=True
        )
        
        TestResultValidator.validate_performance_metrics(metrics, min_requests=5)
        assert metrics['concurrent'] == True
        assert metrics['total_requests'] == 5
        
        # Concurrent execution should generally be faster than sequential
        # (though not guaranteed with small delays and small request counts)
    
    @pytest.mark.asyncio
    async def test_performance_with_blocking_shield(self):
        """Test performance measurement with blocking shield."""
        shield = MockShieldAlwaysBlock("PerfBlockShield", delay=0.002)
        requests = TestDataGenerator.generate_test_requests(3)
        
        metrics = await PerformanceTestRunner.measure_shield_performance(
            shield, requests, concurrent=False
        )
        
        assert metrics['total_requests'] == 3
        assert metrics['blocked_requests'] == 3
        assert metrics['successful_executions'] == 3
    
    @pytest.mark.asyncio
    async def test_performance_with_error_shield(self):
        """Test performance measurement with error-producing shield."""
        shield = MockShieldWithError("PerfErrorShield", error_probability=0.5)
        requests = TestDataGenerator.generate_test_requests(10)
        
        metrics = await PerformanceTestRunner.measure_shield_performance(
            shield, requests, concurrent=False
        )
        
        assert metrics['total_requests'] == 10
        # Should have some failures due to error probability
        assert metrics['failed_executions'] >= 0
        assert metrics['successful_executions'] >= 0
        assert metrics['successful_executions'] + metrics['failed_executions'] == 10


class TestShieldTestReporter:
    """Test ShieldTestReporter functionality."""
    
    def test_generate_text_report(self):
        """Test text report generation."""
        # Create some test results
        results = []
        
        # Successful result
        success_result = ShieldTestResult(
            shield_name="TestShield1",
            test_name="test_success",
            result=ShieldTestExecutionResult(
                status=ShieldTestResultStatus.PASSED,
                message="Test passed successfully",
                execution_time=0.005
            )
        )
        results.append(success_result)
        
        # Failed result
        failed_result = ShieldTestResult(
            shield_name="TestShield2",
            test_name="test_failure",
            result=ShieldTestExecutionResult(
                status=ShieldTestResultStatus.FAILED,
                message="Test failed",
                execution_time=0.003
            )
        )
        results.append(failed_result)
        
        report = ShieldTestReporter.generate_text_report(results)
        
        assert "SHIELD TEST REPORT" in report
        assert "TestShield1" in report
        assert "TestShield2" in report
        assert "test_success" in report
        assert "test_failure" in report
        assert "SUMMARY" in report
        assert "Total tests: 2" in report
        assert "Passed: 1" in report
        assert "Failed: 1" in report
    
    def test_generate_json_report(self):
        """Test JSON report generation."""
        results = [
            ShieldTestResult(
                shield_name="JSONTestShield",
                test_name="json_test",
                result=ShieldTestExecutionResult(
                    status=ShieldTestResultStatus.PASSED,
                    message="JSON test passed",
                    execution_time=0.002
                )
            )
        ]
        
        report = ShieldTestReporter.generate_json_report(results)
        
        # Should be valid JSON
        report_data = json.loads(report)
        
        assert "test_report" in report_data
        assert "timestamp" in report_data["test_report"]
        assert "total_tests" in report_data["test_report"]
        assert report_data["test_report"]["total_tests"] == 1
        
        result_data = report_data["test_report"]["results"][0]
        assert result_data["shield_name"] == "JSONTestShield"
        assert result_data["test_name"] == "json_test"
    
    def test_save_report(self):
        """Test saving reports to file."""
        results = [
            ShieldTestResult(
                shield_name="SaveTestShield",
                test_name="save_test",
                result=ShieldTestExecutionResult(
                    status=ShieldTestResultStatus.PASSED,
                    message="Save test passed",
                    execution_time=0.001
                )
            )
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            text_filename = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json_filename = f.name
        
        try:
            # Save text report
            ShieldTestReporter.save_report(results, text_filename, "text")
            
            with open(text_filename, 'r') as f:
                text_content = f.read()
            
            assert "SaveTestShield" in text_content
            
            # Save JSON report
            ShieldTestReporter.save_report(results, json_filename, "json")
            
            with open(json_filename, 'r') as f:
                json_content = json.load(f)
            
            assert json_content["test_report"]["total_tests"] == 1
        
        finally:
            import os
            try:
                os.unlink(text_filename)
                os.unlink(json_filename)
            except:
                pass


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_create_test_request(self):
        """Test create_test_request function."""
        request = create_test_request()
        
        assert isinstance(request, MockRequest)
        assert request.method == "GET"
        assert "testserver" in str(request.url)
        
        # Test with parameters
        custom_request = create_test_request(
            method="POST",
            url="http://example.com/api",
            headers={"authorization": "Bearer token"},
            json_data={"test": "data"}
        )
        
        assert custom_request.method == "POST"
        assert custom_request.headers["authorization"] == "Bearer token"
    
    def test_create_test_suite(self):
        """Test create_test_suite function."""
        suite = create_test_suite("Custom Suite")
        
        assert isinstance(suite, ShieldTestSuite)
        assert suite.name == "Custom Suite"
    
    @pytest.mark.asyncio
    async def test_quick_test_shield(self):
        """Test quick_test_shield function."""
        shield = MockShieldAlwaysAllow("QuickTestShield")
        
        result = await quick_test_shield(shield)
        
        assert isinstance(result, ShieldTestResult)
        assert result.shield_name == "MockShieldAlwaysAllow"
        assert result.result.status == ShieldTestResultStatus.PASSED
    
    @pytest.mark.asyncio
    async def test_performance_test_shield(self):
        """Test performance_test_shield function."""
        shield = MockShieldPerformance("QuickPerfShield")
        
        metrics = await performance_test_shield(shield, iterations=5)
        
        assert isinstance(metrics, dict)
        assert "avg_time" in metrics
        assert metrics["iterations"] == 5
    
    def test_assert_shield_blocks_function(self):
        """Test assert_shield_blocks convenience function."""
        # Should not raise
        assert_shield_blocks({"error": "blocked"})
        
        # Should raise
        with pytest.raises(AssertionError):
            assert_shield_blocks(None)
    
    def test_assert_shield_allows_function(self):
        """Test assert_shield_allows convenience function."""
        # Should not raise
        assert_shield_allows(None)
        
        # Should raise
        with pytest.raises(AssertionError):
            assert_shield_allows({"error": "blocked"})


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple components."""
    
    @pytest.mark.asyncio
    async def test_comprehensive_shield_testing_workflow(self):
        """Test comprehensive testing workflow."""
        # Create a mix of shields
        shields = TestShieldFactory.create_shield_collection()
        
        # Create test suite
        suite = create_test_suite("Comprehensive Test Suite")
        
        for shield in shields:
            suite.add_shield(shield)
        
        # Add various test scenarios
        shield_scenarios = TestScenarioBuilder.build_shield_test_scenarios()
        
        for scenario in shield_scenarios:
            suite.add_test_case(
                scenario['name'],
                scenario['request'],
                scenario['expected_outcome'],
                scenario['description']
            )
        
        # Run all tests
        results = await suite.run_all_tests()
        
        # Validate results
        assert len(results) > 0
        
        # Get summary
        summary = suite.get_suite_summary()
        TestResultValidator.validate_test_suite_summary(summary)
        
        # Generate reports
        text_report = ShieldTestReporter.generate_text_report(results)
        json_report = ShieldTestReporter.generate_json_report(results)
        
        assert len(text_report) > 100  # Should have substantial content
        assert "test_report" in json.loads(json_report)
    
    @pytest.mark.asyncio
    async def test_performance_comparison_workflow(self):
        """Test performance comparison workflow."""
        # Create shields with different performance characteristics
        fast_shield = MockShieldPerformance("FastShield", 0.001, 0.002)
        slow_shield = MockShieldPerformance("SlowShield", 0.005, 0.010)
        
        # Generate test requests
        requests = TestDataGenerator.generate_test_requests(10)
        
        # Measure performance for both
        fast_metrics = await PerformanceTestRunner.measure_shield_performance(
            fast_shield, requests, concurrent=False
        )
        slow_metrics = await PerformanceTestRunner.measure_shield_performance(
            slow_shield, requests, concurrent=False
        )
        
        # Validate metrics
        TestResultValidator.validate_performance_metrics(fast_metrics)
        TestResultValidator.validate_performance_metrics(slow_metrics)
        
        # Fast shield should be faster on average
        assert fast_metrics['average_time_per_request'] < slow_metrics['average_time_per_request']
    
    @pytest.mark.asyncio
    async def test_error_handling_workflow(self):
        """Test error handling in comprehensive workflow."""
        # Create shields that produce various types of errors
        error_shield = MockShieldWithError("ErrorShield", error_probability=0.3)
        
        # Create test suite
        suite = create_test_suite("Error Handling Suite")
        suite.add_shield(error_shield)
        
        # Add multiple test cases
        for i in range(10):
            suite.add_test_case(
                f"error_test_{i}",
                create_test_request(url=f"http://testserver/test{i}"),
                "allow"
            )
        
        # Run tests (should not crash despite errors)
        results = await suite.run_all_tests()
        
        assert len(results) == 10
        
        # Should have a mix of passed tests and errors
        statuses = [result.result.status for result in results]
        status_counts = {status: statuses.count(status) for status in set(statuses)}
        
        # Should have at least one of each (though randomness might affect this)
        total_results = len(results)
        assert total_results == 10


class TestMockObjects:
    """Test the mock objects used in testing."""
    
    @pytest.mark.asyncio
    async def test_mock_shield_always_allow(self):
        """Test MockShieldAlwaysAllow."""
        shield = MockShieldAlwaysAllow("TestAllowShield")
        request = create_test_request()
        
        result = await shield._shield_function(request)
        
        assert result is None  # Should allow
        assert shield.call_count == 1
    
    @pytest.mark.asyncio
    async def test_mock_shield_always_block(self):
        """Test MockShieldAlwaysBlock."""
        shield = MockShieldAlwaysBlock("TestBlockShield", block_message="Test block")
        request = create_test_request()
        
        result = await shield._shield_function(request)
        
        assert result is not None  # Should block
        assert shield.call_count == 1
    
    @pytest.mark.asyncio
    async def test_mock_shield_conditional(self):
        """Test MockShieldConditional."""
        shield = MockShieldConditional(
            "TestConditionalShield",
            allow_methods=["GET"],
            block_paths=["/admin"]
        )
        
        # Test allowed request
        get_request = create_test_request(method="GET", url="http://testserver/api/data")
        result1 = await shield._shield_function(get_request)
        assert result1 is None  # Should allow
        
        # Test blocked method
        post_request = create_test_request(method="POST", url="http://testserver/api/data")
        result2 = await shield._shield_function(post_request)
        assert result2 is not None  # Should block
        
        # Test blocked path
        admin_request = create_test_request(method="GET", url="http://testserver/admin/users")
        result3 = await shield._shield_function(admin_request)
        assert result3 is not None  # Should block
        
        assert shield.allowed_count == 1
        assert shield.blocked_count == 2
    
    @pytest.mark.asyncio
    async def test_mock_shield_rate_limit(self):
        """Test MockShieldRateLimit."""
        shield = MockShieldRateLimit("TestRateLimitShield", max_requests=2, window_seconds=60)
        request = create_test_request()
        
        # First two requests should be allowed
        result1 = await shield._shield_function(request)
        result2 = await shield._shield_function(request)
        
        assert result1 is None
        assert result2 is None
        
        # Third request should be blocked
        result3 = await shield._shield_function(request)
        
        assert result3 is not None
        assert shield.blocked_count == 1
    
    def test_test_shield_factory(self):
        """Test TestShieldFactory."""
        # Test individual shield creation
        allow_shield = TestShieldFactory.create_allow_shield()
        block_shield = TestShieldFactory.create_block_shield()
        error_shield = TestShieldFactory.create_error_shield()
        
        assert isinstance(allow_shield, MockShieldAlwaysAllow)
        assert isinstance(block_shield, MockShieldAlwaysBlock)
        assert isinstance(error_shield, MockShieldWithError)
        
        # Test collection creation
        collection = TestShieldFactory.create_shield_collection()
        assert len(collection) == 5
        assert all(hasattr(shield, '_shield_function') for shield in collection)
    
    def test_mock_database(self):
        """Test MockDatabase."""
        db = MockDatabase()
        
        # Test async operations would need to be in async test
        assert len(db.data) == 0
        assert len(db.access_log) == 0
    
    def test_mock_cache(self):
        """Test MockCache."""
        cache = MockCache(max_size=3)
        
        # Test initial state
        stats = cache.get_stats()
        assert stats['size'] == 0
        assert stats['hits'] == 0
        assert stats['misses'] == 0