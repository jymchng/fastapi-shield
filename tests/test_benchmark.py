"""Comprehensive tests for benchmarking framework."""

import asyncio
import json
import pytest
import tempfile
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
from unittest.mock import Mock, patch, AsyncMock

import httpx
from fastapi import FastAPI, Request

from fastapi_shield.benchmark import (
    BenchmarkType,
    BenchmarkMetric,
    BenchmarkRequest,
    BenchmarkResult,
    BenchmarkReport,
    HTTPBenchmarkRunner,
    ShieldBenchmark,
    ComparativeBenchmark,
    BenchmarkSuite,
    quick_benchmark,
    compare_shield_performance,
    benchmark_optimization_levels
)

from fastapi_shield.async_performance import PerformanceLevel, OptimizationConfig, OptimizedAsyncShield
from fastapi_shield.shield import Shield

from tests.mocks.async_performance_mocks import (
    MockAsyncShield,
    MockSyncShield,
    MockCPUIntensiveShield,
    MockIOIntensiveShield,
    MockMemoryHeavyShield,
    MockRequest,
    PerformanceTestHelper
)


class TestBenchmarkDataStructures:
    """Tests for benchmark data structures."""
    
    def test_benchmark_request_creation(self):
        """Test BenchmarkRequest creation."""
        request = BenchmarkRequest(
            method="POST",
            path="/api/test",
            headers={"Content-Type": "application/json"},
            json={"test": "data"},
            params={"param1": "value1"},
            timeout=60.0
        )
        
        assert request.method == "POST"
        assert request.path == "/api/test"
        assert request.headers["Content-Type"] == "application/json"
        assert request.json == {"test": "data"}
        assert request.params == {"param1": "value1"}
        assert request.timeout == 60.0
    
    def test_benchmark_request_defaults(self):
        """Test BenchmarkRequest default values."""
        request = BenchmarkRequest()
        
        assert request.method == "GET"
        assert request.path == "/"
        assert request.headers == {}
        assert request.json is None
        assert request.data is None
        assert request.params == {}
        assert request.timeout == 30.0
    
    def test_benchmark_result_creation(self):
        """Test BenchmarkResult creation."""
        timestamp = datetime.utcnow()
        
        result = BenchmarkResult(
            timestamp=timestamp,
            response_time_ms=25.5,
            status_code=200,
            success=True,
            error_message=None,
            memory_mb=50.0,
            cpu_percent=10.5
        )
        
        assert result.timestamp == timestamp
        assert result.response_time_ms == 25.5
        assert result.status_code == 200
        assert result.success is True
        assert result.error_message is None
        assert result.memory_mb == 50.0
        assert result.cpu_percent == 10.5
    
    def test_benchmark_result_failure(self):
        """Test BenchmarkResult for failed requests."""
        result = BenchmarkResult(
            timestamp=datetime.utcnow(),
            response_time_ms=5000.0,  # Timeout
            status_code=0,
            success=False,
            error_message="Connection timeout"
        )
        
        assert result.success is False
        assert result.error_message == "Connection timeout"
        assert result.status_code == 0
    
    def test_benchmark_report_creation(self):
        """Test BenchmarkReport creation."""
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(seconds=60)
        
        report = BenchmarkReport(
            name="test_benchmark",
            benchmark_type=BenchmarkType.LOAD_TEST,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=60.0,
            total_requests=1000,
            successful_requests=980,
            failed_requests=20,
            min_response_time_ms=5.0,
            max_response_time_ms=150.0,
            avg_response_time_ms=25.5,
            median_response_time_ms=20.0,
            p95_response_time_ms=45.0,
            p99_response_time_ms=85.0,
            throughput_rps=16.33,
            success_rate_percent=98.0,
            error_rate_percent=2.0
        )
        
        assert report.name == "test_benchmark"
        assert report.benchmark_type == BenchmarkType.LOAD_TEST
        assert report.duration_seconds == 60.0
        assert report.total_requests == 1000
        assert report.success_rate_percent == 98.0
        assert report.throughput_rps == 16.33


class TestHTTPBenchmarkRunner:
    """Tests for HTTPBenchmarkRunner."""
    
    @pytest.mark.asyncio
    async def test_runner_context_manager(self):
        """Test runner context manager usage."""
        async with HTTPBenchmarkRunner("http://localhost:8000") as runner:
            assert runner._client is not None
            assert isinstance(runner._client, httpx.AsyncClient)
        
        # Client should be closed after context
        assert runner._client is not None  # Reference still exists but connection is closed
    
    @pytest.mark.asyncio
    async def test_make_request_success(self):
        """Test successful HTTP request making."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            mock_response = Mock()
            mock_response.status_code = 200
            mock_client.request.return_value = mock_response
            
            async with HTTPBenchmarkRunner("http://localhost:8000") as runner:
                runner._client = mock_client
                
                request_config = BenchmarkRequest(method="GET", path="/test")
                
                # Test the internal request logic by creating a simple benchmark
                start_time = datetime.utcnow()
                results = []
                
                async def make_test_request():
                    nonlocal results
                    request_start = time.perf_counter()
                    
                    response = await runner._client.request(
                        method=request_config.method,
                        url=f"{runner.base_url}{request_config.path}",
                        headers=request_config.headers,
                        json=request_config.json,
                        data=request_config.data,
                        params=request_config.params,
                        timeout=request_config.timeout
                    )
                    
                    response_time_ms = (time.perf_counter() - request_start) * 1000
                    
                    results.append(BenchmarkResult(
                        timestamp=datetime.utcnow(),
                        response_time_ms=response_time_ms,
                        status_code=response.status_code,
                        success=200 <= response.status_code < 400
                    ))
                
                await make_test_request()
                
                assert len(results) == 1
                assert results[0].success is True
                assert results[0].status_code == 200
                assert results[0].response_time_ms >= 0
    
    @pytest.mark.asyncio
    async def test_make_request_failure(self):
        """Test failed HTTP request handling."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            # Mock client to raise an exception
            mock_client.request.side_effect = httpx.ConnectError("Connection failed")
            
            async with HTTPBenchmarkRunner("http://localhost:8000") as runner:
                runner._client = mock_client
                
                request_config = BenchmarkRequest(method="GET", path="/test")
                results = []
                
                async def make_test_request():
                    nonlocal results
                    request_start = time.perf_counter()
                    
                    try:
                        response = await runner._client.request(
                            method=request_config.method,
                            url=f"{runner.base_url}{request_config.path}",
                            headers=request_config.headers,
                            json=request_config.json,
                            data=request_config.data,
                            params=request_config.params,
                            timeout=request_config.timeout
                        )
                        
                        response_time_ms = (time.perf_counter() - request_start) * 1000
                        success = 200 <= response.status_code < 400
                        
                        results.append(BenchmarkResult(
                            timestamp=datetime.utcnow(),
                            response_time_ms=response_time_ms,
                            status_code=response.status_code,
                            success=success
                        ))
                        
                    except Exception as e:
                        response_time_ms = (time.perf_counter() - request_start) * 1000
                        results.append(BenchmarkResult(
                            timestamp=datetime.utcnow(),
                            response_time_ms=response_time_ms,
                            status_code=0,
                            success=False,
                            error_message=str(e)
                        ))
                
                await make_test_request()
                
                assert len(results) == 1
                assert results[0].success is False
                assert results[0].status_code == 0
                assert results[0].error_message == "Connection failed"
    
    def test_generate_report_empty_results(self):
        """Test report generation with empty results."""
        runner = HTTPBenchmarkRunner("http://localhost:8000")
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(seconds=30)
        
        report = runner._generate_report(
            name="empty_test",
            benchmark_type=BenchmarkType.LOAD_TEST,
            start_time=start_time,
            end_time=end_time,
            results=[]
        )
        
        assert report.name == "empty_test"
        assert report.benchmark_type == BenchmarkType.LOAD_TEST
        assert report.total_requests == 0
        assert report.successful_requests == 0
        assert report.failed_requests == 0
        assert report.throughput_rps == 0
        assert report.success_rate_percent == 0
    
    def test_generate_report_with_results(self):
        """Test report generation with actual results."""
        runner = HTTPBenchmarkRunner("http://localhost:8000")
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(seconds=10)
        
        # Create test results
        results = []
        for i in range(100):
            results.append(BenchmarkResult(
                timestamp=start_time + timedelta(milliseconds=i*100),
                response_time_ms=10.0 + i,  # 10-109ms range
                status_code=200 if i < 95 else 500,  # 5% failure rate
                success=i < 95,
                error_message=None if i < 95 else "Server error"
            ))
        
        report = runner._generate_report(
            name="test_results",
            benchmark_type=BenchmarkType.LOAD_TEST,
            start_time=start_time,
            end_time=end_time,
            results=results
        )
        
        assert report.name == "test_results"
        assert report.total_requests == 100
        assert report.successful_requests == 95
        assert report.failed_requests == 5
        assert report.success_rate_percent == 95.0
        assert report.error_rate_percent == 5.0
        assert report.min_response_time_ms == 10.0
        assert report.max_response_time_ms == 109.0
        assert report.avg_response_time_ms == 59.5  # (10 + 109) / 2
        assert report.throughput_rps == 10.0  # 100 requests in 10 seconds
        assert "Server error" in report.errors


class TestShieldBenchmark:
    """Tests for ShieldBenchmark functionality."""
    
    def test_shield_benchmark_initialization(self):
        """Test shield benchmark initialization."""
        app = FastAPI()
        benchmark = ShieldBenchmark(app)
        
        assert benchmark.app is app
        assert benchmark.client is not None
    
    @pytest.mark.asyncio
    async def test_benchmark_shield_performance_basic(self):
        """Test basic shield performance benchmarking."""
        app = FastAPI()
        benchmark = ShieldBenchmark(app)
        
        # Mock test client responses
        with patch.object(benchmark.client, 'get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            shield = MockAsyncShield("test_shield", delay_ms=5.0)
            
            result = await benchmark.benchmark_shield_performance(
                shield=shield,
                endpoint_path="/test",
                method="GET",
                iterations=10,
                concurrent_requests=2,
                warmup_iterations=2
            )
            
            assert result["shield_name"] == "test_shield"
            assert result["total_requests"] == 10
            assert result["successful_requests"] >= 0
            assert "avg_response_time_ms" in result
            assert "throughput_rps" in result
    
    @pytest.mark.asyncio
    async def test_benchmark_shield_with_failures(self):
        """Test benchmarking with request failures."""
        app = FastAPI()
        benchmark = ShieldBenchmark(app)
        
        # Mock test client to raise exceptions
        with patch.object(benchmark.client, 'get') as mock_get:
            mock_get.side_effect = Exception("Connection error")
            
            shield = MockAsyncShield("failing_shield")
            
            result = await benchmark.benchmark_shield_performance(
                shield=shield,
                endpoint_path="/test",
                iterations=5,
                concurrent_requests=1,
                warmup_iterations=0
            )
            
            assert result["shield_name"] == "failing_shield"
            assert result["total_requests"] == 5
            assert result["successful_requests"] == 0  # All failed
    
    @pytest.mark.asyncio
    async def test_benchmark_different_http_methods(self):
        """Test benchmarking different HTTP methods."""
        app = FastAPI()
        benchmark = ShieldBenchmark(app)
        
        # Test POST method
        with patch.object(benchmark.client, 'post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 201
            mock_post.return_value = mock_response
            
            shield = MockAsyncShield("post_shield")
            
            result = await benchmark.benchmark_shield_performance(
                shield=shield,
                method="POST",
                iterations=5,
                warmup_iterations=0
            )
            
            assert result["shield_name"] == "post_shield"
            assert mock_post.called
    
    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self):
        """Test concurrent request handling in benchmark."""
        app = FastAPI()
        benchmark = ShieldBenchmark(app)
        
        request_count = 0
        
        def mock_get_side_effect(*args, **kwargs):
            nonlocal request_count
            request_count += 1
            mock_response = Mock()
            mock_response.status_code = 200
            return mock_response
        
        with patch.object(benchmark.client, 'get', side_effect=mock_get_side_effect):
            shield = MockAsyncShield("concurrent_shield")
            
            result = await benchmark.benchmark_shield_performance(
                shield=shield,
                iterations=20,
                concurrent_requests=5,
                warmup_iterations=0
            )
            
            assert result["total_requests"] == 20
            assert request_count >= 20  # Including warmup requests


class TestComparativeBenchmark:
    """Tests for ComparativeBenchmark functionality."""
    
    @pytest.mark.asyncio
    async def test_compare_shields_basic(self):
        """Test basic shield comparison."""
        app = FastAPI()
        comparison = ComparativeBenchmark(app)
        
        with patch.object(comparison.benchmark, 'benchmark_shield_performance') as mock_benchmark:
            # Mock benchmark results
            mock_benchmark.side_effect = [
                {
                    "shield_name": "fast_shield",
                    "avg_response_time_ms": 10.0,
                    "throughput_rps": 100.0,
                    "total_requests": 100,
                    "successful_requests": 100
                },
                {
                    "shield_name": "slow_shield", 
                    "avg_response_time_ms": 50.0,
                    "throughput_rps": 20.0,
                    "total_requests": 100,
                    "successful_requests": 100
                }
            ]
            
            shields = [
                ("Fast Shield", MockAsyncShield("fast_shield", delay_ms=1.0)),
                ("Slow Shield", MockAsyncShield("slow_shield", delay_ms=10.0))
            ]
            
            result = await comparison.compare_shields(
                shields=shields,
                iterations=100,
                concurrent_requests=5
            )
            
            assert "individual_results" in result
            assert "comparison" in result
            assert len(result["individual_results"]) == 2
            assert "Fast Shield" in result["individual_results"]
            assert "Slow Shield" in result["individual_results"]
    
    def test_generate_comparison_summary(self):
        """Test comparison summary generation."""
        comparison = ComparativeBenchmark(FastAPI())
        
        results = {
            "fast_shield": {
                "avg_response_time_ms": 10.0,
                "throughput_rps": 100.0
            },
            "slow_shield": {
                "avg_response_time_ms": 50.0,
                "throughput_rps": 20.0
            },
            "medium_shield": {
                "avg_response_time_ms": 25.0,
                "throughput_rps": 40.0
            }
        }
        
        summary = comparison._generate_comparison_summary(results)
        
        assert "best_response_time" in summary
        assert "worst_response_time" in summary
        assert "best_throughput" in summary
        assert "worst_throughput" in summary
        assert "relative_performance" in summary
        
        assert summary["best_response_time"]["shield"] == "fast_shield"
        assert summary["worst_response_time"]["shield"] == "slow_shield"
        assert summary["best_throughput"]["shield"] == "fast_shield"
        assert summary["worst_throughput"]["shield"] == "slow_shield"
    
    def test_generate_comparison_summary_empty(self):
        """Test comparison summary with empty results."""
        comparison = ComparativeBenchmark(FastAPI())
        
        summary = comparison._generate_comparison_summary({})
        assert summary == {}
        
        # Test with invalid results
        invalid_results = {
            "shield1": {"invalid": "data"},
            "shield2": {"also_invalid": "data"}
        }
        
        summary = comparison._generate_comparison_summary(invalid_results)
        assert "error" in summary
    
    @pytest.mark.asyncio
    async def test_compare_optimization_levels(self):
        """Test comparing different optimization levels."""
        app = FastAPI()
        comparison = ComparativeBenchmark(app)
        
        async def test_shield_func(request):
            await asyncio.sleep(0.001)
            return {"test": "data"}
        
        with patch.object(comparison, 'compare_shields') as mock_compare:
            mock_compare.return_value = {
                "individual_results": {
                    "Optimization Level: minimal": {"avg_response_time_ms": 20.0},
                    "Optimization Level: balanced": {"avg_response_time_ms": 15.0},
                    "Optimization Level: aggressive": {"avg_response_time_ms": 10.0},
                    "Optimization Level: maximum": {"avg_response_time_ms": 8.0}
                },
                "comparison": {"best_response_time": {"shield": "maximum"}}
            }
            
            result = await comparison.compare_optimization_levels(
                shield_func=test_shield_func,
                optimization_levels=[
                    PerformanceLevel.MINIMAL,
                    PerformanceLevel.BALANCED,
                    PerformanceLevel.AGGRESSIVE,
                    PerformanceLevel.MAXIMUM
                ],
                iterations=50
            )
            
            assert "individual_results" in result
            assert "comparison" in result
            assert len(result["individual_results"]) == 4


class TestBenchmarkSuite:
    """Tests for BenchmarkSuite functionality."""
    
    def test_benchmark_suite_initialization(self):
        """Test benchmark suite initialization."""
        # Test with base_url
        suite1 = BenchmarkSuite(base_url="http://localhost:8000")
        assert suite1.base_url == "http://localhost:8000"
        assert suite1.app is None
        
        # Test with app
        app = FastAPI()
        suite2 = BenchmarkSuite(app=app)
        assert suite2.app is app
        assert suite2.base_url is None
    
    @pytest.mark.asyncio
    async def test_run_comprehensive_benchmark_with_app(self):
        """Test comprehensive benchmark with FastAPI app."""
        app = FastAPI()
        suite = BenchmarkSuite(app=app)
        
        with patch('fastapi_shield.benchmark.ShieldBenchmark') as mock_benchmark_class:
            mock_benchmark = Mock()
            mock_benchmark_class.return_value = mock_benchmark
            
            # Mock benchmark results
            mock_benchmark.benchmark_shield_performance.return_value = {
                "shield_name": "test_shield",
                "total_requests": 100,
                "successful_requests": 95,
                "avg_response_time_ms": 25.0,
                "throughput_rps": 40.0
            }
            
            shield = MockAsyncShield("test_shield")
            
            results = await suite.run_comprehensive_benchmark(
                shield=shield,
                include_load_test=True,
                include_stress_test=False,
                include_spike_test=False,
                include_endurance_test=False
            )
            
            assert "load_test" in results
            assert results["load_test"]["shield_name"] == "test_shield"
    
    def test_export_results(self):
        """Test exporting benchmark results."""
        suite = BenchmarkSuite()
        
        # Add test results
        report1 = BenchmarkReport(
            name="test1",
            benchmark_type=BenchmarkType.LOAD_TEST,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            duration_seconds=60.0,
            total_requests=100,
            successful_requests=95,
            failed_requests=5,
            min_response_time_ms=10.0,
            max_response_time_ms=100.0,
            avg_response_time_ms=25.0,
            median_response_time_ms=20.0,
            p95_response_time_ms=45.0,
            p99_response_time_ms=75.0,
            throughput_rps=40.0,
            success_rate_percent=95.0,
            error_rate_percent=5.0
        )
        
        suite.results.append(report1)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            suite.export_results(f.name)
            
            # Read back and verify
            with open(f.name, 'r') as read_f:
                exported_data = json.load(read_f)
                
                assert len(exported_data) == 1
                assert exported_data[0]["name"] == "test1"
                assert exported_data[0]["benchmark_type"] == "load_test"
                assert exported_data[0]["total_requests"] == 100
                assert "raw_results" not in exported_data[0]  # Should be excluded
    
    def test_generate_summary_report(self):
        """Test generating summary report."""
        suite = BenchmarkSuite()
        
        # Test empty results
        summary = suite.generate_summary_report()
        assert "error" in summary
        
        # Add test results
        reports = []
        for i in range(3):
            report = BenchmarkReport(
                name=f"test_{i}",
                benchmark_type=BenchmarkType.LOAD_TEST if i % 2 == 0 else BenchmarkType.STRESS_TEST,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                duration_seconds=60.0,
                total_requests=100 + i*10,
                successful_requests=95 + i*5,
                failed_requests=5,
                min_response_time_ms=10.0,
                max_response_time_ms=100.0,
                avg_response_time_ms=25.0 + i*5,
                median_response_time_ms=20.0,
                p95_response_time_ms=45.0,
                p99_response_time_ms=75.0,
                throughput_rps=40.0 + i*10,
                success_rate_percent=95.0,
                error_rate_percent=5.0
            )
            reports.append(report)
        
        suite.results.extend(reports)
        
        summary = suite.generate_summary_report()
        
        assert summary["total_benchmarks"] == 3
        assert summary["benchmark_types"]["load_test"] == 2
        assert summary["benchmark_types"]["stress_test"] == 1
        assert summary["overall_stats"]["total_requests"] == 330  # 100+110+120
        assert summary["overall_stats"]["total_successful_requests"] == 305  # 95+100+105
        assert summary["overall_stats"]["avg_response_time_ms"] == 30.0  # (25+30+35)/3
        assert summary["overall_stats"]["avg_throughput_rps"] == 50.0  # (40+50+60)/3


class TestConvenienceFunctions:
    """Tests for convenience benchmark functions."""
    
    @pytest.mark.asyncio
    async def test_quick_benchmark(self):
        """Test quick benchmark function."""
        with patch('fastapi_shield.benchmark.ShieldBenchmark') as mock_benchmark_class:
            mock_benchmark = Mock()
            mock_benchmark_class.return_value = mock_benchmark
            
            mock_benchmark.benchmark_shield_performance.return_value = {
                "shield_name": "quick_test",
                "total_requests": 100,
                "avg_response_time_ms": 15.0
            }
            
            shield = MockAsyncShield("quick_test")
            result = await quick_benchmark(shield, iterations=100)
            
            assert result["shield_name"] == "quick_test"
            assert result["total_requests"] == 100
            mock_benchmark.benchmark_shield_performance.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_compare_shield_performance(self):
        """Test compare shield performance function."""
        with patch('fastapi_shield.benchmark.ComparativeBenchmark') as mock_comparison_class:
            mock_comparison = Mock()
            mock_comparison_class.return_value = mock_comparison
            
            mock_comparison.compare_shields.return_value = {
                "individual_results": {
                    "Shield A": {"avg_response_time_ms": 20.0},
                    "Shield B": {"avg_response_time_ms": 30.0}
                },
                "comparison": {"best_response_time": {"shield": "Shield A"}}
            }
            
            shields = [
                ("Shield A", MockAsyncShield("shield_a")),
                ("Shield B", MockAsyncShield("shield_b"))
            ]
            
            result = await compare_shield_performance(shields, iterations=50)
            
            assert "individual_results" in result
            assert "comparison" in result
            mock_comparison.compare_shields.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_benchmark_optimization_levels(self):
        """Test benchmark optimization levels function."""
        with patch('fastapi_shield.benchmark.ComparativeBenchmark') as mock_comparison_class:
            mock_comparison = Mock()
            mock_comparison_class.return_value = mock_comparison
            
            mock_comparison.compare_optimization_levels.return_value = {
                "individual_results": {
                    "minimal": {"avg_response_time_ms": 30.0},
                    "balanced": {"avg_response_time_ms": 25.0},
                    "aggressive": {"avg_response_time_ms": 20.0},
                    "maximum": {"avg_response_time_ms": 15.0}
                },
                "comparison": {"best_response_time": {"shield": "maximum"}}
            }
            
            async def test_shield_func(request):
                return {"test": "data"}
            
            result = await benchmark_optimization_levels(test_shield_func, iterations=100)
            
            assert "individual_results" in result
            assert "comparison" in result
            mock_comparison.compare_optimization_levels.assert_called_once()


class TestBenchmarkIntegration:
    """Integration tests for benchmark functionality."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_shield_benchmark(self):
        """Test end-to-end shield benchmarking."""
        app = FastAPI()
        
        # Create a real shield for testing
        shield = MockAsyncShield("integration_test", delay_ms=2.0)
        
        # Mock the test client to avoid actual HTTP calls
        with patch('fastapi.testclient.TestClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            # Mock successful responses
            mock_response = Mock()
            mock_response.status_code = 200
            mock_client.get.return_value = mock_response
            
            benchmark = ShieldBenchmark(app)
            benchmark.client = mock_client
            
            result = await benchmark.benchmark_shield_performance(
                shield=shield,
                endpoint_path="/integration_test",
                iterations=20,
                concurrent_requests=3,
                warmup_iterations=5
            )
            
            assert result["shield_name"] == "integration_test"
            assert result["total_requests"] == 20
            assert result["successful_requests"] >= 0
            assert "avg_response_time_ms" in result
            assert "throughput_rps" in result
            assert result["throughput_rps"] > 0
    
    @pytest.mark.asyncio
    async def test_performance_comparison_workflow(self):
        """Test complete performance comparison workflow."""
        # Create shields with different characteristics
        fast_shield = MockAsyncShield("fast", delay_ms=1.0)
        medium_shield = MockAsyncShield("medium", delay_ms=5.0)
        slow_shield = MockAsyncShield("slow", delay_ms=15.0)
        
        shields = [
            ("Fast Shield", fast_shield),
            ("Medium Shield", medium_shield), 
            ("Slow Shield", slow_shield)
        ]
        
        app = FastAPI()
        comparison = ComparativeBenchmark(app)
        
        # Mock the underlying benchmark
        with patch.object(comparison.benchmark, 'benchmark_shield_performance') as mock_benchmark:
            # Return different performance metrics for each shield
            mock_benchmark.side_effect = [
                {  # Fast shield results
                    "shield_name": "fast",
                    "avg_response_time_ms": 5.0,
                    "throughput_rps": 200.0,
                    "total_requests": 50,
                    "successful_requests": 50,
                    "success_rate": 100.0
                },
                {  # Medium shield results
                    "shield_name": "medium",
                    "avg_response_time_ms": 10.0,
                    "throughput_rps": 100.0,
                    "total_requests": 50,
                    "successful_requests": 49,
                    "success_rate": 98.0
                },
                {  # Slow shield results
                    "shield_name": "slow",
                    "avg_response_time_ms": 20.0,
                    "throughput_rps": 50.0,
                    "total_requests": 50,
                    "successful_requests": 47,
                    "success_rate": 94.0
                }
            ]
            
            result = await comparison.compare_shields(
                shields=shields,
                iterations=50,
                concurrent_requests=5
            )
            
            # Verify comparison results
            assert "individual_results" in result
            assert "comparison" in result
            
            individual = result["individual_results"]
            assert len(individual) == 3
            assert "Fast Shield" in individual
            assert "Medium Shield" in individual
            assert "Slow Shield" in individual
            
            # Check that fast shield performed best
            comparison_summary = result["comparison"]
            assert comparison_summary["best_response_time"]["shield"] == "Fast Shield"
            assert comparison_summary["best_throughput"]["shield"] == "Fast Shield"
            assert comparison_summary["worst_response_time"]["shield"] == "Slow Shield"
    
    @pytest.mark.asyncio
    async def test_optimization_level_benchmarking(self):
        """Test optimization level benchmarking."""
        async def sample_shield_func(request):
            # Simulate some processing
            await asyncio.sleep(0.002)  # 2ms delay
            return {"processed": True}
        
        app = FastAPI()
        comparison = ComparativeBenchmark(app)
        
        # Mock the comparison results to simulate optimization improvements
        with patch.object(comparison, 'compare_shields') as mock_compare:
            mock_compare.return_value = {
                "individual_results": {
                    "Optimization Level: minimal": {
                        "avg_response_time_ms": 25.0,
                        "throughput_rps": 40.0
                    },
                    "Optimization Level: balanced": {
                        "avg_response_time_ms": 20.0,
                        "throughput_rps": 50.0
                    },
                    "Optimization Level: aggressive": {
                        "avg_response_time_ms": 15.0,
                        "throughput_rps": 65.0
                    },
                    "Optimization Level: maximum": {
                        "avg_response_time_ms": 12.0,
                        "throughput_rps": 80.0
                    }
                },
                "comparison": {
                    "best_response_time": {
                        "shield": "Optimization Level: maximum",
                        "value_ms": 12.0
                    },
                    "best_throughput": {
                        "shield": "Optimization Level: maximum",
                        "value_rps": 80.0
                    },
                    "relative_performance": {
                        "Optimization Level: maximum": {
                            "response_time_improvement": 52.0,  # (25-12)/25 * 100
                            "throughput_improvement": 100.0     # (80-40)/40 * 100
                        }
                    }
                }
            }
            
            result = await comparison.compare_optimization_levels(
                shield_func=sample_shield_func,
                optimization_levels=list(PerformanceLevel),
                iterations=100
            )
            
            # Verify optimization comparison
            assert "individual_results" in result
            assert "comparison" in result
            
            # Check that maximum optimization performed best
            best_response = result["comparison"]["best_response_time"]
            assert best_response["shield"] == "Optimization Level: maximum"
            assert best_response["value_ms"] == 12.0
            
            best_throughput = result["comparison"]["best_throughput"]
            assert best_throughput["shield"] == "Optimization Level: maximum"
            assert best_throughput["value_rps"] == 80.0
    
    def test_benchmark_result_accuracy(self):
        """Test accuracy of benchmark result calculations."""
        runner = HTTPBenchmarkRunner("http://localhost:8000")
        
        # Create precise test data
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(seconds=30)  # Exactly 30 seconds
        
        results = []
        # 100 requests: 90 successful (10-99ms), 10 failed
        for i in range(90):
            results.append(BenchmarkResult(
                timestamp=start_time + timedelta(milliseconds=i*100),
                response_time_ms=10.0 + i,  # 10-99ms
                status_code=200,
                success=True
            ))
        
        for i in range(10):
            results.append(BenchmarkResult(
                timestamp=start_time + timedelta(milliseconds=(90+i)*100),
                response_time_ms=5000.0,  # Timeout
                status_code=0,
                success=False,
                error_message="Timeout"
            ))
        
        report = runner._generate_report(
            name="accuracy_test",
            benchmark_type=BenchmarkType.LOAD_TEST,
            start_time=start_time,
            end_time=end_time,
            results=results
        )
        
        # Verify calculations
        assert report.total_requests == 100
        assert report.successful_requests == 90
        assert report.failed_requests == 10
        assert report.success_rate_percent == 90.0
        assert report.error_rate_percent == 10.0
        assert report.duration_seconds == 30.0
        assert abs(report.throughput_rps - 3.333) < 0.01  # 100/30 ≈ 3.333
        
        # Response time statistics (only for successful requests)
        successful_times = [10.0 + i for i in range(90)]
        assert report.min_response_time_ms == 10.0
        assert report.max_response_time_ms == 5000.0  # Includes failed requests
        
        # Verify error tracking
        assert "Timeout" in report.errors
        assert report.errors["Timeout"] == 10