"""Performance Benchmarking Framework for FastAPI Shield.

This module provides comprehensive benchmarking capabilities for shield performance
testing, including load testing, stress testing, and comparative analysis.
"""

import asyncio
import json
import statistics
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from threading import Lock

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from fastapi_shield.async_performance import (
    OptimizationConfig,
    OptimizedAsyncShield,
    PerformanceLevel
)
from fastapi_shield.shield import Shield


class BenchmarkType(str, Enum):
    """Types of benchmarks."""
    LOAD_TEST = "load_test"
    STRESS_TEST = "stress_test"
    SPIKE_TEST = "spike_test"
    VOLUME_TEST = "volume_test"
    ENDURANCE_TEST = "endurance_test"
    BASELINE = "baseline"
    COMPARATIVE = "comparative"


class BenchmarkMetric(str, Enum):
    """Benchmark metrics."""
    RESPONSE_TIME = "response_time_ms"
    THROUGHPUT = "throughput_rps"
    ERROR_RATE = "error_rate_percent"
    MEMORY_USAGE = "memory_usage_mb"
    CPU_USAGE = "cpu_usage_percent"
    LATENCY_P50 = "latency_p50_ms"
    LATENCY_P95 = "latency_p95_ms"
    LATENCY_P99 = "latency_p99_ms"
    CONCURRENT_REQUESTS = "concurrent_requests"
    SUCCESS_RATE = "success_rate_percent"


@dataclass
class BenchmarkRequest:
    """Benchmark request configuration."""
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    json: Optional[Dict[str, Any]] = None
    data: Optional[Union[str, bytes, Dict[str, Any]]] = None
    params: Dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0


@dataclass
class BenchmarkResult:
    """Individual benchmark result."""
    timestamp: datetime
    response_time_ms: float
    status_code: int
    success: bool
    error_message: Optional[str] = None
    memory_mb: Optional[float] = None
    cpu_percent: Optional[float] = None


@dataclass
class BenchmarkReport:
    """Comprehensive benchmark report."""
    name: str
    benchmark_type: BenchmarkType
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    
    # Performance metrics
    min_response_time_ms: float
    max_response_time_ms: float
    avg_response_time_ms: float
    median_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    
    throughput_rps: float
    success_rate_percent: float
    error_rate_percent: float
    
    # Resource usage
    avg_memory_mb: float = 0.0
    peak_memory_mb: float = 0.0
    avg_cpu_percent: float = 0.0
    peak_cpu_percent: float = 0.0
    
    # Additional data
    errors: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_results: List[BenchmarkResult] = field(default_factory=list)


class BenchmarkRunner(ABC):
    """Abstract base class for benchmark runners."""
    
    @abstractmethod
    async def run_benchmark(
        self,
        name: str,
        benchmark_type: BenchmarkType,
        request_config: BenchmarkRequest,
        **kwargs
    ) -> BenchmarkReport:
        """Run a benchmark and return results."""
        pass


class HTTPBenchmarkRunner(BenchmarkRunner):
    """HTTP-based benchmark runner."""
    
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
    
    async def run_benchmark(
        self,
        name: str,
        benchmark_type: BenchmarkType,
        request_config: BenchmarkRequest,
        duration_seconds: int = 60,
        concurrent_users: int = 10,
        requests_per_second: Optional[int] = None,
        total_requests: Optional[int] = None,
        ramp_up_seconds: int = 0,
        collect_system_metrics: bool = True
    ) -> BenchmarkReport:
        """Run HTTP benchmark."""
        if not self._client:
            raise RuntimeError("BenchmarkRunner must be used as async context manager")
        
        start_time = datetime.utcnow()
        results: List[BenchmarkResult] = []
        results_lock = Lock()
        
        # Calculate request parameters
        if total_requests:
            target_requests = total_requests
        elif requests_per_second:
            target_requests = requests_per_second * duration_seconds
        else:
            target_requests = concurrent_users * duration_seconds * 10  # Default 10 RPS per user
        
        semaphore = asyncio.Semaphore(concurrent_users)
        
        async def make_request(request_id: int) -> None:
            """Make a single HTTP request."""
            async with semaphore:
                request_start = time.perf_counter()
                
                try:
                    url = f"{self.base_url}{request_config.path}"
                    
                    response = await self._client.request(
                        method=request_config.method,
                        url=url,
                        headers=request_config.headers,
                        json=request_config.json,
                        data=request_config.data,
                        params=request_config.params,
                        timeout=request_config.timeout
                    )
                    
                    response_time_ms = (time.perf_counter() - request_start) * 1000
                    success = 200 <= response.status_code < 400
                    
                    result = BenchmarkResult(
                        timestamp=datetime.utcnow(),
                        response_time_ms=response_time_ms,
                        status_code=response.status_code,
                        success=success,
                        error_message=None if success else f"HTTP {response.status_code}"
                    )
                    
                except Exception as e:
                    response_time_ms = (time.perf_counter() - request_start) * 1000
                    result = BenchmarkResult(
                        timestamp=datetime.utcnow(),
                        response_time_ms=response_time_ms,
                        status_code=0,
                        success=False,
                        error_message=str(e)
                    )
                
                with results_lock:
                    results.append(result)
        
        # Execute benchmark based on type
        if benchmark_type == BenchmarkType.LOAD_TEST:
            await self._run_load_test(make_request, target_requests, duration_seconds, ramp_up_seconds)
        elif benchmark_type == BenchmarkType.STRESS_TEST:
            await self._run_stress_test(make_request, concurrent_users, duration_seconds)
        elif benchmark_type == BenchmarkType.SPIKE_TEST:
            await self._run_spike_test(make_request, concurrent_users, duration_seconds)
        elif benchmark_type == BenchmarkType.ENDURANCE_TEST:
            await self._run_endurance_test(make_request, target_requests, duration_seconds)
        else:
            await self._run_standard_test(make_request, target_requests)
        
        end_time = datetime.utcnow()
        
        # Generate report
        return self._generate_report(name, benchmark_type, start_time, end_time, results)
    
    async def _run_load_test(self, make_request: Callable, target_requests: int, 
                           duration_seconds: int, ramp_up_seconds: int) -> None:
        """Run load test with gradual ramp-up."""
        requests_per_second = target_requests / duration_seconds
        
        if ramp_up_seconds > 0:
            # Gradual ramp-up
            ramp_increment = requests_per_second / ramp_up_seconds
            current_rps = 0.0
            
            for second in range(ramp_up_seconds):
                current_rps += ramp_increment
                requests_this_second = int(current_rps)
                
                tasks = [make_request(i) for i in range(requests_this_second)]
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                
                await asyncio.sleep(1)
            
            # Continue at full rate
            remaining_seconds = duration_seconds - ramp_up_seconds
            for second in range(remaining_seconds):
                requests_this_second = int(requests_per_second)
                tasks = [make_request(i) for i in range(requests_this_second)]
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(1)
        else:
            # Immediate full load
            for second in range(duration_seconds):
                requests_this_second = int(requests_per_second)
                tasks = [make_request(i) for i in range(requests_this_second)]
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(1)
    
    async def _run_stress_test(self, make_request: Callable, concurrent_users: int, 
                             duration_seconds: int) -> None:
        """Run stress test with increasing concurrent users."""
        end_time = time.time() + duration_seconds
        request_id = 0
        
        # Start with base concurrent users
        base_users = max(1, concurrent_users // 4)
        current_users = base_users
        
        while time.time() < end_time:
            # Increase concurrent users every 10 seconds
            if int(time.time()) % 10 == 0:
                current_users = min(concurrent_users * 2, current_users + base_users)
            
            tasks = []
            for _ in range(current_users):
                tasks.append(make_request(request_id))
                request_id += 1
            
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(0.1)  # Brief pause between batches
    
    async def _run_spike_test(self, make_request: Callable, concurrent_users: int,
                            duration_seconds: int) -> None:
        """Run spike test with sudden load increases."""
        end_time = time.time() + duration_seconds
        request_id = 0
        
        while time.time() < end_time:
            # Normal load for 10 seconds
            for _ in range(100):  # 10 seconds at 10 requests/second
                await make_request(request_id)
                request_id += 1
                await asyncio.sleep(0.1)
                
                if time.time() >= end_time:
                    break
            
            if time.time() >= end_time:
                break
            
            # Spike load for 5 seconds
            for _ in range(5):  # 5 seconds
                tasks = []
                for _ in range(concurrent_users):
                    tasks.append(make_request(request_id))
                    request_id += 1
                
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(1)
                
                if time.time() >= end_time:
                    break
    
    async def _run_endurance_test(self, make_request: Callable, target_requests: int,
                                duration_seconds: int) -> None:
        """Run endurance test with consistent load over time."""
        requests_per_second = target_requests / duration_seconds
        
        for second in range(duration_seconds):
            requests_this_second = int(requests_per_second)
            
            tasks = []
            for i in range(requests_this_second):
                tasks.append(make_request(second * requests_this_second + i))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            await asyncio.sleep(1)
    
    async def _run_standard_test(self, make_request: Callable, target_requests: int) -> None:
        """Run standard benchmark test."""
        tasks = []
        for i in range(target_requests):
            tasks.append(make_request(i))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    def _generate_report(self, name: str, benchmark_type: BenchmarkType, 
                        start_time: datetime, end_time: datetime,
                        results: List[BenchmarkResult]) -> BenchmarkReport:
        """Generate benchmark report from results."""
        duration_seconds = (end_time - start_time).total_seconds()
        
        if not results:
            return BenchmarkReport(
                name=name,
                benchmark_type=benchmark_type,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration_seconds,
                total_requests=0,
                successful_requests=0,
                failed_requests=0,
                min_response_time_ms=0,
                max_response_time_ms=0,
                avg_response_time_ms=0,
                median_response_time_ms=0,
                p95_response_time_ms=0,
                p99_response_time_ms=0,
                throughput_rps=0,
                success_rate_percent=0,
                error_rate_percent=0
            )
        
        successful_results = [r for r in results if r.success]
        failed_results = [r for r in results if not r.success]
        
        response_times = [r.response_time_ms for r in results]
        response_times.sort()
        
        # Calculate percentiles
        n = len(response_times)
        p95_index = int(n * 0.95)
        p99_index = int(n * 0.99)
        median_index = n // 2
        
        # Calculate error distribution
        errors = defaultdict(int)
        for result in failed_results:
            if result.error_message:
                errors[result.error_message] += 1
        
        # Resource usage statistics
        memory_values = [r.memory_mb for r in results if r.memory_mb is not None]
        cpu_values = [r.cpu_percent for r in results if r.cpu_percent is not None]
        
        return BenchmarkReport(
            name=name,
            benchmark_type=benchmark_type,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration_seconds,
            total_requests=len(results),
            successful_requests=len(successful_results),
            failed_requests=len(failed_results),
            
            min_response_time_ms=min(response_times),
            max_response_time_ms=max(response_times),
            avg_response_time_ms=statistics.mean(response_times),
            median_response_time_ms=response_times[median_index],
            p95_response_time_ms=response_times[p95_index] if p95_index < n else response_times[-1],
            p99_response_time_ms=response_times[p99_index] if p99_index < n else response_times[-1],
            
            throughput_rps=len(results) / duration_seconds if duration_seconds > 0 else 0,
            success_rate_percent=(len(successful_results) / len(results)) * 100,
            error_rate_percent=(len(failed_results) / len(results)) * 100,
            
            avg_memory_mb=statistics.mean(memory_values) if memory_values else 0,
            peak_memory_mb=max(memory_values) if memory_values else 0,
            avg_cpu_percent=statistics.mean(cpu_values) if cpu_values else 0,
            peak_cpu_percent=max(cpu_values) if cpu_values else 0,
            
            errors=dict(errors),
            raw_results=results
        )


class ShieldBenchmark:
    """Specialized benchmark for shield performance."""
    
    def __init__(self, app: FastAPI):
        self.app = app
        self.client = TestClient(app)
    
    async def benchmark_shield_performance(
        self,
        shield: Shield,
        endpoint_path: str = "/test",
        method: str = "GET",
        iterations: int = 1000,
        concurrent_requests: int = 10,
        warmup_iterations: int = 100
    ) -> Dict[str, Any]:
        """Benchmark a specific shield's performance."""
        
        # Create test endpoint
        @self.app.get(endpoint_path)
        @self.app.post(endpoint_path)
        @shield
        def test_endpoint(request: Request):
            return {"message": "success", "timestamp": time.time()}
        
        # Warmup
        for _ in range(warmup_iterations):
            if method.upper() == "GET":
                self.client.get(endpoint_path)
            elif method.upper() == "POST":
                self.client.post(endpoint_path, json={"test": "data"})
        
        # Benchmark
        results = []
        semaphore = asyncio.Semaphore(concurrent_requests)
        
        async def make_test_request():
            async with semaphore:
                start_time = time.perf_counter()
                
                try:
                    if method.upper() == "GET":
                        response = self.client.get(endpoint_path)
                    elif method.upper() == "POST":
                        response = self.client.post(endpoint_path, json={"test": "data"})
                    else:
                        response = self.client.request(method, endpoint_path)
                    
                    end_time = time.perf_counter()
                    duration_ms = (end_time - start_time) * 1000
                    
                    results.append({
                        "duration_ms": duration_ms,
                        "status_code": response.status_code,
                        "success": 200 <= response.status_code < 400
                    })
                    
                except Exception as e:
                    end_time = time.perf_counter()
                    duration_ms = (end_time - start_time) * 1000
                    
                    results.append({
                        "duration_ms": duration_ms,
                        "status_code": 0,
                        "success": False,
                        "error": str(e)
                    })
        
        # Run benchmark
        start_time = time.perf_counter()
        tasks = [make_test_request() for _ in range(iterations)]
        await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.perf_counter() - start_time
        
        # Calculate statistics
        durations = [r["duration_ms"] for r in results]
        successful_requests = len([r for r in results if r["success"]])
        
        if durations:
            durations.sort()
            n = len(durations)
            
            stats = {
                "shield_name": getattr(shield, 'name', 'unknown'),
                "total_requests": len(results),
                "successful_requests": successful_requests,
                "success_rate": (successful_requests / len(results)) * 100,
                "total_time_seconds": total_time,
                "throughput_rps": len(results) / total_time,
                "min_response_time_ms": min(durations),
                "max_response_time_ms": max(durations),
                "avg_response_time_ms": statistics.mean(durations),
                "median_response_time_ms": durations[n // 2],
                "p95_response_time_ms": durations[int(n * 0.95)],
                "p99_response_time_ms": durations[int(n * 0.99)],
                "std_dev_ms": statistics.stdev(durations) if n > 1 else 0
            }
            
            return stats
        
        return {
            "shield_name": getattr(shield, 'name', 'unknown'),
            "total_requests": 0,
            "error": "No successful requests"
        }


class ComparativeBenchmark:
    """Comparative benchmark for testing shield performance differences."""
    
    def __init__(self, app: FastAPI):
        self.app = app
        self.benchmark = ShieldBenchmark(app)
    
    async def compare_shields(
        self,
        shields: List[Tuple[str, Shield]],
        endpoint_path: str = "/test",
        method: str = "GET",
        iterations: int = 1000,
        concurrent_requests: int = 10
    ) -> Dict[str, Any]:
        """Compare performance of multiple shields."""
        
        results = {}
        
        for shield_name, shield in shields:
            print(f"Benchmarking {shield_name}...")
            
            # Create unique endpoint for this shield
            test_path = f"{endpoint_path}_{shield_name.lower().replace(' ', '_')}"
            
            result = await self.benchmark.benchmark_shield_performance(
                shield=shield,
                endpoint_path=test_path,
                method=method,
                iterations=iterations,
                concurrent_requests=concurrent_requests
            )
            
            results[shield_name] = result
        
        # Generate comparison summary
        comparison = self._generate_comparison_summary(results)
        
        return {
            "individual_results": results,
            "comparison": comparison
        }
    
    async def compare_optimization_levels(
        self,
        shield_func: Callable,
        optimization_levels: List[PerformanceLevel],
        iterations: int = 1000,
        concurrent_requests: int = 10
    ) -> Dict[str, Any]:
        """Compare different optimization levels for the same shield function."""
        
        shields = []
        
        for level in optimization_levels:
            config = OptimizationConfig(level=level)
            shield = OptimizedAsyncShield(
                shield_func, 
                config, 
                name=f"optimized_{level.value}"
            )
            shields.append((f"Optimization Level: {level.value}", shield))
        
        return await self.compare_shields(
            shields=shields,
            iterations=iterations,
            concurrent_requests=concurrent_requests
        )
    
    def _generate_comparison_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comparison summary from individual results."""
        if not results:
            return {}
        
        # Find best and worst performers
        valid_results = {k: v for k, v in results.items() if "avg_response_time_ms" in v}
        
        if not valid_results:
            return {"error": "No valid results to compare"}
        
        # Best/worst by response time
        best_response_time = min(valid_results.items(), key=lambda x: x[1]["avg_response_time_ms"])
        worst_response_time = max(valid_results.items(), key=lambda x: x[1]["avg_response_time_ms"])
        
        # Best/worst by throughput
        best_throughput = max(valid_results.items(), key=lambda x: x[1]["throughput_rps"])
        worst_throughput = min(valid_results.items(), key=lambda x: x[1]["throughput_rps"])
        
        # Calculate relative performance
        base_response_time = worst_response_time[1]["avg_response_time_ms"]
        base_throughput = worst_throughput[1]["throughput_rps"]
        
        relative_performance = {}
        for name, result in valid_results.items():
            if base_response_time > 0 and base_throughput > 0:
                relative_performance[name] = {
                    "response_time_improvement": (
                        (base_response_time - result["avg_response_time_ms"]) / base_response_time
                    ) * 100,
                    "throughput_improvement": (
                        (result["throughput_rps"] - base_throughput) / base_throughput
                    ) * 100
                }
        
        return {
            "best_response_time": {
                "shield": best_response_time[0],
                "value_ms": best_response_time[1]["avg_response_time_ms"]
            },
            "worst_response_time": {
                "shield": worst_response_time[0],
                "value_ms": worst_response_time[1]["avg_response_time_ms"]
            },
            "best_throughput": {
                "shield": best_throughput[0],
                "value_rps": best_throughput[1]["throughput_rps"]
            },
            "worst_throughput": {
                "shield": worst_throughput[0],
                "value_rps": worst_throughput[1]["throughput_rps"]
            },
            "relative_performance": relative_performance
        }


class BenchmarkSuite:
    """Comprehensive benchmark suite for shield performance testing."""
    
    def __init__(self, base_url: Optional[str] = None, app: Optional[FastAPI] = None):
        self.base_url = base_url
        self.app = app
        self.results: List[BenchmarkReport] = []
    
    async def run_comprehensive_benchmark(
        self,
        shield: Shield,
        endpoint_path: str = "/benchmark",
        include_load_test: bool = True,
        include_stress_test: bool = True,
        include_spike_test: bool = True,
        include_endurance_test: bool = True
    ) -> Dict[str, BenchmarkReport]:
        """Run comprehensive benchmark suite for a shield."""
        
        results = {}
        
        if self.app:
            # Setup test endpoint
            @self.app.get(endpoint_path)
            @shield
            def benchmark_endpoint(request: Request):
                return {"message": "benchmark", "timestamp": time.time()}
        
        request_config = BenchmarkRequest(
            method="GET",
            path=endpoint_path
        )
        
        if self.base_url:
            async with HTTPBenchmarkRunner(self.base_url) as runner:
                if include_load_test:
                    results["load_test"] = await runner.run_benchmark(
                        name=f"{shield.name}_load_test",
                        benchmark_type=BenchmarkType.LOAD_TEST,
                        request_config=request_config,
                        duration_seconds=60,
                        concurrent_users=10,
                        ramp_up_seconds=10
                    )
                
                if include_stress_test:
                    results["stress_test"] = await runner.run_benchmark(
                        name=f"{shield.name}_stress_test",
                        benchmark_type=BenchmarkType.STRESS_TEST,
                        request_config=request_config,
                        duration_seconds=30,
                        concurrent_users=50
                    )
                
                if include_spike_test:
                    results["spike_test"] = await runner.run_benchmark(
                        name=f"{shield.name}_spike_test",
                        benchmark_type=BenchmarkType.SPIKE_TEST,
                        request_config=request_config,
                        duration_seconds=30,
                        concurrent_users=100
                    )
                
                if include_endurance_test:
                    results["endurance_test"] = await runner.run_benchmark(
                        name=f"{shield.name}_endurance_test",
                        benchmark_type=BenchmarkType.ENDURANCE_TEST,
                        request_config=request_config,
                        duration_seconds=300,  # 5 minutes
                        concurrent_users=5
                    )
        
        elif self.app:
            # Use internal benchmark for app-based testing
            benchmark = ShieldBenchmark(self.app)
            
            if include_load_test:
                load_result = await benchmark.benchmark_shield_performance(
                    shield=shield,
                    endpoint_path=endpoint_path,
                    iterations=1000,
                    concurrent_requests=10
                )
                results["load_test"] = load_result
        
        # Store results
        for report in results.values():
            if isinstance(report, BenchmarkReport):
                self.results.append(report)
        
        return results
    
    def export_results(self, filename: str) -> None:
        """Export benchmark results to JSON file."""
        export_data = []
        
        for result in self.results:
            if isinstance(result, BenchmarkReport):
                # Convert to dict, excluding raw_results for cleaner export
                result_dict = asdict(result)
                result_dict.pop('raw_results', None)
                export_data.append(result_dict)
            else:
                export_data.append(result)
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate summary report from all benchmark results."""
        if not self.results:
            return {"error": "No benchmark results available"}
        
        summary = {
            "total_benchmarks": len(self.results),
            "benchmark_types": defaultdict(int),
            "overall_stats": {
                "total_requests": 0,
                "total_successful_requests": 0,
                "total_failed_requests": 0,
                "avg_throughput_rps": 0,
                "avg_response_time_ms": 0
            }
        }
        
        response_times = []
        throughputs = []
        
        for result in self.results:
            if isinstance(result, BenchmarkReport):
                summary["benchmark_types"][result.benchmark_type.value] += 1
                summary["overall_stats"]["total_requests"] += result.total_requests
                summary["overall_stats"]["total_successful_requests"] += result.successful_requests
                summary["overall_stats"]["total_failed_requests"] += result.failed_requests
                
                response_times.append(result.avg_response_time_ms)
                throughputs.append(result.throughput_rps)
        
        if response_times:
            summary["overall_stats"]["avg_response_time_ms"] = statistics.mean(response_times)
        
        if throughputs:
            summary["overall_stats"]["avg_throughput_rps"] = statistics.mean(throughputs)
        
        return summary


# Convenience functions for quick benchmarking

async def quick_benchmark(shield: Shield, iterations: int = 1000) -> Dict[str, Any]:
    """Quick benchmark of a shield."""
    app = FastAPI()
    benchmark = ShieldBenchmark(app)
    
    return await benchmark.benchmark_shield_performance(
        shield=shield,
        iterations=iterations
    )


async def compare_shield_performance(shields: List[Tuple[str, Shield]], 
                                   iterations: int = 1000) -> Dict[str, Any]:
    """Compare performance of multiple shields."""
    app = FastAPI()
    comparison = ComparativeBenchmark(app)
    
    return await comparison.compare_shields(
        shields=shields,
        iterations=iterations
    )


async def benchmark_optimization_levels(shield_func: Callable, 
                                      iterations: int = 1000) -> Dict[str, Any]:
    """Benchmark different optimization levels."""
    app = FastAPI()
    comparison = ComparativeBenchmark(app)
    
    return await comparison.compare_optimization_levels(
        shield_func=shield_func,
        optimization_levels=list(PerformanceLevel),
        iterations=iterations
    )