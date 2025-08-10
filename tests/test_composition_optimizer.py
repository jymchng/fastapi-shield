"""Tests for Shield Composition Optimizer."""

import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch

from fastapi_shield.composition_optimizer import (
    ShieldCompositionOptimizer,
    StaticAnalyzer,
    PerformanceAnalyzer,
    DependencyAnalyzer,
    OptimizationEngine,
    OptimizationLevel,
    OptimizationType,
    AnalysisType,
    PerformanceMetrics,
    ShieldAnalysis,
    CompositionAnalysis,
    OptimizationRecommendation,
    create_basic_optimizer,
    create_performance_focused_optimizer,
    create_conservative_optimizer,
    analyze_shield_composition,
    benchmark_shields,
)

from tests.mocks.composition_optimizer_mocks import (
    MockShield,
    MockAnalyzer,
    ShieldCompositionBuilder,
    OptimizationTestScenarios,
    PerformanceTestHelper,
    OptimizationTestValidator,
)


class TestShieldCompositionOptimizer:
    """Test ShieldCompositionOptimizer class."""
    
    @pytest.mark.asyncio
    async def test_basic_composition_analysis(self):
        """Test basic composition analysis functionality."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.simple_composition()
        
        analysis = await optimizer.analyze_composition(shields)
        
        # Validate analysis structure
        OptimizationTestValidator.validate_analysis_completeness(analysis, shields)
        assert len(analysis.optimization_opportunities) > 0
        assert analysis.dependency_graph is not None
        assert isinstance(analysis.metadata, dict)
    
    @pytest.mark.asyncio
    async def test_redundancy_detection(self):
        """Test detection of redundant shields in composition."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.redundant_composition()
        
        analysis = await optimizer.analyze_composition(shields)
        
        # Should detect redundancies
        assert len(analysis.redundancies) > 0
        OptimizationTestValidator.validate_redundancy_detection(analysis)
        
        # Check redundancy details
        redundancy_types = {r.get('type') for r in analysis.redundancies}
        assert 'capability_duplication' in redundancy_types
    
    @pytest.mark.asyncio
    async def test_bottleneck_detection(self):
        """Test detection of performance bottlenecks."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.performance_bottleneck_composition()
        
        analysis = await optimizer.analyze_composition(shields)
        
        # Should detect bottlenecks
        assert len(analysis.bottlenecks) > 0
        OptimizationTestValidator.validate_bottleneck_detection(analysis)
        
        # Check bottleneck types
        bottleneck_types = {b.get('type') for b in analysis.bottlenecks}
        expected_types = {'high_latency', 'configured_high_latency', 'high_execution_time'}
        assert len(bottleneck_types.intersection(expected_types)) > 0
    
    @pytest.mark.asyncio
    async def test_dependency_analysis(self):
        """Test dependency analysis between shields."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.dependent_shields_composition()
        
        analysis = await optimizer.analyze_composition(shields)
        
        # Should have dependency graph
        assert len(analysis.dependency_graph) > 0
        
        # Check specific dependencies
        dependency_keys = set(analysis.dependency_graph.keys())
        assert len(dependency_keys) > 0
    
    @pytest.mark.asyncio
    async def test_compatibility_analysis(self):
        """Test compatibility analysis for mixed shield types."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.mixed_async_sync_composition()
        
        analysis = await optimizer.analyze_composition(shields)
        
        # Should detect compatibility issues
        assert len(analysis.compatibility_issues) > 0
        
        # Check for async/sync compatibility issue
        issue_types = {issue.get('type') for issue in analysis.compatibility_issues}
        assert 'async_sync_mix' in issue_types
    
    @pytest.mark.asyncio
    async def test_optimization_recommendations(self):
        """Test generation of optimization recommendations."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.redundant_composition()
        
        recommendations, _ = await optimizer.optimize_composition(shields)
        
        # Should generate recommendations
        OptimizationTestValidator.validate_recommendations_quality(recommendations)
        
        # Check recommendation types
        rec_types = {rec.optimization_type for rec in recommendations}
        assert OptimizationType.REDUNDANCY_ELIMINATION in rec_types
    
    @pytest.mark.asyncio
    async def test_performance_analysis_integration(self):
        """Test integration with performance analysis."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.simple_composition()
        
        analysis = await optimizer.analyze_composition(shields, include_performance=True)
        
        # Should have performance metrics
        assert analysis.performance_metrics is not None
        OptimizationTestValidator.validate_performance_metrics(analysis.performance_metrics)
    
    @pytest.mark.asyncio
    async def test_caching_functionality(self):
        """Test analysis result caching."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.simple_composition()
        
        # First analysis
        start_time = time.perf_counter()
        analysis1 = await optimizer.analyze_composition(shields, include_performance=False)
        first_duration = time.perf_counter() - start_time
        
        # Second analysis (should be cached)
        start_time = time.perf_counter()
        analysis2 = await optimizer.analyze_composition(shields, include_performance=False)
        second_duration = time.perf_counter() - start_time
        
        # Second should be faster due to caching
        assert second_duration < first_duration * 0.5
        assert analysis1.shields == analysis2.shields
        
        # Clear cache and verify
        optimizer.clear_cache()
        cache_stats = optimizer.get_cache_stats()
        assert cache_stats['cache_size'] == 0
    
    @pytest.mark.asyncio
    async def test_different_optimization_levels(self):
        """Test different optimization levels produce different results."""
        shields = OptimizationTestScenarios.redundant_composition()
        
        # Conservative optimizer
        conservative = ShieldCompositionOptimizer(OptimizationLevel.CONSERVATIVE)
        conservative_recs, _ = await conservative.optimize_composition(shields)
        
        # Aggressive optimizer
        aggressive = ShieldCompositionOptimizer(OptimizationLevel.AGGRESSIVE)
        aggressive_recs, _ = await aggressive.optimize_composition(shields)
        
        # Aggressive should produce more recommendations
        assert len(aggressive_recs) >= len(conservative_recs)
        
        # Conservative recommendations should all be low risk
        for rec in conservative_recs:
            assert rec.risk_level in ["low", "medium"]
    
    @pytest.mark.asyncio
    async def test_parallel_execution_detection(self):
        """Test detection of parallel execution opportunities."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.independent_shields_composition()
        
        recommendations, _ = await optimizer.optimize_composition(shields)
        
        # Should suggest parallel execution
        parallel_recs = [
            rec for rec in recommendations 
            if rec.optimization_type == OptimizationType.PARALLEL_EXECUTION
        ]
        assert len(parallel_recs) > 0
    
    @pytest.mark.asyncio
    async def test_resource_pooling_recommendations(self):
        """Test resource pooling recommendations."""
        shields = (ShieldCompositionBuilder()
                  .add_database_shield("DB1")
                  .add_database_shield("DB2")
                  .add_cache_shield("Cache1") 
                  .add_cache_shield("Cache2")
                  .build())
        
        optimizer = ShieldCompositionOptimizer()
        recommendations, _ = await optimizer.optimize_composition(shields)
        
        # Should suggest resource pooling
        pooling_recs = [
            rec for rec in recommendations
            if rec.optimization_type == OptimizationType.RESOURCE_POOLING
        ]
        assert len(pooling_recs) > 0
    
    @pytest.mark.asyncio
    async def test_benchmark_composition_performance(self):
        """Test composition performance benchmarking."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.simple_composition()
        
        metrics = await optimizer.benchmark_composition(shields, request_count=25)
        
        # Validate metrics
        OptimizationTestValidator.validate_performance_metrics(metrics)
        assert metrics.total_requests == 25
        assert metrics.execution_time > 0
        assert 'requests_per_second' in metrics.metadata
    
    @pytest.mark.asyncio
    async def test_auto_apply_safe_optimizations(self):
        """Test automatic application of safe optimizations."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.simple_composition()
        
        recommendations, optimized_shields = await optimizer.optimize_composition(
            shields, auto_apply=True
        )
        
        # Should return both recommendations and optimized shields
        assert recommendations is not None
        if optimized_shields is not None:  # Some optimizations might not be auto-applicable
            assert len(optimized_shields) == len(shields)


class TestShieldAnalyzers:
    """Test individual shield analyzers."""
    
    @pytest.mark.asyncio
    async def test_static_analyzer(self):
        """Test static analyzer functionality."""
        analyzer = StaticAnalyzer()
        shield = MockShield(
            name="TestShield",
            dependencies={'redis', 'database'},
            capabilities={'authentication', 'validation'}
        )
        
        analysis = await analyzer.analyze(shield)
        
        assert analysis.shield_type == "MockShield"
        assert len(analysis.dependencies) > 0
        # Capabilities should come from the shield's explicit capabilities
        assert len(analysis.capabilities) >= 2  # authentication, validation
        assert analyzer.get_analysis_type() == AnalysisType.STATIC_ANALYSIS
    
    @pytest.mark.asyncio
    async def test_performance_analyzer(self):
        """Test performance analyzer functionality."""
        analyzer = PerformanceAnalyzer()
        shield = MockShield(name="PerfShield", execution_time=0.05)
        
        analysis = await analyzer.analyze(shield)
        
        assert analyzer.get_analysis_type() == AnalysisType.PERFORMANCE_ANALYSIS
        
        # Should have performance characteristics (either from profiling or fallback)
        assert len(analysis.performance_characteristics) > 0
        
        # Check for either profiled or fallback metrics
        has_avg_time = 'avg_execution_time' in analysis.performance_characteristics
        has_estimated_time = 'estimated_memory_usage' in analysis.performance_characteristics
        
        assert has_avg_time or has_estimated_time, f"Performance characteristics: {analysis.performance_characteristics}, Metadata: {analysis.metadata}"
    
    @pytest.mark.asyncio
    async def test_dependency_analyzer(self):
        """Test dependency analyzer functionality."""
        analyzer = DependencyAnalyzer()
        shield = MockShield(
            name="DepShield",
            dependencies={'redis', 'database'},
            capabilities={'caching', 'storage'}
        )
        
        analysis = await analyzer.analyze(shield)
        
        assert analyzer.get_analysis_type() == AnalysisType.DEPENDENCY_ANALYSIS
        assert len(analysis.dependencies) >= 2
        assert len(analysis.capabilities) >= 2
    
    @pytest.mark.asyncio
    async def test_mock_analyzer_functionality(self):
        """Test mock analyzer for testing purposes."""
        mock_analyses = {
            'Test': {  # Use shield name instead of shield type
                'dependencies': ['redis'],
                'capabilities': ['caching'],
                'optimization_opportunities': ['parallel_execution']
            }
        }
        
        analyzer = MockAnalyzer(AnalysisType.STATIC_ANALYSIS, mock_analyses)
        shield = MockShield(name="Test")
        
        analysis = await analyzer.analyze(shield)
        
        assert 'redis' in analysis.dependencies
        assert 'caching' in analysis.capabilities
        assert 'parallel_execution' in analysis.optimization_opportunities
        assert analyzer.get_analyze_call_count() == 1


class TestOptimizationEngine:
    """Test optimization engine functionality."""
    
    def test_recommendation_generation(self):
        """Test generation of optimization recommendations."""
        engine = OptimizationEngine(OptimizationLevel.MODERATE)
        
        # Create analysis with redundancies
        analysis = CompositionAnalysis(
            shields=[],
            shield_analyses=[],
            redundancies=[{
                'type': 'capability_duplication',
                'capability': 'authentication',
                'shields': ['Auth1', 'Auth2'],
                'time_savings': 0.1,
                'memory_savings': 0.05
            }]
        )
        
        recommendations = engine.generate_recommendations(analysis)
        
        assert len(recommendations) > 0
        
        # Check redundancy elimination recommendation
        redundancy_recs = [
            r for r in recommendations 
            if r.optimization_type == OptimizationType.REDUNDANCY_ELIMINATION
        ]
        assert len(redundancy_recs) > 0
    
    def test_optimization_level_filtering(self):
        """Test filtering by optimization level."""
        # Conservative engine should filter out high-risk recommendations
        conservative_engine = OptimizationEngine(OptimizationLevel.CONSERVATIVE)
        
        # Create high-risk recommendation
        high_risk_rec = OptimizationRecommendation(
            optimization_type=OptimizationType.PARALLEL_EXECUTION,
            description="High risk optimization",
            estimated_improvement={'performance': 0.5},
            implementation_complexity="high",
            risk_level="high",
            applicable_shields=["TestShield"]
        )
        
        # Test internal filtering method
        filtered = conservative_engine._filter_by_optimization_level([high_risk_rec])
        assert len(filtered) == 0  # Should filter out high-risk recommendation
    
    def test_recommendation_sorting(self):
        """Test sorting of recommendations by improvement."""
        engine = OptimizationEngine()
        
        # Create analysis with multiple optimization opportunities
        analysis = CompositionAnalysis(
            shields=[],
            shield_analyses=[
                ShieldAnalysis(
                    shield=MockShield("TestShield1"),
                    shield_type="TestShield1",
                    compatibility_info={'cacheable': True}
                ),
                ShieldAnalysis(
                    shield=MockShield("TestShield2"),
                    shield_type="TestShield2",
                    compatibility_info={'cacheable': True}
                )
            ]
        )
        
        recommendations = engine.generate_recommendations(analysis)
        
        if len(recommendations) > 1:
            # Should be sorted by total estimated improvement
            improvements = [sum(r.estimated_improvement.values()) for r in recommendations]
            assert improvements == sorted(improvements, reverse=True)


class TestConvenienceFunctions:
    """Test convenience functions for creating optimizers."""
    
    def test_create_basic_optimizer(self):
        """Test basic optimizer creation."""
        optimizer = create_basic_optimizer(OptimizationLevel.CONSERVATIVE)
        
        assert isinstance(optimizer, ShieldCompositionOptimizer)
        assert optimizer.optimization_level == OptimizationLevel.CONSERVATIVE
        assert len(optimizer.analyzers) > 0
    
    def test_create_performance_focused_optimizer(self):
        """Test performance-focused optimizer creation."""
        optimizer = create_performance_focused_optimizer()
        
        assert isinstance(optimizer, ShieldCompositionOptimizer)
        assert optimizer.optimization_level == OptimizationLevel.AGGRESSIVE
        
        # Should include performance analyzer
        analyzer_types = {type(analyzer) for analyzer in optimizer.analyzers}
        assert PerformanceAnalyzer in analyzer_types
    
    def test_create_conservative_optimizer(self):
        """Test conservative optimizer creation."""
        optimizer = create_conservative_optimizer()
        
        assert isinstance(optimizer, ShieldCompositionOptimizer)
        assert optimizer.optimization_level == OptimizationLevel.CONSERVATIVE
        
        # Should only use static analyzer for safety
        assert len(optimizer.analyzers) == 1
        assert isinstance(optimizer.analyzers[0], StaticAnalyzer)
    
    def test_analyze_shield_composition_function(self):
        """Test convenience function for shield composition analysis."""
        shields = OptimizationTestScenarios.simple_composition()
        
        analysis, recommendations = analyze_shield_composition(
            shields, OptimizationLevel.MODERATE
        )
        
        assert isinstance(analysis, CompositionAnalysis)
        assert isinstance(recommendations, list)
        OptimizationTestValidator.validate_analysis_completeness(analysis, shields)
    
    def test_benchmark_shields_function(self):
        """Test convenience function for benchmarking shields."""
        shields = OptimizationTestScenarios.simple_composition()
        
        metrics = benchmark_shields(shields, request_count=20)
        
        assert isinstance(metrics, PerformanceMetrics)
        OptimizationTestValidator.validate_performance_metrics(metrics)
        assert metrics.total_requests == 20


class TestPerformanceMetrics:
    """Test performance metrics functionality."""
    
    def test_performance_metrics_creation(self):
        """Test creation of performance metrics."""
        metrics = PerformanceMetrics(
            execution_time=1.0,
            memory_usage=50.0,
            success_count=100,
            failure_count=5,
            total_requests=105
        )
        
        assert metrics.execution_time == 1.0
        assert metrics.memory_usage == 50.0
        assert metrics.success_count == 100
        assert metrics.failure_count == 5
        assert metrics.total_requests == 105
    
    def test_performance_metrics_to_dict(self):
        """Test conversion of performance metrics to dictionary."""
        metrics = PerformanceMetrics(
            execution_time=2.0,
            total_requests=50,
            metadata={'test': 'value'}
        )
        
        metrics_dict = metrics.to_dict()
        
        assert isinstance(metrics_dict, dict)
        assert metrics_dict['execution_time'] == 2.0
        assert metrics_dict['total_requests'] == 50
        assert metrics_dict['metadata']['test'] == 'value'


class TestOptimizationRecommendation:
    """Test optimization recommendation functionality."""
    
    def test_recommendation_creation(self):
        """Test creation of optimization recommendations."""
        recommendation = OptimizationRecommendation(
            optimization_type=OptimizationType.CACHING,
            description="Add caching layer",
            estimated_improvement={'performance': 0.3},
            implementation_complexity="medium",
            risk_level="low",
            applicable_shields=["TestShield"]
        )
        
        assert recommendation.optimization_type == OptimizationType.CACHING
        assert recommendation.description == "Add caching layer"
        assert recommendation.estimated_improvement['performance'] == 0.3
    
    def test_recommendation_to_dict(self):
        """Test conversion of recommendation to dictionary."""
        recommendation = OptimizationRecommendation(
            optimization_type=OptimizationType.REORDERING,
            description="Reorder shields",
            estimated_improvement={'latency': 0.15},
            implementation_complexity="low",
            risk_level="low",
            applicable_shields=["Shield1", "Shield2"],
            code_example="# Example code"
        )
        
        rec_dict = recommendation.to_dict()
        
        assert isinstance(rec_dict, dict)
        assert rec_dict['optimization_type'] == 'reordering'
        assert rec_dict['description'] == "Reorder shields"
        assert rec_dict['code_example'] == "# Example code"


class TestComplexOptimizationScenarios:
    """Test complex optimization scenarios."""
    
    @pytest.mark.asyncio
    async def test_complex_composition_optimization(self):
        """Test optimization of complex shield compositions."""
        optimizer = ShieldCompositionOptimizer(OptimizationLevel.AGGRESSIVE)
        shields = ShieldCompositionBuilder().build_complex_composition()
        
        analysis = await optimizer.analyze_composition(shields)
        recommendations, _ = await optimizer.optimize_composition(shields)
        
        # Complex composition should generate multiple types of recommendations
        rec_types = {rec.optimization_type for rec in recommendations}
        assert len(rec_types) >= 2
        
        # Should detect various optimization opportunities
        assert len(analysis.optimization_opportunities) > 0
        assert len(analysis.shield_analyses) == len(shields)
    
    @pytest.mark.asyncio
    async def test_high_resource_composition_analysis(self):
        """Test analysis of high-resource compositions."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.high_resource_composition()
        
        analysis = await optimizer.analyze_composition(shields)
        
        # Should identify resource optimization opportunities
        resource_opts = [
            opt for opt in analysis.optimization_opportunities
            if 'resource' in opt.get('type', '').lower()
        ]
        assert len(resource_opts) > 0 or len(analysis.bottlenecks) > 0
    
    @pytest.mark.asyncio
    async def test_performance_comparison(self):
        """Test performance comparison between compositions."""
        original_shields = OptimizationTestScenarios.performance_bottleneck_composition()
        optimized_shields = OptimizationTestScenarios.simple_composition()
        
        comparison = await PerformanceTestHelper.compare_composition_performance(
            original_shields, optimized_shields, request_count=20
        )
        
        assert 'original_performance' in comparison
        assert 'optimized_performance' in comparison
        assert 'improvement' in comparison
        
        # Optimized should generally be faster
        original_time = comparison['original_performance']['total_time']
        optimized_time = comparison['optimized_performance']['total_time']
        assert optimized_time <= original_time * 2  # Allow some variance
    
    @pytest.mark.asyncio
    async def test_concurrent_optimization_analysis(self):
        """Test optimization analysis under concurrent conditions."""
        optimizer = ShieldCompositionOptimizer()
        shields = OptimizationTestScenarios.simple_composition()
        
        # Run multiple analyses concurrently
        tasks = []
        for _ in range(5):
            task = asyncio.create_task(optimizer.analyze_composition(shields))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # All results should be successful and consistent
        assert len(results) == 5
        for result in results:
            assert isinstance(result, CompositionAnalysis)
            assert len(result.shield_analyses) == len(shields)
    
    @pytest.mark.asyncio
    async def test_optimization_with_errors(self):
        """Test optimization behavior with analyzer errors."""
        # Create analyzer that raises exceptions
        class ErrorAnalyzer(MockAnalyzer):
            async def analyze(self, shield):
                raise Exception("Analyzer error")
        
        error_analyzer = ErrorAnalyzer(AnalysisType.STATIC_ANALYSIS)
        optimizer = ShieldCompositionOptimizer(analyzers=[error_analyzer])
        shields = OptimizationTestScenarios.simple_composition()
        
        # Should handle analyzer errors gracefully
        analysis = await optimizer.analyze_composition(shields)
        
        # Should still produce basic analysis structure
        assert isinstance(analysis, CompositionAnalysis)
        assert len(analysis.shield_analyses) == len(shields)


class TestMockClasses:
    """Test mock classes used in testing."""
    
    @pytest.mark.asyncio
    async def test_mock_shield_functionality(self):
        """Test MockShield functionality."""
        shield = MockShield(
            name="TestShield",
            execution_time=0.01,
            should_block=True,
            dependencies={'redis'},
            capabilities={'caching'}
        )
        
        mock_request = Mock()
        
        # Test execution
        result = await shield._mock_shield_function(mock_request)
        assert result is not None  # Should block
        assert shield.call_count == 1
        
        # Test performance stats
        stats = shield.get_performance_stats()
        assert stats['call_count'] == 1
        assert stats['avg_execution_time'] > 0
        
        # Test configuration changes
        shield.set_blocking(False)
        result = await shield._mock_shield_function(mock_request)
        assert result is None  # Should not block
    
    def test_shield_composition_builder(self):
        """Test ShieldCompositionBuilder functionality."""
        builder = ShieldCompositionBuilder()
        
        shields = (builder
                  .add_validation_shield()
                  .add_auth_shield()
                  .add_rate_limiting_shield()
                  .build())
        
        assert len(shields) == 3
        assert all(isinstance(shield, MockShield) for shield in shields)
        
        # Test specialized builders
        complex_shields = builder.build_complex_composition()
        assert len(complex_shields) > 3
        
        redundant_shields = builder.build_with_redundancy()
        assert len(redundant_shields) > len(shields)
    
    def test_optimization_test_scenarios(self):
        """Test optimization test scenarios."""
        simple = OptimizationTestScenarios.simple_composition()
        assert len(simple) == 3
        
        redundant = OptimizationTestScenarios.redundant_composition()
        assert len(redundant) == 5  # Includes duplicates
        
        bottleneck = OptimizationTestScenarios.performance_bottleneck_composition()
        # Should have at least one slow shield
        slow_shields = [s for s in bottleneck if s.execution_time > 0.1]
        assert len(slow_shields) > 0
    
    @pytest.mark.asyncio
    async def test_performance_test_helper(self):
        """Test performance test helper functionality."""
        shields = OptimizationTestScenarios.simple_composition()
        
        perf_data = await PerformanceTestHelper.measure_composition_performance(
            shields, request_count=10
        )
        
        assert 'total_time' in perf_data
        assert 'requests_per_second' in perf_data
        assert 'shield_stats' in perf_data
        assert len(perf_data['shield_stats']) == len(shields)
    
    def test_optimization_test_validator(self):
        """Test optimization test validator functionality."""
        shields = OptimizationTestScenarios.simple_composition()
        
        # Create mock analysis
        analysis = CompositionAnalysis(
            shields=shields,
            shield_analyses=[
                ShieldAnalysis(shield=shield, shield_type=type(shield).__name__)
                for shield in shields
            ],
            redundancies=[{
                'type': 'capability_duplication',
                'capability': 'test',
                'shields': ['Shield1', 'Shield2']
            }]
        )
        
        # Should not raise exceptions
        OptimizationTestValidator.validate_analysis_completeness(analysis, shields)
        OptimizationTestValidator.validate_redundancy_detection(analysis)
        
        # Test performance metrics validation
        metrics = PerformanceMetrics(execution_time=1.0, total_requests=10)
        OptimizationTestValidator.validate_performance_metrics(metrics)