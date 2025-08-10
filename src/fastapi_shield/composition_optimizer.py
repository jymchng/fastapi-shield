"""Shield Composition Optimizer for FastAPI Shield.

This module provides comprehensive shield composition analysis, optimization,
and performance improvement functionality including static analysis, redundancy
detection, performance profiling integration, and automatic optimization suggestions.
"""

import asyncio
import inspect
import time
import logging
import statistics
from abc import ABC, abstractmethod
from collections import defaultdict, Counter
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple, Type
from functools import wraps

from fastapi import Request, Response
from fastapi_shield.shield import Shield


class OptimizationLevel(str, Enum):
    """Optimization level enumeration."""
    NONE = "none"
    CONSERVATIVE = "conservative"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"
    EXPERIMENTAL = "experimental"


class OptimizationType(str, Enum):
    """Optimization type enumeration."""
    REDUNDANCY_ELIMINATION = "redundancy_elimination"
    REORDERING = "reordering"
    CACHING = "caching"
    PARALLEL_EXECUTION = "parallel_execution"
    CONDITIONAL_EXECUTION = "conditional_execution"
    RESOURCE_POOLING = "resource_pooling"
    EARLY_TERMINATION = "early_termination"
    BATCHING = "batching"


class AnalysisType(str, Enum):
    """Analysis type enumeration."""
    STATIC_ANALYSIS = "static_analysis"
    RUNTIME_ANALYSIS = "runtime_analysis"
    PERFORMANCE_ANALYSIS = "performance_analysis"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    COMPATIBILITY_ANALYSIS = "compatibility_analysis"


@dataclass
class PerformanceMetrics:
    """Performance metrics for shield execution."""
    execution_time: float
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None
    success_count: int = 0
    failure_count: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_requests: int = 0
    average_response_time: float = 0.0
    percentile_95: float = 0.0
    percentile_99: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'execution_time': self.execution_time,
            'memory_usage': self.memory_usage,
            'cpu_usage': self.cpu_usage,
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'total_requests': self.total_requests,
            'average_response_time': self.average_response_time,
            'percentile_95': self.percentile_95,
            'percentile_99': self.percentile_99,
            'metadata': self.metadata
        }


@dataclass
class ShieldAnalysis:
    """Analysis results for a single shield."""
    shield: Shield
    shield_type: str
    dependencies: Set[str] = field(default_factory=set)
    capabilities: Set[str] = field(default_factory=set)
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    performance_characteristics: Dict[str, Any] = field(default_factory=dict)
    optimization_opportunities: List[str] = field(default_factory=list)
    compatibility_info: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CompositionAnalysis:
    """Analysis results for shield composition."""
    shields: List[Shield]
    shield_analyses: List[ShieldAnalysis]
    dependency_graph: Dict[str, Set[str]] = field(default_factory=dict)
    redundancies: List[Dict[str, Any]] = field(default_factory=list)
    bottlenecks: List[Dict[str, Any]] = field(default_factory=list)
    optimization_opportunities: List[Dict[str, Any]] = field(default_factory=list)
    performance_metrics: Optional[PerformanceMetrics] = None
    compatibility_issues: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OptimizationRecommendation:
    """Optimization recommendation."""
    optimization_type: OptimizationType
    description: str
    estimated_improvement: Dict[str, float]
    implementation_complexity: str  # "low", "medium", "high"
    risk_level: str  # "low", "medium", "high"
    applicable_shields: List[str]
    prerequisites: List[str] = field(default_factory=list)
    code_example: Optional[str] = None
    metrics_impact: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'optimization_type': self.optimization_type.value,
            'description': self.description,
            'estimated_improvement': self.estimated_improvement,
            'implementation_complexity': self.implementation_complexity,
            'risk_level': self.risk_level,
            'applicable_shields': self.applicable_shields,
            'prerequisites': self.prerequisites,
            'code_example': self.code_example,
            'metrics_impact': self.metrics_impact,
            'metadata': self.metadata
        }


class ShieldAnalyzer(ABC):
    """Abstract base class for shield analyzers."""
    
    @abstractmethod
    async def analyze(self, shield: Shield) -> ShieldAnalysis:
        """Analyze a shield and return analysis results."""
        pass
    
    @abstractmethod
    def get_analysis_type(self) -> AnalysisType:
        """Get the type of analysis this analyzer performs."""
        pass


class StaticAnalyzer(ShieldAnalyzer):
    """Static analysis of shield properties and characteristics."""
    
    def __init__(self):
        self._logger = logging.getLogger(__name__)
    
    def get_analysis_type(self) -> AnalysisType:
        """Get the analysis type."""
        return AnalysisType.STATIC_ANALYSIS
    
    async def analyze(self, shield: Shield) -> ShieldAnalysis:
        """Perform static analysis of a shield."""
        shield_type = type(shield).__name__
        
        analysis = ShieldAnalysis(
            shield=shield,
            shield_type=shield_type
        )
        
        # Check for explicit capabilities first (for MockShield)
        if hasattr(shield, 'capabilities'):
            analysis.capabilities.update(shield.capabilities)
        
        # Analyze shield function
        if hasattr(shield, '_shield_function'):
            analysis.capabilities.update(self._analyze_shield_function(shield._shield_function))
        
        # Analyze dependencies
        analysis.dependencies.update(self._analyze_dependencies(shield))
        
        # Analyze resource requirements
        analysis.resource_requirements.update(self._analyze_resource_requirements(shield))
        
        # Analyze performance characteristics
        analysis.performance_characteristics.update(self._analyze_performance_characteristics(shield))
        
        # Identify optimization opportunities
        analysis.optimization_opportunities.extend(self._identify_optimization_opportunities(shield))
        
        # Analyze compatibility
        analysis.compatibility_info.update(self._analyze_compatibility(shield))
        
        return analysis
    
    def _analyze_shield_function(self, shield_function: Callable) -> Set[str]:
        """Analyze shield function to identify capabilities."""
        capabilities = set()
        
        try:
            # Get function signature
            sig = inspect.signature(shield_function)
            
            # Analyze parameters
            if 'request' in sig.parameters:
                capabilities.add('request_processing')
            
            # Analyze return type annotations
            return_annotation = sig.return_annotation
            if return_annotation and return_annotation != inspect.Signature.empty:
                if 'Response' in str(return_annotation):
                    capabilities.add('response_generation')
                if 'Optional' in str(return_annotation):
                    capabilities.add('conditional_response')
            
            # Analyze function code (if available)
            if hasattr(shield_function, '__code__'):
                code = shield_function.__code__
                
                # Check for async operations
                if 'await' in str(code.co_names):
                    capabilities.add('async_operations')
                
                # Check for common operations
                names = code.co_names
                if 'cache' in names or 'redis' in names:
                    capabilities.add('caching')
                if 'database' in names or 'db' in names or 'sql' in names:
                    capabilities.add('database_access')
                if 'log' in names or 'logger' in names:
                    capabilities.add('logging')
                if 'rate' in names or 'limit' in names:
                    capabilities.add('rate_limiting')
                if 'auth' in names or 'token' in names:
                    capabilities.add('authentication')
                if 'valid' in names or 'check' in names:
                    capabilities.add('validation')
                if 'encrypt' in names or 'decrypt' in names or 'hash' in names:
                    capabilities.add('cryptography')
        
        except Exception as e:
            self._logger.warning(f"Error analyzing shield function: {e}")
        
        return capabilities
    
    def _analyze_dependencies(self, shield: Shield) -> Set[str]:
        """Analyze shield dependencies."""
        dependencies = set()
        
        # Check if shield is a MockShield with explicit dependencies
        if hasattr(shield, 'dependencies'):
            dependencies.update(shield.dependencies)
        
        # Check for common dependency attributes
        for attr_name in dir(shield):
            if attr_name.startswith('_'):
                continue
            
            try:
                attr = getattr(shield, attr_name)
                attr_type = type(attr).__name__.lower()
                
                if 'redis' in attr_type or 'redis' in attr_name.lower():
                    dependencies.add('redis')
                elif 'database' in attr_type or 'db' in attr_name.lower():
                    dependencies.add('database')
                elif 'cache' in attr_type or 'cache' in attr_name.lower():
                    dependencies.add('cache')
                elif 'client' in attr_type or 'client' in attr_name.lower():
                    dependencies.add('external_service')
                elif 'storage' in attr_type or 'storage' in attr_name.lower():
                    dependencies.add('storage')
                elif 'config' in attr_type or 'config' in attr_name.lower():
                    dependencies.add('configuration')
            
            except Exception:
                continue
        
        return dependencies
    
    def _analyze_resource_requirements(self, shield: Shield) -> Dict[str, Any]:
        """Analyze shield resource requirements."""
        requirements = {
            'memory': 'low',  # Default assumption
            'cpu': 'low',
            'network': 'none',
            'storage': 'none'
        }
        
        # Check if shield is a MockShield with explicit resource requirements
        if hasattr(shield, 'resource_requirements'):
            requirements.update(shield.resource_requirements)
        
        shield_type = type(shield).__name__.lower()
        
        # Adjust based on shield type
        if 'rate' in shield_type or 'throttl' in shield_type:
            requirements['memory'] = 'medium'
            requirements['cpu'] = 'medium'
        
        if 'cache' in shield_type or 'redis' in shield_type:
            requirements['memory'] = 'medium'
            requirements['network'] = 'medium'
            requirements['storage'] = 'medium'
        
        if 'database' in shield_type or 'sql' in shield_type:
            requirements['network'] = 'high'
            requirements['storage'] = 'high'
        
        if 'encrypt' in shield_type or 'crypto' in shield_type:
            requirements['cpu'] = 'high'
        
        if 'log' in shield_type or 'audit' in shield_type:
            requirements['storage'] = 'medium'
        
        return requirements
    
    def _analyze_performance_characteristics(self, shield: Shield) -> Dict[str, Any]:
        """Analyze shield performance characteristics."""
        characteristics = {
            'latency': 'low',
            'throughput': 'high',
            'scalability': 'high',
            'consistency': 'strong'
        }
        
        shield_type = type(shield).__name__.lower()
        
        # Adjust based on shield type and dependencies
        if 'database' in shield_type or 'sql' in shield_type:
            characteristics['latency'] = 'medium'
            characteristics['throughput'] = 'medium'
        
        if 'external' in shield_type or 'api' in shield_type:
            characteristics['latency'] = 'high'
            characteristics['consistency'] = 'eventual'
        
        if 'crypto' in shield_type or 'encrypt' in shield_type:
            characteristics['latency'] = 'medium'
            characteristics['throughput'] = 'medium'
        
        if 'cache' in shield_type or 'redis' in shield_type:
            characteristics['latency'] = 'low'
            characteristics['throughput'] = 'high'
        
        return characteristics
    
    def _identify_optimization_opportunities(self, shield: Shield) -> List[str]:
        """Identify optimization opportunities for a shield."""
        opportunities = []
        
        shield_type = type(shield).__name__.lower()
        
        # Common optimization opportunities
        if hasattr(shield, '_shield_function'):
            opportunities.append('function_caching')
        
        if 'database' in shield_type:
            opportunities.extend(['connection_pooling', 'query_optimization', 'result_caching'])
        
        if 'cache' in shield_type or 'redis' in shield_type:
            opportunities.extend(['pipeline_operations', 'connection_multiplexing'])
        
        if 'rate' in shield_type or 'throttl' in shield_type:
            opportunities.extend(['sliding_window_optimization', 'memory_optimization'])
        
        if 'auth' in shield_type or 'token' in shield_type:
            opportunities.extend(['token_caching', 'batch_validation'])
        
        # Check for async optimization opportunities
        if hasattr(shield, '_shield_function') and asyncio.iscoroutinefunction(shield._shield_function):
            opportunities.append('async_optimization')
        
        return opportunities
    
    def _analyze_compatibility(self, shield: Shield) -> Dict[str, Any]:
        """Analyze shield compatibility characteristics."""
        compatibility = {
            'thread_safe': True,  # Assume true by default
            'async_compatible': True,
            'stateless': True,
            'idempotent': False,
            'cacheable': False,
            'parallel_safe': True
        }
        
        # Check if shield is a MockShield with explicit compatibility info
        if hasattr(shield, 'compatibility_info'):
            compatibility.update(shield.compatibility_info)
        
        # Check for state in shield
        if hasattr(shield, '__dict__') and shield.__dict__:
            for attr_name, attr_value in shield.__dict__.items():
                if not attr_name.startswith('_'):
                    # If shield has non-private attributes, it might have state
                    compatibility['stateless'] = False
                    break
        
        # Check shield function properties
        if hasattr(shield, '_shield_function'):
            func = shield._shield_function
            
            # Check if function is async
            compatibility['async_compatible'] = asyncio.iscoroutinefunction(func)
            
            # Basic heuristics for other properties
            shield_type = type(shield).__name__.lower()
            
            if 'rate' in shield_type or 'throttl' in shield_type:
                compatibility['stateless'] = False
                compatibility['idempotent'] = False
            
            if 'cache' in shield_type:
                compatibility['cacheable'] = True
                compatibility['idempotent'] = True
            
            if 'auth' in shield_type:
                compatibility['cacheable'] = True
                compatibility['idempotent'] = True
            
            if 'log' in shield_type or 'audit' in shield_type:
                compatibility['idempotent'] = False
        
        return compatibility


class PerformanceAnalyzer(ShieldAnalyzer):
    """Performance analysis of shield execution."""
    
    def __init__(self):
        self._logger = logging.getLogger(__name__)
        self._performance_cache = {}
    
    def get_analysis_type(self) -> AnalysisType:
        """Get the analysis type."""
        return AnalysisType.PERFORMANCE_ANALYSIS
    
    async def analyze(self, shield: Shield) -> ShieldAnalysis:
        """Perform performance analysis of a shield."""
        shield_type = type(shield).__name__
        
        analysis = ShieldAnalysis(
            shield=shield,
            shield_type=shield_type
        )
        
        # Perform performance profiling
        try:
            performance_metrics = await self._profile_shield_performance(shield)
            if performance_metrics:
                analysis.performance_characteristics.update(performance_metrics)
                
                # Identify performance-based optimization opportunities
                analysis.optimization_opportunities.extend(
                    self._identify_performance_optimizations(performance_metrics)
                )
            else:
                # No metrics returned, use fallback
                raise ValueError("No performance metrics returned")
        
        except Exception as e:
            self._logger.warning(f"Performance analysis failed, using fallback: {e}")
            # Provide basic fallback characteristics
            fallback_metrics = {
                'avg_execution_time': 0.01,
                'estimated_memory_usage': 'low',
                'estimated_cpu_intensity': 'low'
            }
            analysis.performance_characteristics.update(fallback_metrics)
            analysis.metadata['performance_analysis_error'] = str(e)
            
            # Still try to identify optimization opportunities from fallback
            analysis.optimization_opportunities.extend(
                self._identify_performance_optimizations(fallback_metrics)
            )
        
        return analysis
    
    async def _profile_shield_performance(self, shield: Shield) -> Dict[str, Any]:
        """Profile shield performance characteristics."""
        metrics = {}
        
        if not hasattr(shield, '_shield_function'):
            return metrics
        
        # Create a mock request for testing
        mock_request = self._create_mock_request()
        
        # Profile execution time
        execution_times = []
        
        for _ in range(10):  # Run multiple times for accuracy
            start_time = time.perf_counter()
            
            try:
                result = await shield._shield_function(mock_request)
                end_time = time.perf_counter()
                execution_times.append(end_time - start_time)
            
            except Exception as e:
                # Shield might reject the mock request, which is normal
                end_time = time.perf_counter()
                execution_times.append(end_time - start_time)
                break
        
        if execution_times:
            metrics['avg_execution_time'] = statistics.mean(execution_times)
            metrics['min_execution_time'] = min(execution_times)
            metrics['max_execution_time'] = max(execution_times)
            
            if len(execution_times) > 1:
                metrics['execution_time_std'] = statistics.stdev(execution_times)
        
        # Estimate memory usage (basic heuristic)
        metrics['estimated_memory_usage'] = self._estimate_memory_usage(shield)
        
        # Estimate CPU intensity
        metrics['estimated_cpu_intensity'] = self._estimate_cpu_intensity(shield)
        
        return metrics
    
    def _create_mock_request(self):
        """Create a mock request for performance testing."""
        from unittest.mock import Mock
        
        mock_request = Mock()
        mock_request.method = "GET"
        mock_request.url = Mock()
        mock_request.url.path = "/test"
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.client = Mock()
        mock_request.client.host = "127.0.0.1"
        mock_request.state = Mock()
        
        return mock_request
    
    def _estimate_memory_usage(self, shield: Shield) -> str:
        """Estimate memory usage of a shield."""
        shield_type = type(shield).__name__.lower()
        
        if 'cache' in shield_type or 'redis' in shield_type:
            return 'medium'
        elif 'database' in shield_type or 'storage' in shield_type:
            return 'low'
        elif 'rate' in shield_type or 'throttl' in shield_type:
            return 'medium'
        else:
            return 'low'
    
    def _estimate_cpu_intensity(self, shield: Shield) -> str:
        """Estimate CPU intensity of a shield."""
        shield_type = type(shield).__name__.lower()
        
        if 'crypto' in shield_type or 'encrypt' in shield_type or 'hash' in shield_type:
            return 'high'
        elif 'valid' in shield_type or 'check' in shield_type:
            return 'medium'
        elif 'log' in shield_type or 'audit' in shield_type:
            return 'low'
        else:
            return 'low'
    
    def _identify_performance_optimizations(self, metrics: Dict[str, Any]) -> List[str]:
        """Identify performance optimization opportunities."""
        opportunities = []
        
        avg_time = metrics.get('avg_execution_time', 0)
        
        if avg_time > 0.1:  # 100ms
            opportunities.append('execution_time_optimization')
        
        if avg_time > 0.01:  # 10ms
            opportunities.append('caching_consideration')
        
        if metrics.get('execution_time_std', 0) > avg_time * 0.5:
            opportunities.append('consistency_improvement')
        
        if metrics.get('estimated_memory_usage') == 'high':
            opportunities.append('memory_optimization')
        
        if metrics.get('estimated_cpu_intensity') == 'high':
            opportunities.append('cpu_optimization')
        
        return opportunities


class DependencyAnalyzer(ShieldAnalyzer):
    """Dependency analysis for shield interactions."""
    
    def __init__(self):
        self._logger = logging.getLogger(__name__)
    
    def get_analysis_type(self) -> AnalysisType:
        """Get the analysis type."""
        return AnalysisType.DEPENDENCY_ANALYSIS
    
    async def analyze(self, shield: Shield) -> ShieldAnalysis:
        """Perform dependency analysis of a shield."""
        shield_type = type(shield).__name__
        
        analysis = ShieldAnalysis(
            shield=shield,
            shield_type=shield_type
        )
        
        # Analyze dependencies
        analysis.dependencies.update(self._analyze_shield_dependencies(shield))
        
        # Analyze capabilities that other shields might depend on
        analysis.capabilities.update(self._analyze_shield_capabilities(shield))
        
        # Analyze resource sharing opportunities
        analysis.optimization_opportunities.extend(
            self._identify_resource_sharing_opportunities(shield)
        )
        
        return analysis
    
    def _analyze_shield_dependencies(self, shield: Shield) -> Set[str]:
        """Analyze what this shield depends on."""
        dependencies = set()
        
        # Check shield attributes for dependencies
        for attr_name in dir(shield):
            if attr_name.startswith('_'):
                continue
            
            try:
                attr = getattr(shield, attr_name)
                
                # Check for common dependency patterns
                if hasattr(attr, 'connect') or hasattr(attr, 'connection'):
                    if 'redis' in str(type(attr)).lower():
                        dependencies.add('redis')
                    elif 'database' in str(type(attr)).lower() or 'sql' in str(type(attr)).lower():
                        dependencies.add('database')
                    else:
                        dependencies.add('external_connection')
                
                if hasattr(attr, 'cache') or 'cache' in attr_name.lower():
                    dependencies.add('cache')
                
                if hasattr(attr, 'storage') or 'storage' in attr_name.lower():
                    dependencies.add('storage')
                
                if hasattr(attr, 'config') or 'config' in attr_name.lower():
                    dependencies.add('configuration')
            
            except Exception:
                continue
        
        return dependencies
    
    def _analyze_shield_capabilities(self, shield: Shield) -> Set[str]:
        """Analyze what capabilities this shield provides."""
        capabilities = set()
        
        # Check if shield is a MockShield with explicit capabilities
        if hasattr(shield, 'capabilities'):
            capabilities.update(shield.capabilities)
        
        shield_type = type(shield).__name__.lower()
        
        # Infer capabilities from shield type
        if 'rate' in shield_type or 'throttl' in shield_type:
            capabilities.update(['rate_limiting', 'request_control'])
        
        if 'auth' in shield_type or 'token' in shield_type:
            capabilities.update(['authentication', 'authorization'])
        
        if 'cache' in shield_type:
            capabilities.update(['caching', 'response_optimization'])
        
        if 'valid' in shield_type or 'check' in shield_type:
            capabilities.update(['validation', 'input_checking'])
        
        if 'log' in shield_type or 'audit' in shield_type:
            capabilities.update(['logging', 'auditing'])
        
        if 'cors' in shield_type:
            capabilities.update(['cross_origin_support'])
        
        if 'security' in shield_type or 'protect' in shield_type:
            capabilities.update(['security_enforcement'])
        
        return capabilities
    
    def _identify_resource_sharing_opportunities(self, shield: Shield) -> List[str]:
        """Identify opportunities for resource sharing."""
        opportunities = []
        
        shield_type = type(shield).__name__.lower()
        
        if 'database' in shield_type or 'sql' in shield_type:
            opportunities.append('database_connection_pooling')
        
        if 'redis' in shield_type or 'cache' in shield_type:
            opportunities.append('cache_connection_sharing')
        
        if 'http' in shield_type or 'client' in shield_type:
            opportunities.append('http_client_pooling')
        
        if 'config' in shield_type:
            opportunities.append('configuration_sharing')
        
        return opportunities


class OptimizationEngine:
    """Engine for generating optimization recommendations."""
    
    def __init__(self, optimization_level: OptimizationLevel = OptimizationLevel.MODERATE):
        self.optimization_level = optimization_level
        self._logger = logging.getLogger(__name__)
    
    def generate_recommendations(self, analysis: CompositionAnalysis) -> List[OptimizationRecommendation]:
        """Generate optimization recommendations based on analysis."""
        recommendations = []
        
        # Generate recommendations based on analysis
        recommendations.extend(self._generate_redundancy_recommendations(analysis))
        recommendations.extend(self._generate_reordering_recommendations(analysis))
        recommendations.extend(self._generate_caching_recommendations(analysis))
        recommendations.extend(self._generate_parallel_execution_recommendations(analysis))
        recommendations.extend(self._generate_resource_pooling_recommendations(analysis))
        
        # Filter recommendations based on optimization level
        filtered_recommendations = self._filter_by_optimization_level(recommendations)
        
        # Sort by estimated improvement
        filtered_recommendations.sort(
            key=lambda r: sum(r.estimated_improvement.values()), 
            reverse=True
        )
        
        return filtered_recommendations
    
    def _generate_redundancy_recommendations(self, analysis: CompositionAnalysis) -> List[OptimizationRecommendation]:
        """Generate recommendations for redundancy elimination."""
        recommendations = []
        
        for redundancy in analysis.redundancies:
            recommendation = OptimizationRecommendation(
                optimization_type=OptimizationType.REDUNDANCY_ELIMINATION,
                description=f"Eliminate redundant {redundancy.get('type', 'operation')} between shields",
                estimated_improvement={
                    'execution_time': redundancy.get('time_savings', 0.1),
                    'memory_usage': redundancy.get('memory_savings', 0.05)
                },
                implementation_complexity="low",
                risk_level="low",
                applicable_shields=redundancy.get('shields', []),
                code_example=self._generate_redundancy_elimination_code(redundancy)
            )
            recommendations.append(recommendation)
        
        return recommendations
    
    def _generate_reordering_recommendations(self, analysis: CompositionAnalysis) -> List[OptimizationRecommendation]:
        """Generate recommendations for shield reordering."""
        recommendations = []
        
        # Analyze shield order for optimization opportunities
        for i, shield_analysis in enumerate(analysis.shield_analyses):
            performance_chars = shield_analysis.performance_characteristics
            
            # Recommend moving fast shields earlier
            if performance_chars.get('latency') == 'low' and i > 0:
                recommendation = OptimizationRecommendation(
                    optimization_type=OptimizationType.REORDERING,
                    description=f"Move low-latency shield '{shield_analysis.shield_type}' earlier in chain",
                    estimated_improvement={
                        'execution_time': 0.15,
                        'user_experience': 0.2
                    },
                    implementation_complexity="low",
                    risk_level="low",
                    applicable_shields=[shield_analysis.shield_type],
                    code_example="# Move shield to earlier position in composition chain"
                )
                recommendations.append(recommendation)
        
        return recommendations
    
    def _generate_caching_recommendations(self, analysis: CompositionAnalysis) -> List[OptimizationRecommendation]:
        """Generate recommendations for caching optimizations."""
        recommendations = []
        
        for shield_analysis in analysis.shield_analyses:
            if shield_analysis.compatibility_info.get('cacheable', False):
                recommendation = OptimizationRecommendation(
                    optimization_type=OptimizationType.CACHING,
                    description=f"Add result caching for '{shield_analysis.shield_type}'",
                    estimated_improvement={
                        'execution_time': 0.3,
                        'throughput': 0.25
                    },
                    implementation_complexity="medium",
                    risk_level="low",
                    applicable_shields=[shield_analysis.shield_type],
                    code_example=self._generate_caching_code_example()
                )
                recommendations.append(recommendation)
        
        return recommendations
    
    def _generate_parallel_execution_recommendations(self, analysis: CompositionAnalysis) -> List[OptimizationRecommendation]:
        """Generate recommendations for parallel execution."""
        recommendations = []
        
        # Find independent shields that can run in parallel
        independent_groups = self._find_independent_shield_groups(analysis)
        
        for group in independent_groups:
            if len(group) > 1:
                recommendation = OptimizationRecommendation(
                    optimization_type=OptimizationType.PARALLEL_EXECUTION,
                    description=f"Execute independent shields in parallel: {', '.join(group)}",
                    estimated_improvement={
                        'execution_time': 0.4,
                        'throughput': 0.35
                    },
                    implementation_complexity="medium",
                    risk_level="medium",
                    applicable_shields=group,
                    code_example=self._generate_parallel_execution_code()
                )
                recommendations.append(recommendation)
        
        # Also check the analysis opportunities directly
        for opportunity in analysis.optimization_opportunities:
            if opportunity.get('type') == 'parallel_execution':
                # Extract shield names from the opportunity description
                description = opportunity.get('description', '')
                
                recommendation = OptimizationRecommendation(
                    optimization_type=OptimizationType.PARALLEL_EXECUTION,
                    description=description,
                    estimated_improvement={
                        'execution_time': opportunity.get('potential_improvement', 0.3),
                        'throughput': opportunity.get('potential_improvement', 0.3) * 0.8
                    },
                    implementation_complexity="medium",
                    risk_level="medium",
                    applicable_shields=[sa.shield_type for sa in analysis.shield_analyses],
                    code_example=self._generate_parallel_execution_code()
                )
                recommendations.append(recommendation)
        
        return recommendations
    
    def _generate_resource_pooling_recommendations(self, analysis: CompositionAnalysis) -> List[OptimizationRecommendation]:
        """Generate recommendations for resource pooling."""
        recommendations = []
        
        # Group shields by resource requirements
        resource_groups = defaultdict(list)
        
        for shield_analysis in analysis.shield_analyses:
            for dep in shield_analysis.dependencies:
                resource_groups[dep].append(shield_analysis.shield_type)
        
        for resource, shields in resource_groups.items():
            if len(shields) > 1:
                recommendation = OptimizationRecommendation(
                    optimization_type=OptimizationType.RESOURCE_POOLING,
                    description=f"Share {resource} resources between shields: {', '.join(shields)}",
                    estimated_improvement={
                        'resource_usage': 0.25,
                        'initialization_time': 0.3
                    },
                    implementation_complexity="high",
                    risk_level="medium",
                    applicable_shields=shields,
                    code_example=self._generate_resource_pooling_code(resource)
                )
                recommendations.append(recommendation)
        
        return recommendations
    
    def _filter_by_optimization_level(self, recommendations: List[OptimizationRecommendation]) -> List[OptimizationRecommendation]:
        """Filter recommendations based on optimization level."""
        if self.optimization_level == OptimizationLevel.NONE:
            return []
        
        filtered = []
        
        for rec in recommendations:
            if self.optimization_level == OptimizationLevel.CONSERVATIVE:
                if rec.risk_level == "low" and rec.implementation_complexity in ["low", "medium"]:
                    filtered.append(rec)
            
            elif self.optimization_level == OptimizationLevel.MODERATE:
                if rec.risk_level in ["low", "medium"]:
                    filtered.append(rec)
            
            elif self.optimization_level == OptimizationLevel.AGGRESSIVE:
                if rec.risk_level in ["low", "medium", "high"]:
                    filtered.append(rec)
            
            elif self.optimization_level == OptimizationLevel.EXPERIMENTAL:
                filtered.append(rec)  # Include all recommendations
        
        return filtered
    
    def _find_independent_shield_groups(self, analysis: CompositionAnalysis) -> List[List[str]]:
        """Find groups of shields that can execute independently."""
        independent_groups = []
        
        # Simple heuristic: shields with no shared dependencies can run in parallel
        shield_deps = {}
        
        for shield_analysis in analysis.shield_analyses:
            shield_deps[shield_analysis.shield_type] = shield_analysis.dependencies
        
        # If shields have no dependencies, they can all run in parallel
        shields_with_no_deps = [
            shield_type for shield_type, deps in shield_deps.items() 
            if not deps
        ]
        
        if len(shields_with_no_deps) > 1:
            independent_groups.append(shields_with_no_deps)
        
        # Find shields with no overlapping dependencies
        processed = set(shields_with_no_deps)
        
        for shield_type, deps in shield_deps.items():
            if shield_type in processed or not deps:
                continue
            
            group = [shield_type]
            processed.add(shield_type)
            
            # Find other shields that don't conflict
            for other_shield, other_deps in shield_deps.items():
                if other_shield in processed:
                    continue
                
                # Check if dependencies overlap
                if not deps.intersection(other_deps):
                    group.append(other_shield)
                    processed.add(other_shield)
            
            if len(group) > 1:
                independent_groups.append(group)
        
        return independent_groups
    
    def _generate_redundancy_elimination_code(self, redundancy: Dict[str, Any]) -> str:
        """Generate code example for redundancy elimination."""
        return f"""
# Eliminate redundant {redundancy.get('type', 'operation')}
# Consider combining shields or using shared resources
from fastapi_shield.composition import ShieldComposition

# Before: Redundant operations
composition = ShieldComposition([shield1, shield2, shield3])

# After: Optimized composition
optimized_composition = composition.eliminate_redundancy()
"""
    
    def _generate_caching_code_example(self) -> str:
        """Generate code example for caching optimization."""
        return """
# Add result caching to improve performance
from fastapi_shield.composition import CachedShieldWrapper

# Wrap shield with caching layer
cached_shield = CachedShieldWrapper(
    shield=original_shield,
    cache_ttl=300,  # 5 minutes
    cache_key_generator=lambda request: f"shield:{request.url.path}"
)
"""
    
    def _generate_parallel_execution_code(self) -> str:
        """Generate code example for parallel execution."""
        return """
# Execute independent shields in parallel
import asyncio
from fastapi_shield.composition import ParallelShieldGroup

# Group independent shields for parallel execution
parallel_group = ParallelShieldGroup([shield1, shield2, shield3])

async def execute_parallel(request):
    # Execute all shields concurrently
    results = await parallel_group.execute_all(request)
    return results
"""
    
    def _generate_resource_pooling_code(self, resource: str) -> str:
        """Generate code example for resource pooling."""
        return f"""
# Share {resource} resources between shields
from fastapi_shield.composition import ResourcePool

# Create shared resource pool
{resource}_pool = ResourcePool(
    resource_type="{resource}",
    max_size=10,
    min_size=2
)

# Configure shields to use shared pool
shield1.configure_resource_pool({resource}_pool)
shield2.configure_resource_pool({resource}_pool)
"""


class ShieldCompositionOptimizer:
    """Main optimizer for shield compositions."""
    
    def __init__(
        self,
        optimization_level: OptimizationLevel = OptimizationLevel.MODERATE,
        analyzers: Optional[List[ShieldAnalyzer]] = None
    ):
        self.optimization_level = optimization_level
        self.analyzers = analyzers or [
            StaticAnalyzer(),
            PerformanceAnalyzer(),
            DependencyAnalyzer()
        ]
        self.optimization_engine = OptimizationEngine(optimization_level)
        self._logger = logging.getLogger(__name__)
        self._analysis_cache = {}
    
    async def analyze_composition(
        self, 
        shields: List[Shield],
        include_performance: bool = True
    ) -> CompositionAnalysis:
        """Analyze a shield composition for optimization opportunities."""
        composition_key = self._generate_composition_key(shields)
        
        # Check cache
        if composition_key in self._analysis_cache:
            self._logger.debug("Returning cached composition analysis")
            return self._analysis_cache[composition_key]
        
        # Perform individual shield analyses
        shield_analyses = []
        
        for shield in shields:
            shield_analysis = await self._analyze_single_shield(shield)
            shield_analyses.append(shield_analysis)
        
        # Create composition analysis
        composition_analysis = CompositionAnalysis(
            shields=shields,
            shield_analyses=shield_analyses
        )
        
        # Analyze composition-level properties
        self._analyze_dependencies(composition_analysis)
        self._detect_redundancies(composition_analysis)
        self._identify_bottlenecks(composition_analysis)
        self._check_compatibility(composition_analysis)
        
        # Perform performance analysis if requested
        if include_performance:
            composition_analysis.performance_metrics = await self._analyze_composition_performance(shields)
        
        # Generate optimization opportunities
        composition_analysis.optimization_opportunities = self._identify_composition_optimizations(composition_analysis)
        
        # Cache the result
        self._analysis_cache[composition_key] = composition_analysis
        
        return composition_analysis
    
    async def optimize_composition(
        self,
        shields: List[Shield],
        auto_apply: bool = False
    ) -> Tuple[List[OptimizationRecommendation], Optional[List[Shield]]]:
        """Optimize a shield composition and return recommendations."""
        # Analyze the composition
        analysis = await self.analyze_composition(shields)
        
        # Generate optimization recommendations
        recommendations = self.optimization_engine.generate_recommendations(analysis)
        
        optimized_shields = None
        
        if auto_apply and recommendations:
            # Apply safe optimizations automatically
            optimized_shields = await self._apply_safe_optimizations(shields, recommendations)
        
        return recommendations, optimized_shields
    
    async def benchmark_composition(
        self,
        shields: List[Shield],
        request_count: int = 100
    ) -> PerformanceMetrics:
        """Benchmark a shield composition performance."""
        from unittest.mock import Mock
        
        # Create mock requests
        requests = []
        for i in range(request_count):
            mock_request = Mock()
            mock_request.method = "GET"
            mock_request.url = Mock()
            mock_request.url.path = f"/test/{i}"
            mock_request.headers = {"User-Agent": "test"}
            mock_request.query_params = {"id": str(i)}
            mock_request.client = Mock()
            mock_request.client.host = "127.0.0.1"
            mock_request.state = Mock()
            requests.append(mock_request)
        
        # Measure performance
        start_time = time.perf_counter()
        response_times = []
        success_count = 0
        failure_count = 0
        
        for request in requests:
            request_start = time.perf_counter()
            
            try:
                # Execute shield chain
                blocked = False
                for shield in shields:
                    if hasattr(shield, '_shield_function'):
                        result = await shield._shield_function(request)
                        if result is not None:  # Request was blocked
                            blocked = True
                            break
                
                success_count += 1
                
            except Exception as e:
                failure_count += 1
                self._logger.warning(f"Shield execution failed: {e}")
            
            request_end = time.perf_counter()
            response_times.append(request_end - request_start)
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        # Calculate metrics
        avg_response_time = statistics.mean(response_times) if response_times else 0
        percentile_95 = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else avg_response_time
        percentile_99 = statistics.quantiles(response_times, n=100)[98] if len(response_times) >= 100 else avg_response_time
        
        return PerformanceMetrics(
            execution_time=total_time,
            success_count=success_count,
            failure_count=failure_count,
            total_requests=request_count,
            average_response_time=avg_response_time,
            percentile_95=percentile_95,
            percentile_99=percentile_99,
            metadata={
                'requests_per_second': request_count / total_time if total_time > 0 else 0,
                'shield_count': len(shields)
            }
        )
    
    async def _analyze_single_shield(self, shield: Shield) -> ShieldAnalysis:
        """Analyze a single shield using all analyzers."""
        combined_analysis = ShieldAnalysis(
            shield=shield,
            shield_type=type(shield).__name__
        )
        
        for analyzer in self.analyzers:
            try:
                analysis = await analyzer.analyze(shield)
                
                # Merge results
                combined_analysis.dependencies.update(analysis.dependencies)
                combined_analysis.capabilities.update(analysis.capabilities)
                combined_analysis.resource_requirements.update(analysis.resource_requirements)
                combined_analysis.performance_characteristics.update(analysis.performance_characteristics)
                combined_analysis.optimization_opportunities.extend(analysis.optimization_opportunities)
                combined_analysis.compatibility_info.update(analysis.compatibility_info)
                combined_analysis.metadata[analyzer.get_analysis_type().value] = analysis.metadata
                
            except Exception as e:
                self._logger.error(f"Error in {type(analyzer).__name__}: {e}")
        
        return combined_analysis
    
    def _generate_composition_key(self, shields: List[Shield]) -> str:
        """Generate a cache key for a shield composition."""
        shield_types = [type(shield).__name__ for shield in shields]
        return "|".join(shield_types)
    
    def _analyze_dependencies(self, analysis: CompositionAnalysis):
        """Analyze dependencies across the composition."""
        dependency_graph = defaultdict(set)
        
        for shield_analysis in analysis.shield_analyses:
            shield_name = shield_analysis.shield_type
            
            # Add dependencies
            for dep in shield_analysis.dependencies:
                dependency_graph[shield_name].add(dep)
            
            # Check for capability dependencies between shields
            for other_analysis in analysis.shield_analyses:
                if shield_analysis == other_analysis:
                    continue
                
                other_name = other_analysis.shield_type
                
                # If this shield's dependencies match other shield's capabilities
                if shield_analysis.dependencies.intersection(other_analysis.capabilities):
                    dependency_graph[shield_name].add(other_name)
        
        analysis.dependency_graph = dict(dependency_graph)
    
    def _detect_redundancies(self, analysis: CompositionAnalysis):
        """Detect redundant operations in the composition."""
        redundancies = []
        
        # Check for duplicate capabilities
        capability_map = defaultdict(list)
        
        for shield_analysis in analysis.shield_analyses:
            for capability in shield_analysis.capabilities:
                capability_map[capability].append(shield_analysis.shield_type)
        
        for capability, shields in capability_map.items():
            if len(shields) > 1:
                redundancy = {
                    'type': 'capability_duplication',
                    'capability': capability,
                    'shields': shields,
                    'time_savings': 0.1 * (len(shields) - 1),  # Estimated
                    'memory_savings': 0.05 * (len(shields) - 1)
                }
                redundancies.append(redundancy)
        
        # Check for duplicate resource requirements
        resource_map = defaultdict(list)
        
        for shield_analysis in analysis.shield_analyses:
            for resource in shield_analysis.dependencies:
                resource_map[resource].append(shield_analysis.shield_type)
        
        for resource, shields in resource_map.items():
            if len(shields) > 1:
                redundancy = {
                    'type': 'resource_duplication',
                    'resource': resource,
                    'shields': shields,
                    'time_savings': 0.05 * (len(shields) - 1),
                    'memory_savings': 0.1 * (len(shields) - 1)
                }
                redundancies.append(redundancy)
        
        analysis.redundancies = redundancies
    
    def _identify_bottlenecks(self, analysis: CompositionAnalysis):
        """Identify potential bottlenecks in the composition."""
        bottlenecks = []
        
        for shield_analysis in analysis.shield_analyses:
            performance_chars = shield_analysis.performance_characteristics
            
            # High latency shields are potential bottlenecks
            if performance_chars.get('latency') == 'high':
                bottleneck = {
                    'type': 'high_latency',
                    'shield': shield_analysis.shield_type,
                    'estimated_impact': 0.3,
                    'mitigation': 'Consider caching or async execution'
                }
                bottlenecks.append(bottleneck)
            
            # Low throughput shields
            if performance_chars.get('throughput') == 'low':
                bottleneck = {
                    'type': 'low_throughput',
                    'shield': shield_analysis.shield_type,
                    'estimated_impact': 0.25,
                    'mitigation': 'Consider parallel execution or optimization'
                }
                bottlenecks.append(bottleneck)
            
            # Check for high execution time from performance analysis
            avg_exec_time = performance_chars.get('avg_execution_time', 0)
            if avg_exec_time > 0.1:  # 100ms threshold
                bottleneck = {
                    'type': 'high_execution_time',
                    'shield': shield_analysis.shield_type,
                    'estimated_impact': 0.4,
                    'execution_time': avg_exec_time,
                    'mitigation': 'Optimize execution or consider async processing'
                }
                bottlenecks.append(bottleneck)
            
            # Check MockShield execution time
            if hasattr(shield_analysis.shield, 'execution_time') and shield_analysis.shield.execution_time > 0.1:
                bottleneck = {
                    'type': 'configured_high_latency',
                    'shield': shield_analysis.shield_type,
                    'estimated_impact': 0.4,
                    'execution_time': shield_analysis.shield.execution_time,
                    'mitigation': 'Optimize shield configuration or implementation'
                }
                bottlenecks.append(bottleneck)
        
        analysis.bottlenecks = bottlenecks
    
    def _check_compatibility(self, analysis: CompositionAnalysis):
        """Check for compatibility issues in the composition."""
        compatibility_issues = []
        
        # Check for async/sync compatibility
        async_shields = []
        sync_shields = []
        
        for shield_analysis in analysis.shield_analyses:
            if shield_analysis.compatibility_info.get('async_compatible', True):
                async_shields.append(shield_analysis.shield_type)
            else:
                sync_shields.append(shield_analysis.shield_type)
        
        if async_shields and sync_shields:
            issue = {
                'type': 'async_sync_mix',
                'async_shields': async_shields,
                'sync_shields': sync_shields,
                'severity': 'medium',
                'recommendation': 'Consider making all shields async for better performance'
            }
            compatibility_issues.append(issue)
        
        # Check for thread safety issues
        thread_unsafe_shields = []
        
        for shield_analysis in analysis.shield_analyses:
            if not shield_analysis.compatibility_info.get('thread_safe', True):
                thread_unsafe_shields.append(shield_analysis.shield_type)
        
        if thread_unsafe_shields:
            issue = {
                'type': 'thread_safety',
                'shields': thread_unsafe_shields,
                'severity': 'high',
                'recommendation': 'Ensure proper synchronization or avoid concurrent execution'
            }
            compatibility_issues.append(issue)
        
        analysis.compatibility_issues = compatibility_issues
    
    def _identify_composition_optimizations(self, analysis: CompositionAnalysis) -> List[Dict[str, Any]]:
        """Identify optimization opportunities at the composition level."""
        opportunities = []
        
        # Reordering opportunities
        if len(analysis.shields) > 1:
            opportunities.append({
                'type': 'reordering',
                'description': 'Reorder shields for optimal execution sequence',
                'potential_improvement': 0.15
            })
        
        # Parallel execution opportunities
        independent_shields = self._find_independent_shields(analysis)
        if len(independent_shields) > 1:
            opportunities.append({
                'type': 'parallel_execution',
                'description': f'Execute {len(independent_shields)} independent shields in parallel',
                'potential_improvement': 0.3
            })
        
        # Caching opportunities
        cacheable_shields = [
            sa.shield_type for sa in analysis.shield_analyses 
            if sa.compatibility_info.get('cacheable', False)
        ]
        
        if cacheable_shields:
            opportunities.append({
                'type': 'caching',
                'description': f'Add caching for {len(cacheable_shields)} cacheable shields',
                'potential_improvement': 0.25
            })
        
        return opportunities
    
    def _find_independent_shields(self, analysis: CompositionAnalysis) -> List[str]:
        """Find shields that have no dependencies on each other."""
        independent = []
        
        for shield_analysis in analysis.shield_analyses:
            is_independent = True
            
            # Shields with no dependencies are independent
            if not shield_analysis.dependencies:
                independent.append(shield_analysis.shield_type)
                continue
            
            # Check if this shield depends on others in the composition
            for other_analysis in analysis.shield_analyses:
                if shield_analysis == other_analysis:
                    continue
                
                # If this shield's dependencies intersect with other shield's capabilities
                if shield_analysis.dependencies.intersection(other_analysis.capabilities):
                    is_independent = False
                    break
            
            if is_independent:
                independent.append(shield_analysis.shield_type)
        
        return independent
    
    async def _analyze_composition_performance(self, shields: List[Shield]) -> PerformanceMetrics:
        """Analyze performance of the entire composition."""
        return await self.benchmark_composition(shields, request_count=50)
    
    async def _apply_safe_optimizations(
        self,
        shields: List[Shield],
        recommendations: List[OptimizationRecommendation]
    ) -> List[Shield]:
        """Apply safe optimizations automatically."""
        optimized_shields = shields.copy()
        
        for recommendation in recommendations:
            if (recommendation.risk_level == "low" and 
                recommendation.implementation_complexity in ["low", "medium"]):
                
                # Apply optimization based on type
                if recommendation.optimization_type == OptimizationType.REORDERING:
                    optimized_shields = self._apply_reordering_optimization(
                        optimized_shields, recommendation
                    )
                
                # Other optimizations would require more complex implementation
                # and are left for manual application
        
        return optimized_shields
    
    def _apply_reordering_optimization(
        self,
        shields: List[Shield],
        recommendation: OptimizationRecommendation
    ) -> List[Shield]:
        """Apply shield reordering optimization."""
        # Simple reordering: move low-latency shields to the front
        shield_map = {type(shield).__name__: shield for shield in shields}
        optimized_order = []
        remaining_shields = shields.copy()
        
        # Move applicable shields to front
        for shield_type in recommendation.applicable_shields:
            if shield_type in shield_map:
                shield = shield_map[shield_type]
                if shield in remaining_shields:
                    optimized_order.append(shield)
                    remaining_shields.remove(shield)
        
        # Add remaining shields
        optimized_order.extend(remaining_shields)
        
        return optimized_order
    
    def clear_cache(self):
        """Clear the analysis cache."""
        self._analysis_cache.clear()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'cache_size': len(self._analysis_cache),
            'cache_keys': list(self._analysis_cache.keys())
        }


# Convenience functions for creating optimizers

def create_basic_optimizer(
    optimization_level: OptimizationLevel = OptimizationLevel.MODERATE
) -> ShieldCompositionOptimizer:
    """Create a basic shield composition optimizer.
    
    Args:
        optimization_level: Level of optimization to apply
    
    Returns:
        ShieldCompositionOptimizer instance
    """
    return ShieldCompositionOptimizer(optimization_level=optimization_level)


def create_performance_focused_optimizer() -> ShieldCompositionOptimizer:
    """Create an optimizer focused on performance analysis.
    
    Returns:
        ShieldCompositionOptimizer instance with performance focus
    """
    analyzers = [
        StaticAnalyzer(),
        PerformanceAnalyzer(),
        DependencyAnalyzer()
    ]
    
    return ShieldCompositionOptimizer(
        optimization_level=OptimizationLevel.AGGRESSIVE,
        analyzers=analyzers
    )


def create_conservative_optimizer() -> ShieldCompositionOptimizer:
    """Create a conservative optimizer for production use.
    
    Returns:
        ShieldCompositionOptimizer instance with conservative settings
    """
    analyzers = [StaticAnalyzer()]  # Only static analysis for safety
    
    return ShieldCompositionOptimizer(
        optimization_level=OptimizationLevel.CONSERVATIVE,
        analyzers=analyzers
    )


def analyze_shield_composition(
    shields: List[Shield],
    optimization_level: OptimizationLevel = OptimizationLevel.MODERATE
) -> Tuple[CompositionAnalysis, List[OptimizationRecommendation]]:
    """Analyze a shield composition and return analysis with recommendations.
    
    Args:
        shields: List of shields to analyze
        optimization_level: Level of optimization to apply
    
    Returns:
        Tuple of (CompositionAnalysis, List[OptimizationRecommendation])
    """
    import asyncio
    
    async def _analyze():
        optimizer = ShieldCompositionOptimizer(optimization_level=optimization_level)
        analysis = await optimizer.analyze_composition(shields)
        recommendations = optimizer.optimization_engine.generate_recommendations(analysis)
        return analysis, recommendations
    
    return asyncio.run(_analyze())


def benchmark_shields(
    shields: List[Shield],
    request_count: int = 100
) -> PerformanceMetrics:
    """Benchmark shield composition performance.
    
    Args:
        shields: List of shields to benchmark
        request_count: Number of test requests to use
    
    Returns:
        PerformanceMetrics with benchmark results
    """
    import asyncio
    
    async def _benchmark():
        optimizer = ShieldCompositionOptimizer()
        return await optimizer.benchmark_composition(shields, request_count)
    
    return asyncio.run(_benchmark())