"""Mock classes and utilities for composition optimizer testing."""

import asyncio
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Callable
from unittest.mock import Mock, AsyncMock

from fastapi_shield.shield import Shield
from fastapi_shield.composition_optimizer import (
    ShieldAnalysis,
    PerformanceMetrics,
    OptimizationType,
    AnalysisType,
    OptimizationRecommendation,
    ShieldAnalyzer,
)


class MockShield(Shield):
    """Mock shield for testing optimization."""
    
    def __init__(
        self,
        name: str,
        shield_type: str = None,
        dependencies: Optional[Set[str]] = None,
        capabilities: Optional[Set[str]] = None,
        execution_time: float = 0.01,
        should_block: bool = False,
        resource_requirements: Optional[Dict[str, str]] = None,
        compatibility_info: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.shield_type = shield_type or f"Mock{name}Shield"
        self.dependencies = dependencies or set()
        self.capabilities = capabilities or set()
        self.execution_time = execution_time
        self.should_block = should_block
        self.resource_requirements = resource_requirements or {}
        self.compatibility_info = compatibility_info or {}
        self.call_count = 0
        self.performance_history = []
        
        # Set up mock attributes based on dependencies
        self._setup_mock_attributes()
        
        super().__init__(self._mock_shield_function, name=name)
    
    def _setup_mock_attributes(self):
        """Set up mock attributes based on dependencies."""
        if 'redis' in self.dependencies:
            self.redis_client = Mock()
            self.redis_client.connect = AsyncMock()
        
        if 'database' in self.dependencies:
            self.db_connection = Mock()
            self.db_connection.execute = AsyncMock()
        
        if 'cache' in self.dependencies:
            self.cache = Mock()
            self.cache.get = AsyncMock()
            self.cache.set = AsyncMock()
        
        if 'storage' in self.dependencies:
            self.storage = Mock()
            self.storage.save = AsyncMock()
        
        if 'config' in self.dependencies:
            self.config = Mock()
    
    async def _mock_shield_function(self, request) -> Optional[Any]:
        """Mock shield function implementation."""
        self.call_count += 1
        start_time = time.perf_counter()
        
        # Simulate execution time
        if self.execution_time > 0:
            await asyncio.sleep(self.execution_time)
        
        end_time = time.perf_counter()
        actual_time = end_time - start_time
        self.performance_history.append(actual_time)
        
        # Return response if should block
        if self.should_block:
            return {"error": f"Blocked by {self.name}"}
        
        return None  # Allow request
    
    def set_execution_time(self, time_seconds: float):
        """Set execution time for the shield."""
        self.execution_time = time_seconds
    
    def set_blocking(self, should_block: bool):
        """Set whether the shield should block requests."""
        self.should_block = should_block
    
    def get_performance_stats(self) -> Dict[str, float]:
        """Get performance statistics."""
        if not self.performance_history:
            return {}
        
        return {
            'call_count': self.call_count,
            'avg_execution_time': sum(self.performance_history) / len(self.performance_history),
            'min_execution_time': min(self.performance_history),
            'max_execution_time': max(self.performance_history),
            'total_execution_time': sum(self.performance_history)
        }
    
    def reset_stats(self):
        """Reset performance statistics."""
        self.call_count = 0
        self.performance_history = []


class MockAnalyzer(ShieldAnalyzer):
    """Mock analyzer for testing."""
    
    def __init__(
        self,
        analysis_type: AnalysisType,
        mock_analyses: Optional[Dict[str, Dict[str, Any]]] = None
    ):
        self.analysis_type = analysis_type
        self.mock_analyses = mock_analyses or {}
        self.analyze_calls = []
    
    def get_analysis_type(self) -> AnalysisType:
        """Get the analysis type."""
        return self.analysis_type
    
    async def analyze(self, shield: Shield) -> ShieldAnalysis:
        """Mock analyze method."""
        self.analyze_calls.append(shield)
        
        shield_type = type(shield).__name__
        shield_name = getattr(shield, 'name', shield_type)
        
        # Get mock analysis or create default
        if shield_name in self.mock_analyses:
            mock_data = self.mock_analyses[shield_name]
        elif shield_type in self.mock_analyses:
            mock_data = self.mock_analyses[shield_type]
        else:
            mock_data = self._create_default_analysis(shield)
        
        analysis = ShieldAnalysis(
            shield=shield,
            shield_type=shield_type,
            dependencies=set(mock_data.get('dependencies', [])),
            capabilities=set(mock_data.get('capabilities', [])),
            resource_requirements=mock_data.get('resource_requirements', {}),
            performance_characteristics=mock_data.get('performance_characteristics', {}),
            optimization_opportunities=mock_data.get('optimization_opportunities', []),
            compatibility_info=mock_data.get('compatibility_info', {}),
            metadata=mock_data.get('metadata', {})
        )
        
        return analysis
    
    def _create_default_analysis(self, shield: Shield) -> Dict[str, Any]:
        """Create default analysis for a shield."""
        if isinstance(shield, MockShield):
            return {
                'dependencies': list(shield.dependencies),
                'capabilities': list(shield.capabilities),
                'resource_requirements': shield.resource_requirements,
                'performance_characteristics': {
                    'latency': 'low' if shield.execution_time < 0.05 else 'medium',
                    'throughput': 'high',
                    'scalability': 'high'
                },
                'optimization_opportunities': ['caching', 'parallel_execution'],
                'compatibility_info': shield.compatibility_info or {
                    'thread_safe': True,
                    'async_compatible': True,
                    'stateless': True
                }
            }
        
        return {
            'dependencies': [],
            'capabilities': [],
            'resource_requirements': {},
            'performance_characteristics': {},
            'optimization_opportunities': [],
            'compatibility_info': {}
        }
    
    def get_analyze_call_count(self) -> int:
        """Get number of analyze calls."""
        return len(self.analyze_calls)
    
    def reset_calls(self):
        """Reset call tracking."""
        self.analyze_calls = []


class ShieldCompositionBuilder:
    """Builder for creating test shield compositions."""
    
    def __init__(self):
        self.shields = []
    
    def add_shield(
        self,
        name: str,
        shield_type: str = None,
        dependencies: Optional[Set[str]] = None,
        capabilities: Optional[Set[str]] = None,
        execution_time: float = 0.01,
        should_block: bool = False
    ) -> 'ShieldCompositionBuilder':
        """Add a shield to the composition."""
        shield = MockShield(
            name=name,
            shield_type=shield_type,
            dependencies=dependencies,
            capabilities=capabilities,
            execution_time=execution_time,
            should_block=should_block
        )
        self.shields.append(shield)
        return self
    
    def add_rate_limiting_shield(
        self,
        name: str = "RateLimit",
        execution_time: float = 0.02
    ) -> 'ShieldCompositionBuilder':
        """Add a rate limiting shield."""
        return self.add_shield(
            name=name,
            shield_type="RateLimitingShield",
            dependencies={'cache', 'redis'},
            capabilities={'rate_limiting', 'request_control'},
            execution_time=execution_time
        )
    
    def add_auth_shield(
        self,
        name: str = "Auth",
        execution_time: float = 0.05
    ) -> 'ShieldCompositionBuilder':
        """Add an authentication shield."""
        return self.add_shield(
            name=name,
            shield_type="AuthenticationShield",
            dependencies={'database', 'cache'},
            capabilities={'authentication', 'authorization'},
            execution_time=execution_time
        )
    
    def add_validation_shield(
        self,
        name: str = "Validation",
        execution_time: float = 0.01
    ) -> 'ShieldCompositionBuilder':
        """Add a validation shield."""
        return self.add_shield(
            name=name,
            shield_type="ValidationShield",
            capabilities={'validation', 'input_checking'},
            execution_time=execution_time
        )
    
    def add_logging_shield(
        self,
        name: str = "Logging",
        execution_time: float = 0.003
    ) -> 'ShieldCompositionBuilder':
        """Add a logging shield."""
        return self.add_shield(
            name=name,
            shield_type="LoggingShield",
            dependencies={'storage'},
            capabilities={'logging', 'auditing'},
            execution_time=execution_time
        )
    
    def add_cache_shield(
        self,
        name: str = "Cache",
        execution_time: float = 0.002
    ) -> 'ShieldCompositionBuilder':
        """Add a cache shield."""
        return self.add_shield(
            name=name,
            shield_type="CacheShield",
            dependencies={'redis', 'cache'},
            capabilities={'caching', 'response_optimization'},
            execution_time=execution_time
        )
    
    def add_database_shield(
        self,
        name: str = "Database",
        execution_time: float = 0.1
    ) -> 'ShieldCompositionBuilder':
        """Add a database shield."""
        return self.add_shield(
            name=name,
            shield_type="DatabaseShield",
            dependencies={'database', 'storage'},
            capabilities={'data_access', 'persistence'},
            execution_time=execution_time
        )
    
    def add_external_api_shield(
        self,
        name: str = "ExternalAPI",
        execution_time: float = 0.2
    ) -> 'ShieldCompositionBuilder':
        """Add an external API shield."""
        return self.add_shield(
            name=name,
            shield_type="ExternalAPIShield",
            dependencies={'external_service'},
            capabilities={'external_integration'},
            execution_time=execution_time
        )
    
    def build(self) -> List[MockShield]:
        """Build and return the shield composition."""
        return self.shields.copy()
    
    def build_with_redundancy(self) -> List[MockShield]:
        """Build composition with intentional redundancy for testing."""
        # Add duplicate shields for redundancy testing
        redundant_shields = []
        
        # Add original shields
        redundant_shields.extend(self.shields)
        
        # Add duplicates of some shields
        for shield in self.shields[:2]:  # Duplicate first two shields
            duplicate = MockShield(
                name=f"Duplicate{shield.name}",
                shield_type=shield.shield_type,
                dependencies=shield.dependencies.copy(),
                capabilities=shield.capabilities.copy(),
                execution_time=shield.execution_time * 1.1
            )
            redundant_shields.append(duplicate)
        
        return redundant_shields
    
    def build_with_bottleneck(self) -> List[MockShield]:
        """Build composition with a performance bottleneck."""
        bottleneck_shields = self.shields.copy()
        
        # Make one shield very slow
        if bottleneck_shields:
            bottleneck_shields[0].set_execution_time(0.5)  # 500ms bottleneck
        
        return bottleneck_shields
    
    def build_complex_composition(self) -> List[MockShield]:
        """Build a complex composition for comprehensive testing."""
        return (ShieldCompositionBuilder()
                .add_validation_shield("InputValidation", 0.005)
                .add_auth_shield("Authentication", 0.08)
                .add_rate_limiting_shield("RateLimit", 0.015)
                .add_cache_shield("ResponseCache", 0.002)
                .add_database_shield("UserDB", 0.12)
                .add_logging_shield("AuditLog", 0.004)
                .add_external_api_shield("NotificationService", 0.18)
                .build())


class OptimizationTestScenarios:
    """Pre-defined test scenarios for optimization testing."""
    
    @staticmethod
    def simple_composition() -> List[MockShield]:
        """Create a simple composition for basic testing."""
        return (ShieldCompositionBuilder()
                .add_validation_shield()
                .add_auth_shield()
                .add_logging_shield()
                .build())
    
    @staticmethod
    def redundant_composition() -> List[MockShield]:
        """Create a composition with redundancies."""
        return (ShieldCompositionBuilder()
                .add_auth_shield("Auth1")
                .add_auth_shield("Auth2")  # Redundant auth
                .add_cache_shield("Cache1")
                .add_cache_shield("Cache2")  # Redundant cache
                .add_validation_shield()
                .build())
    
    @staticmethod
    def performance_bottleneck_composition() -> List[MockShield]:
        """Create a composition with performance bottlenecks."""
        return (ShieldCompositionBuilder()
                .add_validation_shield("FastValidation", 0.001)
                .add_database_shield("SlowDB", 0.5)  # Major bottleneck
                .add_external_api_shield("SlowAPI", 0.3)  # Another bottleneck
                .add_logging_shield("FastLogging", 0.002)
                .build())
    
    @staticmethod
    def independent_shields_composition() -> List[MockShield]:
        """Create a composition with independent shields."""
        return [
            MockShield(
                name="Independent1",
                shield_type="IndependentShield1",
                capabilities={'validation'},
                execution_time=0.01
            ),
            MockShield(
                name="Independent2", 
                shield_type="IndependentShield2",
                capabilities={'logging'},
                execution_time=0.01
            ),
            MockShield(
                name="Independent3",
                shield_type="IndependentShield3",
                capabilities={'monitoring'},
                execution_time=0.01
            )
        ]
    
    @staticmethod
    def dependent_shields_composition() -> List[MockShield]:
        """Create a composition with dependent shields."""
        return [
            MockShield(
                name="Provider",
                shield_type="ProviderShield",
                capabilities={'authentication', 'user_context'},
                execution_time=0.05
            ),
            MockShield(
                name="Consumer",
                shield_type="ConsumerShield", 
                dependencies={'authentication'},
                capabilities={'authorization'},
                execution_time=0.02
            ),
            MockShield(
                name="FinalConsumer",
                shield_type="FinalConsumerShield",
                dependencies={'authorization'},
                execution_time=0.01
            )
        ]
    
    @staticmethod
    def mixed_async_sync_composition() -> List[MockShield]:
        """Create a composition with mixed async/sync compatibility."""
        shields = []
        
        # Async compatible shield
        async_shield = MockShield(
            name="AsyncShield",
            shield_type="AsyncShield",
            compatibility_info={
                'async_compatible': True,
                'thread_safe': True,
                'stateless': True
            }
        )
        shields.append(async_shield)
        
        # Sync only shield
        sync_shield = MockShield(
            name="SyncShield", 
            shield_type="SyncShield",
            compatibility_info={
                'async_compatible': False,
                'thread_safe': True,
                'stateless': False
            }
        )
        shields.append(sync_shield)
        
        return shields
    
    @staticmethod
    def high_resource_composition() -> List[MockShield]:
        """Create a composition with high resource requirements."""
        return [
            MockShield(
                name="MemoryIntensive",
                shield_type="MemoryIntensiveShield",
                resource_requirements={
                    'memory': 'high',
                    'cpu': 'medium'
                },
                execution_time=0.1
            ),
            MockShield(
                name="CPUIntensive",
                shield_type="CPUIntensiveShield",
                resource_requirements={
                    'memory': 'medium',
                    'cpu': 'high'
                },
                execution_time=0.15
            ),
            MockShield(
                name="NetworkIntensive",
                shield_type="NetworkIntensiveShield",
                resource_requirements={
                    'network': 'high',
                    'storage': 'medium'
                },
                execution_time=0.2
            )
        ]


class PerformanceTestHelper:
    """Helper for performance testing."""
    
    @staticmethod
    async def measure_composition_performance(
        shields: List[MockShield],
        request_count: int = 50
    ) -> Dict[str, Any]:
        """Measure performance of a shield composition."""
        from unittest.mock import Mock
        
        # Reset all shield stats
        for shield in shields:
            shield.reset_stats()
        
        start_time = time.perf_counter()
        successful_requests = 0
        blocked_requests = 0
        
        for i in range(request_count):
            mock_request = Mock()
            mock_request.method = "GET"
            mock_request.url = Mock()
            mock_request.url.path = f"/test/{i}"
            mock_request.client = Mock()
            mock_request.client.host = "127.0.0.1"
            
            request_blocked = False
            
            # Execute shields in sequence
            for shield in shields:
                result = await shield._mock_shield_function(mock_request)
                if result is not None:  # Request blocked
                    request_blocked = True
                    break
            
            if request_blocked:
                blocked_requests += 1
            else:
                successful_requests += 1
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        # Collect shield performance stats
        shield_stats = {}
        for shield in shields:
            if hasattr(shield, 'name') and hasattr(shield, 'get_performance_stats'):
                shield_stats[shield.name] = shield.get_performance_stats()
            else:
                # Fallback for shields without name attribute
                shield_name = getattr(shield, 'name', f'shield_{id(shield)}')
                if hasattr(shield, 'get_performance_stats'):
                    shield_stats[shield_name] = shield.get_performance_stats()
                else:
                    shield_stats[shield_name] = {
                        'call_count': 1,
                        'avg_execution_time': 0.001
                    }
        
        return {
            'total_time': total_time,
            'requests_per_second': request_count / total_time if total_time > 0 else 0,
            'successful_requests': successful_requests,
            'blocked_requests': blocked_requests,
            'shield_stats': shield_stats,
            'average_request_time': total_time / request_count if request_count > 0 else 0
        }
    
    @staticmethod
    async def compare_composition_performance(
        original_shields: List[MockShield],
        optimized_shields: List[MockShield],
        request_count: int = 50
    ) -> Dict[str, Any]:
        """Compare performance between original and optimized compositions."""
        original_perf = await PerformanceTestHelper.measure_composition_performance(
            original_shields, request_count
        )
        
        optimized_perf = await PerformanceTestHelper.measure_composition_performance(
            optimized_shields, request_count
        )
        
        improvement = {}
        if original_perf['total_time'] > 0:
            improvement['time_improvement'] = (
                (original_perf['total_time'] - optimized_perf['total_time']) / 
                original_perf['total_time']
            )
        
        if original_perf['requests_per_second'] > 0:
            improvement['throughput_improvement'] = (
                (optimized_perf['requests_per_second'] - original_perf['requests_per_second']) /
                original_perf['requests_per_second']
            )
        
        return {
            'original_performance': original_perf,
            'optimized_performance': optimized_perf,
            'improvement': improvement
        }


class OptimizationTestValidator:
    """Validator for optimization test results."""
    
    @staticmethod
    def validate_analysis_completeness(analysis, shields):
        """Validate that analysis covers all shields."""
        assert len(analysis.shield_analyses) == len(shields)
        
        analyzed_shields = {sa.shield for sa in analysis.shield_analyses}
        original_shields = set(shields)
        assert analyzed_shields == original_shields
    
    @staticmethod
    def validate_recommendations_quality(recommendations):
        """Validate quality of optimization recommendations."""
        assert len(recommendations) > 0, "Should generate at least one recommendation"
        
        for rec in recommendations:
            # Check required fields
            assert rec.optimization_type is not None
            assert rec.description is not None
            assert len(rec.description) > 0
            assert rec.implementation_complexity in ["low", "medium", "high"]
            assert rec.risk_level in ["low", "medium", "high"]
            assert len(rec.applicable_shields) > 0
            
            # Check estimated improvements
            assert len(rec.estimated_improvement) > 0
            for improvement_value in rec.estimated_improvement.values():
                assert isinstance(improvement_value, (int, float))
                assert improvement_value >= 0
    
    @staticmethod
    def validate_performance_metrics(metrics):
        """Validate performance metrics structure."""
        assert hasattr(metrics, 'execution_time')
        assert hasattr(metrics, 'total_requests')
        assert metrics.execution_time >= 0
        assert metrics.total_requests >= 0
        
        if metrics.total_requests > 0:
            assert metrics.average_response_time >= 0
    
    @staticmethod
    def validate_redundancy_detection(analysis):
        """Validate that redundancy detection works correctly."""
        redundancy_types = {r.get('type') for r in analysis.redundancies}
        
        # Should detect both capability and resource redundancies
        expected_types = {'capability_duplication', 'resource_duplication'}
        detected_types = redundancy_types.intersection(expected_types)
        
        assert len(detected_types) > 0, "Should detect at least one type of redundancy"
    
    @staticmethod
    def validate_bottleneck_detection(analysis):
        """Validate that bottleneck detection works correctly."""
        if analysis.bottlenecks:
            for bottleneck in analysis.bottlenecks:
                assert 'type' in bottleneck
                assert 'shield' in bottleneck
                assert 'estimated_impact' in bottleneck
                assert bottleneck['estimated_impact'] > 0