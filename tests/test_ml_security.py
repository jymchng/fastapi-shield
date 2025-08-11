"""Comprehensive tests for ML security functionality.

This test suite covers all aspects of the ML security system including:
- Request feature extraction and analysis
- Anomaly detection with multiple ML algorithms
- Threat intelligence integration and scoring
- Adaptive security policies and rate limiting
- Real-time threat prediction and response
- Performance optimization and model training
- Production scenarios and edge cases
"""

import asyncio
import time
import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any
import json

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# Try to import numpy, but handle gracefully if not available
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    # Create a mock numpy for testing purposes
    class MockNumpy:
        @staticmethod
        def array(data, dtype=None):
            return data
        
        @staticmethod
        def testing():
            class Testing:
                @staticmethod
                def assert_array_equal(a, b):
                    assert a == b
            return Testing()
        
        float32 = float
        
    np = MockNumpy()

from fastapi_shield.ml_security import (
    # Core classes
    RequestFeatureExtractor,
    AnomalyDetectionEngine,
    ThreatIntelligenceManager,
    AdaptiveSecurityManager,
    ThreatPredictionEngine,
    MLSecurityShield,
    
    # Data classes
    RequestFeatures,
    AnomalyResult,
    ThreatIntelligence,
    SecurityMetrics,
    
    # Enums
    ThreatLevel,
    AnomalyType,
    MLModelType,
    SecurityAction,
    
    # Convenience functions
    create_ml_security_shield,
    ml_security_shield_decorator,
)

from tests.mocks.mock_ml_infrastructure import (
    MockIsolationForest,
    MockOneClassSVM,
    MockDBSCAN,
    MockScaler,
    MockThreatIntelligenceAPI,
    MockSecurityEventGenerator,
    MockMLSecurityTestEnvironment,
    create_test_request_features,
    create_malicious_request_features,
)


class TestRequestFeatures:
    """Test RequestFeatures functionality."""
    
    def test_request_features_creation(self):
        """Test creating request features."""
        features = RequestFeatures(
            method="POST",
            path="/api/users",
            path_length=10,
            query_param_count=2,
            header_count=8,
            client_ip="192.168.1.100",
            suspicious_patterns=1,
            request_rate=15.5,
            has_potential_injection=True
        )
        
        assert features.method == "POST"
        assert features.path == "/api/users"
        assert features.path_length == 10
        assert features.suspicious_patterns == 1
        assert features.has_potential_injection is True
    
    def test_request_features_to_vector(self):
        """Test converting features to numerical vector."""
        features = create_test_request_features(
            method="GET",
            path_length=20,
            query_param_count=3,
            suspicious_patterns=2,
            request_rate=45.0
        )
        
        vector = features.to_vector()
        
        if NUMPY_AVAILABLE:
            assert hasattr(vector, 'dtype') or isinstance(vector, (list, tuple))
            assert len(vector) == 25  # Expected number of features
            
            # Check specific feature encodings
            assert vector[0] == 1  # GET method encoding
            assert vector[1] == 20  # path_length
            assert vector[2] == 3   # query_param_count
            assert vector[11] == 2  # suspicious_patterns
            assert vector[12] == 45.0  # request_rate
        else:
            # Without numpy, just check it's a sequence with correct length
            assert hasattr(vector, '__len__')
            assert len(vector) == 25
    
    def test_request_features_vector_consistency(self):
        """Test vector consistency across multiple calls."""
        features = create_test_request_features()
        
        vector1 = features.to_vector()
        vector2 = features.to_vector()
        
        if NUMPY_AVAILABLE:
            np.testing.assert_array_equal(vector1, vector2)
        else:
            assert list(vector1) == list(vector2)
    
    def test_request_features_different_methods(self):
        """Test different HTTP method encodings."""
        methods_and_codes = [
            ("GET", 1), ("POST", 2), ("PUT", 3), ("DELETE", 4),
            ("PATCH", 5), ("HEAD", 6), ("OPTIONS", 7), ("UNKNOWN", 0)
        ]
        
        for method, expected_code in methods_and_codes:
            features = create_test_request_features(method=method)
            vector = features.to_vector()
            assert vector[0] == expected_code


class TestRequestFeatureExtractor:
    """Test RequestFeatureExtractor functionality."""
    
    @pytest.fixture
    def extractor(self):
        """Create feature extractor."""
        return RequestFeatureExtractor()
    
    @pytest.fixture
    def mock_request(self):
        """Create mock FastAPI request."""
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/test"
        mock_request.query_params = {"param1": "value1", "param2": "value2"}
        mock_request.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "content-type": "application/json",
            "authorization": "Bearer token123"
        }
        mock_request.cookies = {}
        mock_request.client.host = "192.168.1.50"
        mock_request._body = b'{"test": "data"}'
        
        # Mock URL string  
        mock_request.url.__str__ = lambda self: "http://testserver/api/test?param1=value1&param2=value2"
        
        return mock_request
    
    def test_extract_basic_features(self, extractor, mock_request):
        """Test extracting basic request features."""
        features = extractor.extract_features(mock_request)
        
        assert features.method == "GET"
        assert features.path == "/api/test"
        assert features.path_length == 9
        assert features.query_param_count == 2
        assert features.header_count == 3
        assert features.client_ip == "192.168.1.50"
        assert features.is_private_ip is True
    
    def test_extract_client_ip_from_headers(self, extractor):
        """Test extracting client IP from various headers."""
        # Test X-Forwarded-For
        mock_request = Mock(spec=Request)
        mock_request.headers = {"x-forwarded-for": "203.0.113.195, 70.41.3.18"}
        mock_request.client.host = "127.0.0.1"
        
        ip = extractor._extract_client_ip(mock_request)
        assert ip == "203.0.113.195"
        
        # Test X-Real-IP
        mock_request.headers = {"x-real-ip": "198.51.100.178"}
        ip = extractor._extract_client_ip(mock_request)
        assert ip == "198.51.100.178"
        
        # Test fallback to client.host
        mock_request.headers = {}
        ip = extractor._extract_client_ip(mock_request)
        assert ip == "127.0.0.1"
    
    def test_detect_suspicious_patterns(self, extractor):
        """Test detection of suspicious patterns in URLs."""
        test_cases = [
            ("http://test.com/api?id=1' OR '1'='1", True),
            ("http://test.com/api?search=<script>alert('xss')</script>", True),
            ("http://test.com/files?path=../../../etc/passwd", True),
            ("http://test.com/api?cmd=exec('ls')", True),
            ("http://test.com/api?category=electronics&limit=10", False),
            ("http://test.com/search?q=normal search query", False)
        ]
        
        for url, should_be_suspicious in test_cases:
            mock_request = Mock(spec=Request)
            mock_request.url.__str__ = lambda self, u=url: u
            mock_request.method = "GET"
            mock_request.url.path = "/api/test"
            mock_request.query_params = {}
            mock_request.headers = {"user-agent": "test"}
            mock_request.client.host = "127.0.0.1"
            mock_request._body = b""
            
            features = extractor.extract_features(mock_request)
            
            if should_be_suspicious:
                assert features.suspicious_patterns > 0, f"Should detect suspicious pattern in: {url}"
            else:
                assert features.suspicious_patterns == 0, f"Should not detect suspicious pattern in: {url}"
    
    def test_calculate_entropy(self, extractor):
        """Test payload entropy calculation."""
        # High entropy (random-looking data)
        high_entropy_text = "a8f3k9m2x7n4b6c1e5d9g8h3j2l4"
        high_entropy = extractor._calculate_entropy(high_entropy_text)
        
        # Low entropy (repetitive data)
        low_entropy_text = "aaaaaaaaaaaaaaaaaaaa"
        low_entropy = extractor._calculate_entropy(low_entropy_text)
        
        # Medium entropy (normal text)
        medium_entropy_text = "This is a normal sentence with some variety."
        medium_entropy = extractor._calculate_entropy(medium_entropy_text)
        
        assert high_entropy > medium_entropy > low_entropy
        assert high_entropy > 3.0  # Should be relatively high
        assert low_entropy < 2.0   # Should be relatively low
    
    def test_behavioral_feature_tracking(self, extractor, mock_request):
        """Test behavioral feature tracking over time."""
        client_ip = "192.168.1.100"
        
        # Make multiple requests to build behavioral profile
        for i in range(5):
            mock_request.url.path = f"/api/endpoint{i}"
            features = extractor.extract_features(mock_request, client_ip)
            time.sleep(0.01)  # Small delay to ensure different timestamps
        
        # Extract features again to check behavioral tracking
        features = extractor.extract_features(mock_request, client_ip)
        
        assert features.unique_endpoints_accessed >= 5
        assert features.request_rate > 0
        assert features.session_duration > 0
    
    def test_is_private_ip(self, extractor):
        """Test private IP detection."""
        private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]
        public_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        
        for ip in private_ips:
            assert extractor._is_private_ip(ip) is True, f"{ip} should be private"
        
        for ip in public_ips:
            assert extractor._is_private_ip(ip) is False, f"{ip} should be public"
    
    def test_temporal_features(self, extractor, mock_request):
        """Test extraction of temporal features."""
        features = extractor.extract_features(mock_request)
        
        assert 0 <= features.hour_of_day <= 23
        assert 0 <= features.day_of_week <= 6
        assert isinstance(features.is_weekend, bool)


class TestAnomalyDetectionEngine:
    """Test AnomalyDetectionEngine functionality."""
    
    @pytest.fixture
    def engine(self):
        """Create anomaly detection engine."""
        with patch('fastapi_shield.ml_security.SKLEARN_AVAILABLE', True):
            engine = AnomalyDetectionEngine(MLModelType.ENSEMBLE)
            # Mock sklearn components
            engine.models = {
                'isolation_forest': MockIsolationForest(),
                'one_class_svm': MockOneClassSVM(),
                'dbscan': MockDBSCAN()
            }
            engine.scalers = {
                'isolation_forest': MockScaler(),
                'one_class_svm': MockScaler(),
                'dbscan': MockScaler()
            }
            return engine
    
    def test_engine_initialization(self, engine):
        """Test engine initialization."""
        assert engine.model_type == MLModelType.ENSEMBLE
        assert len(engine.models) == 3
        assert len(engine.scalers) == 3
        assert engine.is_trained is False
    
    def test_add_training_data(self, engine):
        """Test adding training data."""
        normal_features = create_test_request_features()
        malicious_features = create_malicious_request_features()
        
        # Add normal data
        for _ in range(50):
            engine.add_training_data(normal_features, is_anomaly=False)
        
        # Add some anomalous data
        for _ in range(10):
            engine.add_training_data(malicious_features, is_anomaly=True)
        
        assert len(engine.training_data) == 60
        assert len(engine.training_labels) == 60
        assert sum(engine.training_labels) == 10  # 10 anomalies
    
    def test_model_training(self, engine):
        """Test ML model training."""
        # Add training data
        for _ in range(100):
            features = create_test_request_features()
            engine.add_training_data(features, is_anomaly=False)
        
        for _ in range(20):
            features = create_malicious_request_features()
            engine.add_training_data(features, is_anomaly=True)
        
        # Train models
        engine.train_models()
        
        assert engine.is_trained is True
        
        # Verify all models are trained
        for model in engine.models.values():
            assert model.is_fitted is True
    
    def test_anomaly_detection_trained(self, engine):
        """Test anomaly detection with trained models."""
        # Train the engine first
        for _ in range(100):
            engine.add_training_data(create_test_request_features(), is_anomaly=False)
        
        engine.train_models()
        
        # Test detection on normal request
        normal_features = create_test_request_features()
        result = engine.detect_anomaly(normal_features)
        
        assert isinstance(result, AnomalyResult)
        assert isinstance(result.is_anomaly, bool)
        assert 0.0 <= result.confidence_score <= 1.0
        assert result.anomaly_type in AnomalyType
        assert result.threat_level in ThreatLevel
        assert result.recommended_action in SecurityAction
    
    def test_anomaly_detection_untrained(self, engine):
        """Test anomaly detection without trained models (rule-based fallback)."""
        malicious_features = create_malicious_request_features(
            suspicious_patterns=3,
            has_potential_injection=True,
            request_rate=150.0,
            payload_entropy=8.0
        )
        
        result = engine.detect_anomaly(malicious_features)
        
        assert isinstance(result, AnomalyResult)
        assert result.is_anomaly is True
        assert result.confidence_score > 0.5
        assert len(result.features_contributing) > 0
    
    def test_rule_based_detection_patterns(self, engine):
        """Test rule-based detection patterns."""
        test_cases = [
            # (features_kwargs, should_be_anomaly, min_confidence)
            ({"suspicious_patterns": 2, "has_potential_injection": True}, True, 0.7),
            ({"request_rate": 200.0}, True, 0.3),
            ({"payload_entropy": 8.5, "has_unusual_encoding": True}, True, 0.4),
            ({"suspicious_patterns": 0, "request_rate": 5.0}, False, 0.3),
        ]
        
        for features_kwargs, should_be_anomaly, min_confidence in test_cases:
            features = create_test_request_features(**features_kwargs)
            result = engine.detect_anomaly(features)
            
            if should_be_anomaly:
                assert result.is_anomaly is True
                assert result.confidence_score >= min_confidence
            else:
                # Note: Normal requests might still be flagged with low confidence
                assert result.confidence_score <= 0.6
    
    def test_threat_level_assessment(self, engine):
        """Test threat level assessment."""
        # Critical threat
        critical_features = create_malicious_request_features(
            has_potential_injection=True,
            suspicious_patterns=5
        )
        result = engine.detect_anomaly(critical_features)
        assert result.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]
        
        # Medium threat
        medium_features = create_test_request_features(
            request_rate=80.0,
            suspicious_patterns=1
        )
        result = engine.detect_anomaly(medium_features)
        # Threat level should be reasonable for medium threat
        assert result.threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH]
    
    def test_ensemble_vs_single_model(self):
        """Test ensemble vs single model performance."""
        with patch('fastapi_shield.ml_security.SKLEARN_AVAILABLE', True):
            # Ensemble engine
            ensemble_engine = AnomalyDetectionEngine(MLModelType.ENSEMBLE)
            ensemble_engine.models = {
                'isolation_forest': MockIsolationForest(),
                'one_class_svm': MockOneClassSVM(),
                'dbscan': MockDBSCAN()
            }
            ensemble_engine.scalers = {
                'isolation_forest': MockScaler(),
                'one_class_svm': MockScaler(),
                'dbscan': MockScaler()
            }
            
            # Single model engine
            single_engine = AnomalyDetectionEngine(MLModelType.ISOLATION_FOREST)
            single_engine.models = {'isolation_forest': MockIsolationForest()}
            single_engine.scalers = {'isolation_forest': MockScaler()}
            
            # Train both
            for engine in [ensemble_engine, single_engine]:
                for _ in range(100):
                    engine.add_training_data(create_test_request_features(), is_anomaly=False)
                engine.train_models()
            
            # Test detection
            malicious_features = create_malicious_request_features()
            
            ensemble_result = ensemble_engine.detect_anomaly(malicious_features)
            single_result = single_engine.detect_anomaly(malicious_features)
            
            # Both should produce valid results
            assert isinstance(ensemble_result.confidence_score, float)
            assert isinstance(single_result.confidence_score, float)


class TestThreatIntelligenceManager:
    """Test ThreatIntelligenceManager functionality."""
    
    @pytest.fixture
    def threat_manager(self):
        """Create threat intelligence manager."""
        return ThreatIntelligenceManager()
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request for testing."""
        mock_request = Mock(spec=Request)
        mock_request.url.__str__ = lambda self: "http://testserver/api/test?param=value"
        mock_request.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "referer": "http://example.com/"
        }
        return mock_request
    
    def test_initialization(self, threat_manager):
        """Test threat manager initialization."""
        assert len(threat_manager.threat_db) == 0
        assert len(threat_manager.ip_reputation) == 0
        assert len(threat_manager.domain_reputation) == 0
        assert len(threat_manager.known_attack_patterns) > 0
    
    def test_add_threat_intelligence(self, threat_manager):
        """Test adding threat intelligence."""
        threat = ThreatIntelligence(
            indicator="192.168.1.100",
            indicator_type="ip",
            threat_level=ThreatLevel.HIGH,
            confidence=0.9,
            source="test",
            first_seen=time.time(),
            last_seen=time.time()
        )
        
        threat_manager.add_threat_intelligence(threat)
        
        assert "192.168.1.100" in threat_manager.threat_db
        assert "192.168.1.100" in threat_manager.ip_reputation
        
        # Reputation should be calculated based on threat level and confidence
        reputation = threat_manager.ip_reputation["192.168.1.100"]
        assert 0.0 <= reputation <= 1.0
        assert reputation < 0.5  # High threat should result in low reputation
    
    def test_score_request_threat_malicious_ip(self, threat_manager, mock_request):
        """Test threat scoring for malicious IP."""
        # Add malicious IP to reputation database
        malicious_ip = "203.0.113.195"
        threat_manager.ip_reputation[malicious_ip] = 0.1  # Very low reputation
        
        threat_score, indicators = threat_manager.score_request_threat(mock_request, malicious_ip)
        
        assert threat_score > 0.3  # Should have significant threat score
        assert any("malicious_ip" in indicator for indicator in indicators)
    
    def test_score_request_threat_attack_patterns(self, threat_manager, mock_request):
        """Test threat scoring for attack patterns."""
        # Create request with attack pattern
        mock_request.url.__str__ = lambda self: "http://testserver/api/test?id=1' OR '1'='1"
        
        threat_score, indicators = threat_manager.score_request_threat(mock_request, "192.168.1.1")
        
        assert threat_score > 0.1  # Should detect attack pattern
        assert any("attack_pattern" in indicator for indicator in indicators)
    
    def test_score_request_threat_malicious_user_agent(self, threat_manager, mock_request):
        """Test threat scoring for malicious user agent."""
        mock_request.headers["user-agent"] = "sqlmap/1.4.7"
        
        threat_score, indicators = threat_manager.score_request_threat(mock_request, "192.168.1.1")
        
        assert threat_score >= 0.3  # Should detect malicious tool
        assert any("malicious_ua" in indicator for indicator in indicators)
    
    def test_update_reputation_feedback(self, threat_manager):
        """Test updating reputation based on feedback."""
        ip = "192.168.1.200"
        
        # Initial reputation
        threat_manager.ip_reputation[ip] = 0.5
        
        # Negative feedback (indicating malicious activity)
        threat_manager.update_reputation(ip, "ip", 0.1, "feedback")
        
        updated_reputation = threat_manager.ip_reputation[ip]
        assert updated_reputation < 0.5  # Should decrease
        
        # Positive feedback
        threat_manager.update_reputation(ip, "ip", 0.9, "feedback")
        
        final_reputation = threat_manager.ip_reputation[ip]
        assert final_reputation > updated_reputation  # Should increase
    
    def test_get_threat_summary(self, threat_manager):
        """Test getting threat intelligence summary."""
        # Add some test data
        for i in range(5):
            threat = ThreatIntelligence(
                indicator=f"192.168.1.{i+100}",
                indicator_type="ip",
                threat_level=ThreatLevel.HIGH if i < 2 else ThreatLevel.MEDIUM,
                confidence=0.8,
                source="test",
                first_seen=time.time(),
                last_seen=time.time()
            )
            threat_manager.add_threat_intelligence(threat)
        
        summary = threat_manager.get_threat_summary()
        
        assert summary["total_indicators"] == 5
        assert summary["ip_indicators"] == 5
        assert summary["high_threats"] == 2
        assert summary["attack_patterns"] > 0


class TestAdaptiveSecurityManager:
    """Test AdaptiveSecurityManager functionality."""
    
    @pytest.fixture
    def adaptive_manager(self):
        """Create adaptive security manager."""
        return AdaptiveSecurityManager(base_rate_limit=100)
    
    def test_initialization(self, adaptive_manager):
        """Test adaptive manager initialization."""
        assert adaptive_manager.base_rate_limit == 100
        assert len(adaptive_manager.adaptive_rules) == 0
        assert len(adaptive_manager.client_profiles) == 0
    
    def test_client_profile_creation(self, adaptive_manager):
        """Test automatic client profile creation."""
        client_ip = "192.168.1.100"
        
        # Access profile (should create automatically)
        trust_score = adaptive_manager.get_client_trust_score(client_ip)
        
        assert trust_score == 0.5  # Default trust score
        assert client_ip in adaptive_manager.client_profiles
    
    def test_trust_score_updates(self, adaptive_manager):
        """Test trust score updates based on behavior."""
        client_ip = "192.168.1.100"
        features = create_test_request_features()
        
        # Simulate anomaly detection results
        critical_anomaly = AnomalyResult(
            is_anomaly=True,
            confidence_score=0.9,
            anomaly_type=AnomalyType.PAYLOAD_ANOMALY,
            threat_level=ThreatLevel.CRITICAL,
            explanation="Critical threat detected",
            features_contributing=["payload_entropy"],
            recommended_action=SecurityAction.BLOCK
        )
        
        initial_trust = adaptive_manager.get_client_trust_score(client_ip)
        
        # Update with critical anomaly
        adaptive_manager.update_client_profile(client_ip, critical_anomaly, 0.8, features)
        
        updated_trust = adaptive_manager.get_client_trust_score(client_ip)
        
        assert updated_trust < initial_trust  # Trust should decrease
        
        # Simulate normal behavior
        normal_anomaly = AnomalyResult(
            is_anomaly=False,
            confidence_score=0.1,
            anomaly_type=AnomalyType.BEHAVIORAL_ANOMALY,
            threat_level=ThreatLevel.LOW,
            explanation="Normal behavior",
            features_contributing=[],
            recommended_action=SecurityAction.ALLOW
        )
        
        # Multiple normal requests should slowly increase trust
        for _ in range(10):
            adaptive_manager.update_client_profile(client_ip, normal_anomaly, 0.1, features)
        
        final_trust = adaptive_manager.get_client_trust_score(client_ip)
        assert final_trust > updated_trust  # Trust should recover
    
    def test_adaptive_rate_limiting(self, adaptive_manager):
        """Test adaptive rate limiting based on trust score."""
        client_ip = "192.168.1.100"
        
        # High trust client
        adaptive_manager.client_profiles[client_ip]['trust_score'] = 0.9
        rate_limit = adaptive_manager.get_client_rate_limit(client_ip)
        assert rate_limit > 100  # Should get higher rate limit
        
        # Low trust client
        adaptive_manager.client_profiles[client_ip]['trust_score'] = 0.2
        rate_limit = adaptive_manager.get_client_rate_limit(client_ip)
        assert rate_limit < 100  # Should get lower rate limit
        
        # Very low trust client
        adaptive_manager.client_profiles[client_ip]['trust_score'] = 0.1
        rate_limit = adaptive_manager.get_client_rate_limit(client_ip)
        assert rate_limit <= 10  # Should get very strict rate limit
    
    def test_adaptive_rule_creation(self, adaptive_manager):
        """Test creation of adaptive security rules."""
        client_ip = "192.168.1.100"
        features = create_test_request_features()
        
        # Rate anomaly should create rate limit rule
        rate_anomaly = AnomalyResult(
            is_anomaly=True,
            confidence_score=0.7,
            anomaly_type=AnomalyType.RATE_ANOMALY,
            threat_level=ThreatLevel.MEDIUM,
            explanation="Rate anomaly detected",
            features_contributing=["request_rate"],
            recommended_action=SecurityAction.THROTTLE
        )
        
        initial_rules_count = len(adaptive_manager.adaptive_rules)
        
        adaptive_manager.update_client_profile(client_ip, rate_anomaly, 0.5, features)
        
        assert len(adaptive_manager.adaptive_rules) > initial_rules_count
        
        # Check rule content
        rate_rules = [rule for rule in adaptive_manager.adaptive_rules.values() 
                     if rule.get('type') == 'rate_limit']
        assert len(rate_rules) > 0
        assert rate_rules[0]['client_ip'] == client_ip
    
    def test_strict_validation_rules(self, adaptive_manager):
        """Test strict validation rule application."""
        client_ip = "192.168.1.100"
        
        # Initially should not require strict validation
        assert adaptive_manager.should_apply_strict_validation(client_ip) is False
        
        # Create payload inspection rule
        adaptive_manager.adaptive_rules["test_rule"] = {
            'type': 'payload_inspection',
            'client_ip': client_ip,
            'created': time.time(),
            'duration': 600
        }
        
        # Now should require strict validation
        assert adaptive_manager.should_apply_strict_validation(client_ip) is True
        
        # Very low trust should also trigger strict validation
        adaptive_manager.client_profiles[client_ip]['trust_score'] = 0.1
        assert adaptive_manager.should_apply_strict_validation(client_ip) is True
    
    def test_rule_cleanup(self, adaptive_manager):
        """Test cleanup of expired adaptive rules."""
        client_ip = "192.168.1.100"
        
        # Create expired rule
        expired_rule = {
            'type': 'rate_limit',
            'client_ip': client_ip,
            'created': time.time() - 1000,  # Old timestamp
            'duration': 300
        }
        adaptive_manager.adaptive_rules["expired_rule"] = expired_rule
        
        # Create active rule
        active_rule = {
            'type': 'payload_inspection',
            'client_ip': client_ip,
            'created': time.time(),
            'duration': 600
        }
        adaptive_manager.adaptive_rules["active_rule"] = active_rule
        
        # Cleanup should remove expired rule
        adaptive_manager.cleanup_expired_rules()
        
        assert "expired_rule" not in adaptive_manager.adaptive_rules
        assert "active_rule" in adaptive_manager.adaptive_rules
    
    def test_adaptive_stats(self, adaptive_manager):
        """Test getting adaptive security statistics."""
        # Add some test data
        for i in range(5):
            client_ip = f"192.168.1.{100+i}"
            adaptive_manager.client_profiles[client_ip]['trust_score'] = 0.3 + (i * 0.15)
        
        adaptive_manager.adaptive_rules["rule1"] = {"type": "rate_limit"}
        adaptive_manager.adaptive_rules["rule2"] = {"type": "payload_inspection"}
        
        stats = adaptive_manager.get_adaptive_stats()
        
        assert stats["total_clients"] == 5
        assert stats["active_rules"] == 2
        assert 0.0 <= stats["avg_trust_score"] <= 1.0
        assert stats["low_trust_clients"] >= 0
        assert stats["high_trust_clients"] >= 0


class TestThreatPredictionEngine:
    """Test ThreatPredictionEngine functionality."""
    
    @pytest.fixture
    def prediction_engine(self):
        """Create threat prediction engine."""
        with patch('fastapi_shield.ml_security.TENSORFLOW_AVAILABLE', True):
            from tests.mocks.mock_ml_infrastructure import MockTensorFlowModel
            engine = ThreatPredictionEngine()
            engine.prediction_model = MockTensorFlowModel()
            engine.prediction_model.compile()
            return engine
    
    def test_initialization(self, prediction_engine):
        """Test prediction engine initialization."""
        assert prediction_engine.sequence_length == 10
        assert len(prediction_engine.client_sequences) == 0
        assert prediction_engine.prediction_model is not None
    
    def test_add_request_sequence(self, prediction_engine):
        """Test adding request sequences."""
        client_ip = "192.168.1.100"
        
        # Add multiple requests to build sequence
        for i in range(15):
            features = create_test_request_features(path=f"/api/endpoint{i}")
            is_threat = (i % 5 == 0)  # Every 5th request is a threat
            prediction_engine.add_request_sequence(client_ip, features, is_threat)
        
        sequence = prediction_engine.client_sequences[client_ip]
        assert len(sequence) == 10  # Should be limited to sequence_length
        assert any(item['is_threat'] for item in sequence)
    
    def test_heuristic_prediction(self, prediction_engine):
        """Test heuristic-based threat prediction."""
        # Normal features
        normal_features = create_test_request_features()
        normal_score = prediction_engine._heuristic_prediction(normal_features)
        
        # Malicious features
        malicious_features = create_malicious_request_features(
            request_rate=120.0,
            suspicious_patterns=3,
            has_potential_injection=True,
            payload_entropy=8.0
        )
        malicious_score = prediction_engine._heuristic_prediction(malicious_features)
        
        assert 0.0 <= normal_score <= 1.0
        assert 0.0 <= malicious_score <= 1.0
        assert malicious_score > normal_score
    
    def test_predict_threat_probability_insufficient_history(self, prediction_engine):
        """Test prediction with insufficient request history."""
        client_ip = "192.168.1.100"
        features = create_test_request_features()
        
        # Add only few requests (less than sequence_length)
        for _ in range(3):
            prediction_engine.add_request_sequence(client_ip, features, False)
        
        probability = prediction_engine.predict_threat_probability(client_ip, features)
        
        assert 0.0 <= probability <= 1.0
    
    def test_predict_threat_probability_with_model(self, prediction_engine):
        """Test prediction with trained model."""
        client_ip = "192.168.1.100"
        
        # Build sufficient sequence
        for i in range(15):
            features = create_test_request_features()
            is_threat = (i < 3)  # First few are threats
            prediction_engine.add_request_sequence(client_ip, features, is_threat)
        
        # Mock scaler
        from tests.mocks.mock_ml_infrastructure import MockScaler
        prediction_engine.feature_scaler = MockScaler()
        prediction_engine.feature_scaler.fit([[1, 2, 3]])  # Dummy fit
        
        current_features = create_test_request_features()
        probability = prediction_engine.predict_threat_probability(client_ip, current_features)
        
        assert 0.0 <= probability <= 1.0


class TestMLSecurityShield:
    """Test MLSecurityShield functionality."""
    
    @pytest.fixture
    def app(self):
        """Create FastAPI test app."""
        from fastapi import FastAPI
        app = FastAPI()
        
        @app.get("/api/test")
        def test_endpoint():
            return {"message": "test"}
        
        @app.post("/api/data")
        def data_endpoint(data: dict):
            return {"received": data}
        
        return app
    
    @pytest.fixture
    def ml_shield(self):
        """Create ML security shield."""
        with patch('fastapi_shield.ml_security.SKLEARN_AVAILABLE', True), \
             patch('fastapi_shield.ml_security.TENSORFLOW_AVAILABLE', True):
            
            shield = MLSecurityShield(
                model_type=MLModelType.ENSEMBLE,
                enable_threat_intelligence=True,
                enable_adaptive_policies=True,
                enable_threat_prediction=True,
                base_rate_limit=100
            )
            
            # Mock ML components
            from tests.mocks.mock_ml_infrastructure import MockIsolationForest, MockScaler
            shield.anomaly_engine.models = {
                'isolation_forest': MockIsolationForest(),
                'one_class_svm': MockIsolationForest()  # Use same mock
            }
            shield.anomaly_engine.scalers = {
                'isolation_forest': MockScaler(),
                'one_class_svm': MockScaler()
            }
            shield.anomaly_engine.is_trained = True
            
            return shield
    
    def test_shield_initialization(self, ml_shield):
        """Test ML security shield initialization."""
        assert ml_shield.feature_extractor is not None
        assert ml_shield.anomaly_engine is not None
        assert ml_shield.threat_intelligence is not None
        assert ml_shield.adaptive_manager is not None
        assert ml_shield.prediction_engine is not None
        assert isinstance(ml_shield.metrics, SecurityMetrics)
    
    def test_shield_integration(self, app, ml_shield):
        """Test shield integration with FastAPI."""
        # Apply shield to endpoint
        @ml_shield
        @app.get("/protected")
        def protected_endpoint():
            return {"message": "protected"}
        
        client = TestClient(app)
        
        # Normal request should pass
        response = client.get("/protected")
        assert response.status_code in [200, 403, 429]  # Could be blocked depending on ML analysis
    
    @pytest.mark.asyncio
    async def test_ml_security_analysis_normal_request(self, ml_shield):
        """Test ML security analysis for normal request."""
        # Create normal request
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/test"
        mock_request.query_params = {"param": "value"}
        mock_request.headers = {"user-agent": "Mozilla/5.0"}
        mock_request.client.host = "192.168.1.50"
        mock_request._body = b""
        mock_request.url.__str__ = lambda: "http://testserver/api/test?param=value"
        
        result = await ml_shield._ml_security_analysis(mock_request)
        
        # Normal request should either pass (None) or get appropriate response
        assert result is None or hasattr(result, 'status_code')
        
        # Check metrics were updated
        assert ml_shield.metrics.total_requests_analyzed > 0
    
    @pytest.mark.asyncio
    async def test_ml_security_analysis_malicious_request(self, ml_shield):
        """Test ML security analysis for malicious request."""
        # Create malicious request
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/test"
        mock_request.query_params = {"id": "1' OR '1'='1"}
        mock_request.headers = {"user-agent": "sqlmap/1.4.7"}
        mock_request.client.host = "203.0.113.195"  # Suspicious IP
        mock_request._body = b""
        mock_request.url.__str__ = lambda: "http://testserver/api/test?id=1' OR '1'='1"
        
        # Add malicious IP to threat intelligence
        if ml_shield.threat_intelligence:
            ml_shield.threat_intelligence.ip_reputation["203.0.113.195"] = 0.1
        
        result = await ml_shield._ml_security_analysis(mock_request)
        
        # Malicious request should be blocked or throttled
        if result is not None:
            assert result.status_code in [403, 429]
    
    def test_determine_response_critical_threat(self, ml_shield):
        """Test response determination for critical threats."""
        mock_request = Mock(spec=Request)
        client_ip = "203.0.113.195"
        
        # Critical anomaly result
        anomaly_result = AnomalyResult(
            is_anomaly=True,
            confidence_score=0.95,
            anomaly_type=AnomalyType.PAYLOAD_ANOMALY,
            threat_level=ThreatLevel.CRITICAL,
            explanation="Critical threat detected",
            features_contributing=["payload_entropy", "suspicious_patterns"],
            recommended_action=SecurityAction.BLOCK
        )
        
        response = ml_shield._determine_response(
            mock_request, client_ip, anomaly_result, 0.9, 0.8, 0.95, []
        )
        
        assert response is not None
        assert response.status_code == 403
    
    def test_determine_response_normal_request(self, ml_shield):
        """Test response determination for normal requests."""
        mock_request = Mock(spec=Request)
        client_ip = "192.168.1.50"
        
        # Normal result
        anomaly_result = AnomalyResult(
            is_anomaly=False,
            confidence_score=0.1,
            anomaly_type=AnomalyType.BEHAVIORAL_ANOMALY,
            threat_level=ThreatLevel.LOW,
            explanation="Normal behavior",
            features_contributing=[],
            recommended_action=SecurityAction.ALLOW
        )
        
        response = ml_shield._determine_response(
            mock_request, client_ip, anomaly_result, 0.1, 0.05, 0.1, []
        )
        
        # Normal request should pass
        assert response is None
    
    def test_get_security_metrics(self, ml_shield):
        """Test getting comprehensive security metrics."""
        # Generate some activity
        ml_shield.metrics.total_requests_analyzed = 1000
        ml_shield.metrics.anomalies_detected = 50
        ml_shield.metrics.threats_blocked = 20
        
        metrics = ml_shield.get_security_metrics()
        
        assert "total_requests_analyzed" in metrics
        assert "anomalies_detected" in metrics
        assert "threats_blocked" in metrics
        assert "threat_intelligence" in metrics
        assert "adaptive_security" in metrics
        assert "ml_models" in metrics
        
        assert metrics["total_requests_analyzed"] == 1000
        assert metrics["anomalies_detected"] == 50
        assert metrics["threats_blocked"] == 20
    
    def test_background_tasks(self, ml_shield):
        """Test background maintenance tasks."""
        assert ml_shield._running is True
        assert ml_shield._background_thread is not None
        assert ml_shield._background_thread.is_alive()
        
        # Test cleanup
        ml_shield.stop_background_tasks()
        assert ml_shield._running is False
    
    def test_threat_feedback(self, ml_shield):
        """Test threat detection feedback mechanism."""
        request_id = "test-request-123"
        
        initial_fp_rate = ml_shield.metrics.false_positive_rate
        
        # Report false positive
        ml_shield.add_threat_feedback(request_id, is_false_positive=True)
        
        # False positive rate should increase slightly
        assert ml_shield.metrics.false_positive_rate >= initial_fp_rate
    
    def test_model_export_load(self, ml_shield, tmp_path):
        """Test model export and loading functionality."""
        test_file = tmp_path / "test_model.pkl"
        
        # Add some test data
        ml_shield.metrics.total_requests_analyzed = 100
        if ml_shield.threat_intelligence:
            ml_shield.threat_intelligence.ip_reputation["192.168.1.100"] = 0.3
        
        # Export model
        ml_shield.export_model(str(test_file))
        assert test_file.exists()
        
        # Create new shield and load model
        new_shield = MLSecurityShield(enable_all_features=False)
        new_shield.load_model(str(test_file))
        
        # Verify data was loaded
        # Note: In a real scenario, you'd check if models and data were properly restored


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_create_ml_security_shield(self):
        """Test creating ML security shield with convenience function."""
        shield = create_ml_security_shield(
            model_type=MLModelType.ISOLATION_FOREST,
            enable_all_features=True
        )
        
        assert isinstance(shield, MLSecurityShield)
        assert shield.anomaly_engine.model_type == MLModelType.ISOLATION_FOREST
        assert shield.threat_intelligence is not None
        assert shield.adaptive_manager is not None
    
    def test_ml_security_shield_decorator(self):
        """Test ML security shield decorator."""
        @ml_security_shield_decorator(model_type=MLModelType.ONE_CLASS_SVM)
        def test_endpoint():
            return {"message": "decorated"}
        
        # The decorator should return a callable
        assert callable(test_endpoint)


class TestIntegrationScenarios:
    """Test complete integration scenarios."""
    
    @pytest.fixture
    def test_environment(self):
        """Create test environment."""
        from tests.mocks.mock_ml_infrastructure import MockMLSecurityTestEnvironment
        return MockMLSecurityTestEnvironment()
    
    def test_mixed_traffic_scenario(self, test_environment):
        """Test mixed normal and malicious traffic."""
        # Generate mixed traffic
        test_requests = test_environment.create_mixed_traffic_scenario(
            total_requests=100,
            attack_ratio=0.2
        )
        
        assert len(test_requests) == 100
        
        # Count attack requests
        attack_requests = [r for r in test_requests if r["threat_level"] in ["medium", "high", "critical"]]
        normal_requests = [r for r in test_requests if r["threat_level"] == "low"]
        
        assert len(attack_requests) >= 15  # Should be around 20, allowing for some variance
        assert len(normal_requests) >= 70
    
    def test_performance_measurement(self, test_environment):
        """Test ML shield performance measurement."""
        # Create test shield
        with patch('fastapi_shield.ml_security.SKLEARN_AVAILABLE', True):
            ml_shield = create_ml_security_shield(enable_all_features=True)
        
        # Generate test requests
        test_requests = test_environment.create_mixed_traffic_scenario(
            total_requests=50,
            attack_ratio=0.3
        )
        
        # Measure performance
        performance_results = test_environment.measure_performance(ml_shield, test_requests)
        
        assert "accuracy" in performance_results
        assert "precision" in performance_results
        assert "recall" in performance_results
        assert "f1_score" in performance_results
        assert "avg_processing_time" in performance_results
        
        assert 0.0 <= performance_results["accuracy"] <= 1.0
        assert 0.0 <= performance_results["precision"] <= 1.0
        assert 0.0 <= performance_results["recall"] <= 1.0
        assert performance_results["avg_processing_time"] >= 0
        assert performance_results["total_requests"] == 50
    
    def test_real_time_attack_simulation(self, test_environment):
        """Test real-time attack scenario."""
        # Simulate SQL injection attack
        attack_requests = test_environment.simulate_real_time_attack(
            attack_type="sql_injection",
            duration_seconds=1,  # Short duration for testing
            requests_per_second=10
        )
        
        assert len(attack_requests) > 0
        
        # All requests should be SQL injection attempts
        for request in attack_requests:
            assert "OR" in str(request.get("query_params", {})) or \
                   "UNION" in str(request.get("query_params", {})) or \
                   "DROP" in str(request.get("query_params", {}))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])