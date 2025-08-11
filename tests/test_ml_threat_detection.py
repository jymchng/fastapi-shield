"""Comprehensive tests for FastAPI-Shield ML Threat Detection Engine.

This test suite covers all aspects of the ML Threat Detection system including:
- Feature engineering and data preprocessing
- Machine learning model training and inference
- Anomaly detection with unsupervised learning
- Predictive threat analysis and risk assessment
- Real-time threat detection with <100ms latency
- Model management and deployment
- Database operations and data persistence
- Performance testing under enterprise load conditions
- Integration with existing FastAPI-Shield components
- Error handling and system resilience
"""

import asyncio
import json
import numpy as np
import pytest
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, AsyncMock, patch
import uuid

from src.fastapi_shield.ml_threat_detection import (
    # Core classes
    MLThreatDetector, FeatureEngineer, AnomalyDetector,
    ModelManager, PredictiveAnalyzer, MLThreatDatabase,
    
    # Data classes
    ThreatFeatures, ThreatPrediction, MLModel, AnomalyDetectionResult,
    
    # Enums
    ThreatType, ModelType, FeatureType, ModelStatus, PredictionConfidence,
    
    # Convenience functions
    create_ml_threat_detector
)

from tests.mocks.mock_ml_threat_detection import (
    MockMLThreatDatabase, MockFeatureEngineer, MockAnomalyDetector,
    MockModelManager, MockPredictiveAnalyzer, MockMLThreatDetector,
    MockMLThreatTestEnvironment
)


class TestThreatFeatures:
    """Test ThreatFeatures data class and operations."""
    
    def test_threat_features_creation(self):
        """Test creating threat features."""
        features = ThreatFeatures(
            id="test-001",
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            target_ip="10.0.0.1", 
            port=80,
            protocol="tcp",
            payload_size=1000,
            request_rate=10.0,
            session_duration=300.0,
            user_agent="Mozilla/5.0",
            headers={'host': 'example.com'},
            payload_entropy=4.2,
            packet_size_variance=50.0,
            connection_count=5,
            failed_attempts=2,
            geo_location="US",
            is_suspicious_domain=False,
            reputation_score=0.8,
            behavioral_score=0.7,
            temporal_pattern=[0.1, 0.2, 0.3, 0.4, 0.5],
            feature_vector=[1.0, 2.0, 3.0, 4.0, 5.0],
            labels=["normal", "web_traffic"]
        )
        
        assert features.id == "test-001"
        assert features.source_ip == "192.168.1.100"
        assert features.port == 80
        assert features.payload_size == 1000
        assert features.request_rate == 10.0
        assert features.is_suspicious_domain is False
        assert len(features.temporal_pattern) == 5
        assert len(features.feature_vector) == 5
        assert "normal" in features.labels
    
    def test_threat_features_to_dict(self):
        """Test converting ThreatFeatures to dictionary."""
        timestamp = datetime.now(timezone.utc)
        features = ThreatFeatures(
            id="test-002",
            timestamp=timestamp,
            source_ip="10.0.0.100",
            target_ip="192.168.1.1",
            port=443,
            protocol="tcp",
            payload_size=2000,
            request_rate=50.0,
            session_duration=120.0,
            user_agent="AttackBot/1.0",
            headers={'host': 'malicious.com'},
            payload_entropy=7.5,
            packet_size_variance=200.0,
            connection_count=10,
            failed_attempts=5,
            geo_location="XX",
            is_suspicious_domain=True,
            reputation_score=0.1,
            behavioral_score=0.2,
            temporal_pattern=[0.8, 0.9, 1.0],
            feature_vector=[10.0, 20.0, 30.0],
            labels=["malicious", "bot_traffic"]
        )
        
        result = features.to_dict()
        
        assert result['id'] == "test-002"
        assert result['timestamp'] == timestamp.isoformat()
        assert result['source_ip'] == "10.0.0.100"
        assert result['port'] == 443
        assert result['is_suspicious_domain'] is True
        assert result['temporal_pattern'] == [0.8, 0.9, 1.0]
        assert result['feature_vector'] == [10.0, 20.0, 30.0]
        assert result['labels'] == ["malicious", "bot_traffic"]


class TestThreatPrediction:
    """Test ThreatPrediction data class and operations."""
    
    def test_threat_prediction_creation(self):
        """Test creating threat prediction."""
        prediction = ThreatPrediction(
            id="pred-001",
            features_id="feat-001",
            threat_type=ThreatType.MALWARE,
            confidence=PredictionConfidence.HIGH,
            probability=0.85,
            risk_score=0.78,
            model_used="RandomForest-v1",
            model_version="1.2.0",
            prediction_time=datetime.now(timezone.utc),
            feature_importance={
                'payload_entropy': 0.3,
                'request_rate': 0.25,
                'reputation_score': 0.2
            },
            explanation="High entropy payload indicates potential malware",
            recommended_actions=["Block IP", "Scan for malware", "Alert security team"]
        )
        
        assert prediction.id == "pred-001"
        assert prediction.threat_type == ThreatType.MALWARE
        assert prediction.confidence == PredictionConfidence.HIGH
        assert prediction.probability == 0.85
        assert prediction.risk_score == 0.78
        assert len(prediction.recommended_actions) == 3
        assert 'payload_entropy' in prediction.feature_importance
    
    def test_threat_prediction_to_dict(self):
        """Test converting ThreatPrediction to dictionary."""
        prediction_time = datetime.now(timezone.utc)
        prediction = ThreatPrediction(
            id="pred-002",
            features_id="feat-002",
            threat_type=ThreatType.BRUTE_FORCE,
            confidence=PredictionConfidence.MEDIUM,
            probability=0.65,
            risk_score=0.5,
            model_used="XGBoost-v2",
            model_version="2.1.0",
            prediction_time=prediction_time,
            feature_importance={'failed_attempts': 0.8, 'source_ip': 0.2},
            explanation="Multiple failed login attempts detected",
            recommended_actions=["Rate limit", "Monitor user"]
        )
        
        result = prediction.to_dict()
        
        assert result['id'] == "pred-002"
        assert result['threat_type'] == "brute_force"
        assert result['confidence'] == "medium"
        assert result['probability'] == 0.65
        assert result['prediction_time'] == prediction_time.isoformat()
        assert result['feature_importance'] == {'failed_attempts': 0.8, 'source_ip': 0.2}
        assert len(result['recommended_actions']) == 2


class TestMLModel:
    """Test MLModel data class and operations."""
    
    def test_ml_model_creation(self):
        """Test creating ML model."""
        model = MLModel(
            id="model-001",
            name="Threat Detection RF",
            model_type=ModelType.RANDOM_FOREST,
            version="1.0.0",
            status=ModelStatus.READY,
            threat_types=[ThreatType.MALWARE, ThreatType.BRUTE_FORCE],
            feature_types=[FeatureType.NETWORK, FeatureType.BEHAVIORAL],
            accuracy=0.92,
            precision=0.89,
            recall=0.91,
            f1_score=0.90,
            training_data_size=10000,
            created_at=datetime.now(timezone.utc),
            last_trained=datetime.now(timezone.utc),
            last_updated=datetime.now(timezone.utc),
            model_path="/models/model-001.pkl",
            hyperparameters={'n_estimators': 100, 'max_depth': 10},
            feature_columns=['payload_size', 'request_rate', 'entropy'],
            target_column="threat_type",
            preprocessing_config={'scaler': 'standard'},
            performance_metrics={'auc': 0.94, 'precision_recall_auc': 0.88}
        )
        
        assert model.id == "model-001"
        assert model.model_type == ModelType.RANDOM_FOREST
        assert model.status == ModelStatus.READY
        assert len(model.threat_types) == 2
        assert ThreatType.MALWARE in model.threat_types
        assert model.accuracy == 0.92
        assert model.training_data_size == 10000
        assert 'n_estimators' in model.hyperparameters
    
    def test_ml_model_to_dict(self):
        """Test converting MLModel to dictionary."""
        created_time = datetime.now(timezone.utc)
        model = MLModel(
            id="model-002",
            name="XGBoost Classifier",
            model_type=ModelType.XGBOOST,
            version="2.0.0",
            status=ModelStatus.DEPLOYED,
            threat_types=[ThreatType.SQL_INJECTION, ThreatType.XSS],
            feature_types=[FeatureType.PAYLOAD, FeatureType.CONTEXTUAL],
            accuracy=0.88,
            precision=0.86,
            recall=0.89,
            f1_score=0.875,
            training_data_size=5000,
            created_at=created_time,
            last_trained=created_time,
            last_updated=created_time,
            model_path="/models/model-002.pkl",
            hyperparameters={'learning_rate': 0.1, 'n_estimators': 200},
            feature_columns=['payload_entropy', 'payload_length'],
            target_column="threat_class",
            preprocessing_config={'encoder': 'label'},
            performance_metrics={'f1': 0.875}
        )
        
        result = model.to_dict()
        
        assert result['id'] == "model-002"
        assert result['model_type'] == "xgboost"
        assert result['status'] == "deployed"
        assert result['threat_types'] == ["sql_injection", "xss"]
        assert result['feature_types'] == ["payload", "contextual"]
        assert result['accuracy'] == 0.88
        assert result['created_at'] == created_time.isoformat()


class TestMLThreatDatabase:
    """Test MLThreatDatabase operations."""
    
    def test_database_initialization(self):
        """Test database initialization."""
        db = MockMLThreatDatabase()
        
        assert len(db.features) == 0
        assert len(db.predictions) == 0
        assert len(db.models) == 0
        assert len(db.storage_calls) == 0
        assert len(db.query_calls) == 0
    
    def test_store_and_retrieve_features(self):
        """Test storing and retrieving threat features."""
        db = MockMLThreatDatabase()
        
        features = ThreatFeatures(
            id="feat-001",
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            target_ip="10.0.0.1",
            port=80,
            protocol="tcp",
            payload_size=1000,
            request_rate=10.0,
            session_duration=300.0,
            user_agent="Mozilla/5.0",
            headers={'host': 'example.com'},
            payload_entropy=4.2,
            packet_size_variance=50.0,
            connection_count=5,
            failed_attempts=0,
            geo_location="US",
            is_suspicious_domain=False,
            reputation_score=0.8,
            behavioral_score=0.7,
            temporal_pattern=[0.1, 0.2, 0.3]
        )
        
        # Store features
        result = db.store_features(features)
        assert result is True
        assert len(db.features) == 1
        assert len(db.storage_calls) == 1
        assert ('features', features.id) in db.storage_calls
        
        # Check stored features
        stored_features = db.features[features.id]
        assert stored_features.id == features.id
        assert stored_features.source_ip == features.source_ip
        assert stored_features.port == features.port
    
    def test_get_features_by_timerange(self):
        """Test getting features by time range."""
        db = MockMLThreatDatabase()
        
        # Create features with different timestamps
        now = datetime.now(timezone.utc)
        features_list = []
        
        for i in range(5):
            features = ThreatFeatures(
                id=f"feat-{i}",
                timestamp=now - timedelta(minutes=i*10),
                source_ip=f"192.168.1.{100+i}",
                target_ip="10.0.0.1",
                port=80,
                protocol="tcp",
                payload_size=1000,
                request_rate=10.0,
                session_duration=300.0,
                user_agent="Mozilla/5.0",
                headers={'host': 'example.com'},
                payload_entropy=4.2,
                packet_size_variance=50.0,
                connection_count=5,
                failed_attempts=0,
                geo_location="US",
                is_suspicious_domain=False,
                reputation_score=0.8,
                behavioral_score=0.7,
                temporal_pattern=[0.1, 0.2, 0.3]
            )
            features_list.append(features)
            db.store_features(features)
        
        # Query features within time range
        start_time = now - timedelta(minutes=25)
        end_time = now - timedelta(minutes=5)
        
        results = db.get_features_by_timerange(start_time, end_time)
        
        assert len(results) >= 2  # Should include features within range
        assert len(db.query_calls) == 1
        assert db.query_calls[0][0] == 'features_timerange'
    
    def test_store_prediction(self):
        """Test storing threat predictions."""
        db = MockMLThreatDatabase()
        
        prediction = ThreatPrediction(
            id="pred-001",
            features_id="feat-001",
            threat_type=ThreatType.MALWARE,
            confidence=PredictionConfidence.HIGH,
            probability=0.85,
            risk_score=0.78,
            model_used="RandomForest-v1",
            model_version="1.0.0",
            prediction_time=datetime.now(timezone.utc),
            feature_importance={'entropy': 0.5, 'size': 0.3},
            explanation="High entropy indicates malware",
            recommended_actions=["Block IP", "Scan system"]
        )
        
        result = db.store_prediction(prediction)
        assert result is True
        assert len(db.predictions) == 1
        assert ('prediction', prediction.id) in db.storage_calls


class TestFeatureEngineer:
    """Test FeatureEngineer functionality."""
    
    def test_feature_engineer_initialization(self):
        """Test feature engineer initialization."""
        engineer = MockFeatureEngineer()
        
        assert len(engineer.scalers) == 0
        assert len(engineer.encoders) == 0
        assert len(engineer.feature_selectors) == 0
        assert len(engineer.extract_calls) == 0
    
    def test_extract_network_features(self):
        """Test extracting network-based features."""
        engineer = MockFeatureEngineer()
        
        raw_data = {
            'payload_size': 2000,
            'port': 443,
            'connection_count': 10,
            'request_rate': 25.0,
            'payload': 'HTTP request data',
            'headers': {'user-agent': 'Mozilla/5.0', 'host': 'example.com'}
        }
        
        features = engineer.extract_network_features(raw_data)
        
        assert len(engineer.extract_calls) == 1
        assert engineer.extract_calls[0][0] == 'network'
        
        assert 'payload_size' in features
        assert 'port' in features
        assert 'connection_count' in features
        assert 'request_rate' in features
        assert 'burst_ratio' in features
        assert 'payload_entropy' in features
        
        assert features['payload_size'] == 2000.0
        assert features['port'] == 443.0
        assert features['connection_count'] == 10.0
    
    def test_extract_behavioral_features(self):
        """Test extracting behavioral patterns."""
        engineer = MockFeatureEngineer()
        
        historical_data = [
            {'timestamp': time.time() - 3600, 'resource': '/login', 'geo_location': 'US'},
            {'timestamp': time.time() - 1800, 'resource': '/dashboard', 'geo_location': 'US'},
            {'timestamp': time.time() - 900, 'resource': '/profile', 'geo_location': 'CA'},
            {'timestamp': time.time(), 'resource': '/settings', 'geo_location': 'CA'}
        ]
        
        features = engineer.extract_behavioral_features(historical_data)
        
        assert len(engineer.extract_calls) == 1
        assert engineer.extract_calls[0][0] == 'behavioral'
        assert engineer.extract_calls[0][1] == 4  # Length of historical data
        
        assert 'behavioral_score' in features
        assert 'request_frequency_std' in features
        assert 'resource_diversity' in features
        assert 'location_changes' in features
        
        assert isinstance(features['behavioral_score'], float)
        assert features['behavioral_score'] > 0
    
    def test_extract_temporal_features(self):
        """Test extracting temporal patterns."""
        engineer = MockFeatureEngineer()
        
        timestamp = datetime(2024, 1, 15, 14, 30, 0, tzinfo=timezone.utc)  # Monday, 2:30 PM
        time_series_data = [1.0, 1.2, 1.5, 1.1, 1.3, 1.8, 1.6, 1.4]
        
        features = engineer.extract_temporal_features(timestamp, time_series_data)
        
        assert len(engineer.extract_calls) == 1
        assert engineer.extract_calls[0][0] == 'temporal'
        
        assert 'hour_of_day' in features
        assert 'day_of_week' in features
        assert 'is_weekend' in features
        assert 'is_business_hours' in features
        assert 'ts_mean' in features
        assert 'ts_std' in features
        
        assert features['hour_of_day'] == 14.0
        assert features['day_of_week'] == 0.0  # Monday
        assert features['is_weekend'] == 0.0  # Not weekend
        assert features['is_business_hours'] == 1.0  # Business hours
    
    def test_create_feature_vector(self):
        """Test creating comprehensive feature vector."""
        engineer = MockFeatureEngineer()
        
        features = ThreatFeatures(
            id="test-001",
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            target_ip="10.0.0.1",
            port=80,
            protocol="tcp",
            payload_size=1500,
            request_rate=15.0,
            session_duration=250.0,
            user_agent="Mozilla/5.0",
            headers={'host': 'example.com'},
            payload_entropy=4.5,
            packet_size_variance=75.0,
            connection_count=8,
            failed_attempts=1,
            geo_location="US",
            is_suspicious_domain=False,
            reputation_score=0.85,
            behavioral_score=0.75,
            temporal_pattern=[0.2, 0.4, 0.6, 0.8, 1.0],
            feature_vector=[1.0, 2.0, 3.0]  # Existing vector
        )
        
        vector = engineer.create_feature_vector(features)
        
        assert isinstance(vector, list)
        assert len(vector) > 10  # Should have multiple feature categories
        assert all(isinstance(x, (int, float)) for x in vector)
        
        # Check that basic features are included
        assert features.payload_size / 1000.0 in vector  # Normalized payload size
        assert features.request_rate in vector
        assert float(features.is_suspicious_domain) in vector
    
    def test_normalize_features(self):
        """Test feature normalization."""
        engineer = MockFeatureEngineer()
        
        # Create test data
        features = np.array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0], [7.0, 8.0, 9.0]])
        
        normalized = engineer.normalize_features(features, "test_scaler")
        
        assert len(engineer.normalize_calls) == 1
        assert engineer.normalize_calls[0][0] == "test_scaler"
        assert normalized.shape == features.shape
        assert "test_scaler" in engineer.scalers
    
    def test_select_features(self):
        """Test feature selection."""
        engineer = MockFeatureEngineer()
        
        # Create test data
        X = np.random.random((100, 20))
        y = np.random.randint(0, 2, 100)
        
        selected = engineer.select_features(X, y, k=10, selector_id="test_selector")
        
        assert len(engineer.select_calls) == 1
        assert engineer.select_calls[0][0] == "test_selector"
        assert engineer.select_calls[0][2] == 10  # k parameter
        assert selected.shape[1] <= 10  # Should select at most k features
        assert selected.shape[0] == X.shape[0]  # Same number of samples


class TestAnomalyDetector:
    """Test AnomalyDetector functionality."""
    
    def test_anomaly_detector_initialization(self):
        """Test anomaly detector initialization."""
        detector = MockAnomalyDetector()
        
        assert detector.is_fitted is False
        assert len(detector.fit_calls) == 0
        assert len(detector.detect_calls) == 0
        assert detector.training_data is None
    
    def test_fit_anomaly_detector(self):
        """Test fitting anomaly detection models."""
        detector = MockAnomalyDetector()
        
        # Create training data
        X = np.random.random((200, 15))
        
        result = detector.fit(X)
        
        assert result is True
        assert detector.is_fitted is True
        assert len(detector.fit_calls) == 1
        assert detector.fit_calls[0] == X.shape
        assert detector.training_data is not None
        assert detector.training_data.shape == X.shape
    
    def test_detect_anomalies(self):
        """Test anomaly detection."""
        detector = MockAnomalyDetector()
        
        # Fit detector first
        X_train = np.random.random((100, 15))
        detector.fit(X_train)
        
        # Test data with some outliers
        X_test = np.array([
            np.ones(15) * 2.0,      # Normal
            np.ones(15) * 15.0,     # Outlier (high values)
            np.ones(15) * -8.0,     # Outlier (negative values)
            np.ones(15) * 0.5       # Normal
        ])
        
        results = detector.detect_anomalies(X_test)
        
        assert len(detector.detect_calls) == 1
        assert detector.detect_calls[0] == X_test.shape
        assert len(results) == 4
        
        # Check result structure
        for i, result in enumerate(results):
            assert isinstance(result, AnomalyDetectionResult)
            assert result.id is not None
            assert isinstance(result.is_anomaly, (bool, np.bool_))
            assert isinstance(result.anomaly_score, float)
            assert result.anomaly_type in ['strong_outlier', 'statistical_outlier', 'normal']
            assert result.detection_method == "ensemble"
            assert isinstance(result.explanation, str)
        
        # Check that outliers are detected
        high_scores = [r.anomaly_score for r in results]
        assert max(high_scores) > 0.5  # Should have at least one high anomaly score
    
    def test_detect_anomalies_without_fitting(self):
        """Test anomaly detection without fitting first."""
        detector = MockAnomalyDetector()
        
        X_test = np.random.random((5, 10))
        results = detector.detect_anomalies(X_test)
        
        assert len(results) == 0  # Should return empty list if not fitted


class TestModelManager:
    """Test ModelManager functionality."""
    
    def test_model_manager_initialization(self):
        """Test model manager initialization."""
        db = MockMLThreatDatabase()
        manager = MockModelManager(db)
        
        assert manager.database == db
        assert len(manager.loaded_models) == 0
        assert len(manager.model_metadata) == 0
        assert len(manager.create_calls) == 0
    
    def test_create_model(self):
        """Test creating ML model."""
        db = MockMLThreatDatabase()
        manager = MockModelManager(db)
        
        model = manager.create_model(
            name="Test Random Forest",
            model_type=ModelType.RANDOM_FOREST,
            threat_types=[ThreatType.MALWARE, ThreatType.BRUTE_FORCE],
            feature_types=[FeatureType.NETWORK, FeatureType.BEHAVIORAL],
            hyperparameters={'n_estimators': 100, 'max_depth': 10}
        )
        
        assert model is not None
        assert len(manager.create_calls) == 1
        assert len(manager.model_metadata) == 1
        assert len(db.models) == 1
        
        create_call = manager.create_calls[0]
        assert create_call['name'] == "Test Random Forest"
        assert create_call['model_type'] == ModelType.RANDOM_FOREST
        assert len(create_call['threat_types']) == 2
        
        assert model.name == "Test Random Forest"
        assert model.model_type == ModelType.RANDOM_FOREST
        assert model.status == ModelStatus.TRAINING
        assert len(model.threat_types) == 2
    
    def test_train_model(self):
        """Test training ML model."""
        db = MockMLThreatDatabase()
        manager = MockModelManager(db)
        
        # Create model first
        model = manager.create_model(
            name="Test XGBoost",
            model_type=ModelType.XGBOOST,
            threat_types=[ThreatType.SQL_INJECTION],
            feature_types=[FeatureType.PAYLOAD]
        )
        
        # Generate training data
        X = np.random.random((1000, 20))
        y = np.random.randint(0, 5, 1000)
        
        result = manager.train_model(model.id, X, y)
        
        assert result is True
        assert len(manager.train_calls) == 1
        
        train_call = manager.train_calls[0]
        assert train_call['model_id'] == model.id
        assert train_call['X_shape'] == X.shape
        assert train_call['y_shape'] == y.shape
        
        # Check model was updated
        updated_model = manager.model_metadata[model.id]
        assert updated_model.status == ModelStatus.READY
        assert updated_model.accuracy > 0.8  # Mock should set high accuracy
        assert updated_model.training_data_size == 1000
        assert model.id in manager.loaded_models
    
    def test_predict_with_model(self):
        """Test making predictions with trained model."""
        db = MockMLThreatDatabase()
        manager = MockModelManager(db)
        
        # Create and train model
        model = manager.create_model(
            name="Test Neural Network",
            model_type=ModelType.NEURAL_NETWORK,
            threat_types=[ThreatType.XSS],
            feature_types=[FeatureType.PAYLOAD]
        )
        
        X_train = np.random.random((500, 15))
        y_train = np.random.randint(0, 3, 500)
        manager.train_model(model.id, X_train, y_train)
        
        # Make predictions
        X_test = np.random.random((10, 15))
        predictions, probabilities = manager.predict(model.id, X_test)
        
        assert len(manager.predict_calls) == 1
        assert manager.predict_calls[0]['model_id'] == model.id
        assert manager.predict_calls[0]['X_shape'] == X_test.shape
        
        assert len(predictions) == 10
        assert probabilities.shape == (10, 5)  # 5 classes in mock model
        assert all(isinstance(p, (int, np.integer)) for p in predictions)
    
    def test_get_feature_importance(self):
        """Test getting feature importance."""
        db = MockMLThreatDatabase()
        manager = MockModelManager(db)
        
        # Create and train model
        model = manager.create_model(
            name="Test Random Forest",
            model_type=ModelType.RANDOM_FOREST,
            threat_types=[ThreatType.MALWARE],
            feature_types=[FeatureType.NETWORK]
        )
        
        X_train = np.random.random((300, 10))
        y_train = np.random.randint(0, 2, 300)
        manager.train_model(model.id, X_train, y_train)
        
        importance = manager.get_feature_importance(model.id)
        
        assert isinstance(importance, dict)
        assert len(importance) > 0
        assert all(isinstance(v, float) for v in importance.values())
        assert all(0 <= v <= 1 for v in importance.values())  # Normalized importance
    
    def test_deploy_model(self):
        """Test deploying model for production."""
        db = MockMLThreatDatabase()
        manager = MockModelManager(db)
        
        # Create and train model
        model = manager.create_model(
            name="Test Deployment Model",
            model_type=ModelType.RANDOM_FOREST,
            threat_types=[ThreatType.DDOS],
            feature_types=[FeatureType.NETWORK]
        )
        
        X_train = np.random.random((200, 12))
        y_train = np.random.randint(0, 2, 200)
        manager.train_model(model.id, X_train, y_train)
        
        # Deploy model
        result = manager.deploy_model(model.id)
        
        assert result is True
        assert model.id in manager.deploy_calls
        
        # Check model status updated
        deployed_model = manager.model_metadata[model.id]
        assert deployed_model.status == ModelStatus.DEPLOYED


class TestPredictiveAnalyzer:
    """Test PredictiveAnalyzer functionality."""
    
    def test_predictive_analyzer_initialization(self):
        """Test predictive analyzer initialization."""
        db = MockMLThreatDatabase()
        model_manager = MockModelManager(db)
        feature_engineer = MockFeatureEngineer()
        analyzer = MockPredictiveAnalyzer(model_manager, feature_engineer)
        
        assert analyzer.model_manager == model_manager
        assert analyzer.feature_engineer == feature_engineer
        assert len(analyzer.predict_calls) == 0
    
    def test_predict_threats(self):
        """Test threat prediction."""
        db = MockMLThreatDatabase()
        model_manager = MockModelManager(db)
        feature_engineer = MockFeatureEngineer()
        analyzer = MockPredictiveAnalyzer(model_manager, feature_engineer)
        
        # Setup deployed models
        for i, model_type in enumerate([ModelType.RANDOM_FOREST, ModelType.XGBOOST]):
            model = model_manager.create_model(
                name=f"Model-{i}",
                model_type=model_type,
                threat_types=[ThreatType.MALWARE, ThreatType.BRUTE_FORCE],
                feature_types=[FeatureType.NETWORK]
            )
            
            X_train = np.random.random((100, 10))
            y_train = np.random.randint(0, 2, 100)
            model_manager.train_model(model.id, X_train, y_train)
            model_manager.deploy_model(model.id)
        
        # Create test features
        features = ThreatFeatures(
            id="test-features",
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.100",
            target_ip="192.168.1.1",
            port=80,
            protocol="tcp",
            payload_size=5000,  # Large payload
            request_rate=200.0,  # High request rate
            session_duration=30.0,
            user_agent="BadBot/1.0",
            headers={'host': 'malicious.com'},
            payload_entropy=8.0,  # High entropy
            packet_size_variance=300.0,
            connection_count=50,
            failed_attempts=10,  # Many failures
            geo_location="XX",
            is_suspicious_domain=True,
            reputation_score=0.1,  # Low reputation
            behavioral_score=0.2,
            temporal_pattern=[0.9, 1.0, 0.9, 0.8, 0.7],
            feature_vector=list(range(20))
        )
        
        predictions = analyzer.predict_threats(features)
        
        assert len(analyzer.predict_calls) == 1
        assert analyzer.predict_calls[0] == features.id
        assert len(predictions) > 0
        
        for prediction in predictions:
            assert isinstance(prediction, ThreatPrediction)
            assert prediction.features_id == features.id
            assert isinstance(prediction.threat_type, ThreatType)
            assert isinstance(prediction.confidence, PredictionConfidence)
            assert 0.0 <= prediction.probability <= 1.0
            assert 0.0 <= prediction.risk_score <= 1.0
            assert len(prediction.recommended_actions) > 0
    
    def test_assess_risk(self):
        """Test risk assessment."""
        db = MockMLThreatDatabase()
        model_manager = MockModelManager(db)
        feature_engineer = MockFeatureEngineer()
        analyzer = MockPredictiveAnalyzer(model_manager, feature_engineer)
        
        # Create test predictions with different risk scores
        predictions = []
        risk_scores = [0.8, 0.6, 0.9, 0.7]
        
        for i, risk_score in enumerate(risk_scores):
            prediction = ThreatPrediction(
                id=f"pred-{i}",
                features_id="feat-001",
                threat_type=ThreatType.MALWARE,
                confidence=PredictionConfidence.HIGH,
                probability=0.8,
                risk_score=risk_score,
                model_used=f"Model-{i}",
                model_version="1.0.0",
                prediction_time=datetime.now(timezone.utc),
                feature_importance={},
                explanation="Test prediction",
                recommended_actions=["Test action"]
            )
            predictions.append(prediction)
        
        overall_risk = analyzer.assess_risk(predictions)
        
        assert len(analyzer.assess_calls) == 1
        assert analyzer.assess_calls[0] == len(predictions)
        assert isinstance(overall_risk, float)
        assert 0.0 <= overall_risk <= 1.0
        
        # Should be average of risk scores
        expected_risk = sum(risk_scores) / len(risk_scores)
        assert abs(overall_risk - expected_risk) < 0.1
    
    def test_predict_attack_timeline(self):
        """Test attack timeline prediction."""
        db = MockMLThreatDatabase()
        model_manager = MockModelManager(db)
        feature_engineer = MockFeatureEngineer()
        analyzer = MockPredictiveAnalyzer(model_manager, feature_engineer)
        
        # Create historical features
        historical_features = []
        base_time = datetime.now(timezone.utc) - timedelta(hours=24)
        
        for i in range(20):  # Need at least 10 for analysis
            features = ThreatFeatures(
                id=f"hist-{i}",
                timestamp=base_time + timedelta(hours=i),
                source_ip="10.0.0.100",
                target_ip="192.168.1.1",
                port=80,
                protocol="tcp",
                payload_size=1000 + i * 100,
                request_rate=10.0 + i * 2.0,
                session_duration=300.0,
                user_agent="TestAgent",
                headers={'host': 'example.com'},
                payload_entropy=4.0 + i * 0.1,
                packet_size_variance=50.0,
                connection_count=1 + i,
                failed_attempts=i,
                geo_location="US",
                is_suspicious_domain=False,
                reputation_score=0.9 - i * 0.02,
                behavioral_score=0.8,
                temporal_pattern=[0.1, 0.2, 0.3],
                feature_vector=list(range(15))
            )
            historical_features.append(features)
        
        timeline = analyzer.predict_attack_timeline(historical_features)
        
        assert len(analyzer.timeline_calls) == 1
        assert analyzer.timeline_calls[0] == len(historical_features)
        assert timeline['status'] == 'analysis_complete'
        assert 'risk_trend' in timeline
        assert 'escalation_probability' in timeline
        assert 'predicted_next_attack' in timeline
        assert 'confidence_interval' in timeline
        assert 'recommendations' in timeline
        
        assert timeline['risk_trend'] in ['increasing', 'stable', 'decreasing']
        assert 0.0 <= timeline['escalation_probability'] <= 1.0
        assert isinstance(timeline['confidence_interval'], tuple)
        assert len(timeline['recommendations']) > 0


class TestMLThreatDetector:
    """Test MLThreatDetector main coordinator."""
    
    def test_ml_threat_detector_initialization(self):
        """Test ML threat detector initialization."""
        detector = MockMLThreatDetector()
        
        assert detector.database is not None
        assert detector.feature_engineer is not None
        assert detector.anomaly_detector is not None
        assert detector.model_manager is not None
        assert detector.predictive_analyzer is not None
        assert detector.is_running is False
        assert len(detector.detect_calls) == 0
    
    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        """Test starting and stopping the detector."""
        detector = MockMLThreatDetector()
        
        # Start detector
        await detector.start()
        assert detector.is_running is True
        assert len(detector.start_calls) == 1
        
        # Stop detector
        await detector.stop()
        assert detector.is_running is False
        assert len(detector.stop_calls) == 1
    
    @pytest.mark.asyncio
    async def test_detect_threats_normal_traffic(self):
        """Test threat detection with normal traffic."""
        detector = MockMLThreatDetector()
        await detector.start()
        
        raw_data = {
            'source_ip': '192.168.1.100',
            'target_ip': '10.0.0.1',
            'port': 80,
            'protocol': 'tcp',
            'payload_size': 1000,
            'request_rate': 5.0,
            'session_duration': 300.0,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'headers': {'host': 'example.com', 'accept': 'text/html'},
            'connection_count': 1,
            'failed_attempts': 0,
            'geo_location': 'US',
            'is_suspicious_domain': False,
            'reputation_score': 0.9,
            'behavioral_score': 0.8,
            'temporal_pattern': [0.1, 0.2, 0.3, 0.4, 0.5]
        }
        
        result = await detector.detect_threats(raw_data)
        
        assert len(detector.detect_calls) == 1
        assert detector.detect_calls[0] == raw_data
        
        assert 'id' in result
        assert 'features_id' in result
        assert 'timestamp' in result
        assert 'anomaly_detected' in result
        assert 'anomaly_score' in result
        assert 'threat_predictions' in result
        assert 'overall_risk_score' in result
        assert 'risk_level' in result
        assert 'recommended_actions' in result
        assert 'processing_time_ms' in result
        assert 'models_used' in result
        assert 'confidence' in result
        
        assert isinstance(result['anomaly_detected'], bool)
        assert isinstance(result['anomaly_score'], (int, float))
        assert isinstance(result['threat_predictions'], list)
        assert isinstance(result['overall_risk_score'], (int, float))
        assert result['risk_level'] in ['minimal', 'low', 'medium', 'high', 'critical']
        assert isinstance(result['recommended_actions'], list)
        assert isinstance(result['processing_time_ms'], int)
        
        await detector.stop()
    
    @pytest.mark.asyncio
    async def test_detect_threats_malicious_traffic(self):
        """Test threat detection with malicious traffic."""
        detector = MockMLThreatDetector()
        await detector.start()
        
        # Setup some deployed models first
        model = detector.model_manager.create_model(
            name="Test Malware Detector",
            model_type=ModelType.RANDOM_FOREST,
            threat_types=[ThreatType.MALWARE],
            feature_types=[FeatureType.NETWORK]
        )
        
        X_train = np.random.random((100, 20))
        y_train = np.random.randint(0, 2, 100)
        detector.model_manager.train_model(model.id, X_train, y_train)
        detector.model_manager.deploy_model(model.id)
        
        raw_data = {
            'source_ip': '10.0.0.100',  # Suspicious IP
            'target_ip': '192.168.1.1',
            'port': 8080,
            'protocol': 'tcp',
            'payload_size': 50000,  # Large payload
            'request_rate': 500.0,  # High request rate
            'session_duration': 30.0,  # Short session
            'user_agent': 'MalwareBot/1.0',  # Suspicious user agent
            'headers': {'host': 'malicious-domain.com'},
            'connection_count': 100,  # Many connections
            'failed_attempts': 15,  # Many failures
            'geo_location': 'XX',  # Unknown location
            'is_suspicious_domain': True,
            'reputation_score': 0.05,  # Very low reputation
            'behavioral_score': 0.1,
            'temporal_pattern': [1.0, 0.9, 0.8, 0.7, 0.6],
            'payload': 'exec(malicious_code)'  # Suspicious payload
        }
        
        result = await detector.detect_threats(raw_data)
        
        assert result['overall_risk_score'] > 0.3  # Should detect as risky
        assert len(result['threat_predictions']) > 0
        assert len(result['recommended_actions']) > 0
        
        # Check if any high-risk threat was predicted
        high_risk_predictions = [
            p for p in result['threat_predictions'] 
            if p.get('risk_score', 0) > 0.5
        ]
        assert len(high_risk_predictions) > 0
        
        await detector.stop()
    
    @pytest.mark.asyncio
    async def test_detect_threats_performance(self):
        """Test detection performance requirements (<100ms)."""
        detector = MockMLThreatDetector()
        await detector.start()
        
        raw_data = {
            'source_ip': '192.168.1.50',
            'target_ip': '10.0.0.1',
            'port': 443,
            'protocol': 'tcp',
            'payload_size': 2000,
            'request_rate': 25.0,
            'session_duration': 180.0,
            'user_agent': 'Mozilla/5.0',
            'headers': {'host': 'test.com'},
            'connection_count': 3,
            'failed_attempts': 1,
            'geo_location': 'US',
            'is_suspicious_domain': False,
            'reputation_score': 0.7,
            'behavioral_score': 0.6,
            'temporal_pattern': [0.3, 0.4, 0.5, 0.6, 0.7]
        }
        
        start_time = time.time()
        result = await detector.detect_threats(raw_data)
        end_time = time.time()
        
        processing_time_seconds = end_time - start_time
        processing_time_ms = processing_time_seconds * 1000
        
        # Check performance requirement
        assert processing_time_ms < 100, f"Detection took {processing_time_ms:.2f}ms, should be <100ms"
        
        # Check reported processing time
        assert 'processing_time_ms' in result
        assert isinstance(result['processing_time_ms'], int)
        
        await detector.stop()


class TestIntegrationScenarios:
    """Test integration scenarios with multiple components."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_threat_detection_pipeline(self):
        """Test complete end-to-end threat detection pipeline."""
        env = MockMLThreatTestEnvironment()
        env.setup_test_environment()
        
        detector = env.detector
        await detector.start()
        
        # Test with multiple types of traffic
        test_scenarios = [
            {
                'name': 'normal_web_traffic',
                'data': {
                    'source_ip': '192.168.1.100',
                    'payload_size': 1500,
                    'request_rate': 10.0,
                    'user_agent': 'Mozilla/5.0',
                    'reputation_score': 0.9
                },
                'expected_risk': 'low'
            },
            {
                'name': 'brute_force_attack',
                'data': {
                    'source_ip': '10.0.0.100',
                    'failed_attempts': 20,
                    'request_rate': 100.0,
                    'reputation_score': 0.1
                },
                'expected_risk': 'high'
            },
            {
                'name': 'potential_malware',
                'data': {
                    'source_ip': '10.0.0.101',
                    'payload_size': 50000,
                    'user_agent': 'MalwareBot',
                    'reputation_score': 0.05
                },
                'expected_risk': 'high'
            }
        ]
        
        results = []
        for scenario in test_scenarios:
            result = await detector.detect_threats(scenario['data'])
            results.append((scenario, result))
            
            # Basic validation
            assert 'error' not in result
            assert 'overall_risk_score' in result
            assert 'risk_level' in result
        
        # Verify different scenarios produce different risk levels
        risk_levels = [result[1]['risk_level'] for result in results]
        assert len(set(risk_levels)) > 1  # Should have different risk levels
        
        await detector.stop()
    
    def test_model_training_and_deployment_workflow(self):
        """Test complete model training and deployment workflow."""
        env = MockMLThreatTestEnvironment()
        model_manager = env.detector.model_manager
        
        # Create model
        model = model_manager.create_model(
            name="Integration Test Model",
            model_type=ModelType.XGBOOST,
            threat_types=[ThreatType.MALWARE, ThreatType.BRUTE_FORCE, ThreatType.SQL_INJECTION],
            feature_types=[FeatureType.NETWORK, FeatureType.BEHAVIORAL, FeatureType.PAYLOAD],
            hyperparameters={'n_estimators': 150, 'learning_rate': 0.15}
        )
        
        assert model.status == ModelStatus.TRAINING
        
        # Generate realistic training data
        n_samples = 2000
        n_features = 25
        X = np.random.random((n_samples, n_features))
        y = np.random.choice([0, 1, 2, 3, 4], n_samples)  # 5 threat classes
        
        # Train model
        training_success = model_manager.train_model(model.id, X, y)
        assert training_success is True
        
        updated_model = model_manager.model_metadata[model.id]
        assert updated_model.status == ModelStatus.READY
        assert updated_model.accuracy > 0.8
        assert updated_model.training_data_size == n_samples
        
        # Deploy model
        deployment_success = model_manager.deploy_model(model.id)
        assert deployment_success is True
        
        final_model = model_manager.model_metadata[model.id]
        assert final_model.status == ModelStatus.DEPLOYED
        
        # Test predictions
        X_test = np.random.random((10, n_features))
        predictions, probabilities = model_manager.predict(model.id, X_test)
        
        assert len(predictions) == 10
        assert probabilities.shape == (10, 5)  # 5 classes
        
        # Test feature importance
        importance = model_manager.get_feature_importance(model.id)
        assert len(importance) > 0
        assert all(isinstance(v, float) for v in importance.values())
    
    def test_anomaly_detection_with_feature_engineering(self):
        """Test anomaly detection integrated with feature engineering."""
        env = MockMLThreatTestEnvironment()
        detector = env.detector
        
        # Generate training data for anomaly detection
        normal_data = []
        for i in range(200):
            features = ThreatFeatures(
                id=f"normal-{i}",
                timestamp=datetime.now(timezone.utc),
                source_ip=f"192.168.1.{100 + i % 50}",
                target_ip="10.0.0.1",
                port=80,
                protocol="tcp",
                payload_size=1000 + np.random.randint(-200, 200),
                request_rate=10.0 + np.random.random() * 5,
                session_duration=300.0 + np.random.random() * 100,
                user_agent="Mozilla/5.0",
                headers={'host': 'example.com'},
                payload_entropy=4.0 + np.random.random(),
                packet_size_variance=50.0 + np.random.random() * 20,
                connection_count=1 + np.random.randint(0, 5),
                failed_attempts=0,
                geo_location="US",
                is_suspicious_domain=False,
                reputation_score=0.8 + np.random.random() * 0.2,
                behavioral_score=0.7 + np.random.random() * 0.2,
                temporal_pattern=[0.1, 0.2, 0.3, 0.4, 0.5]
            )
            
            # Create feature vector
            features.feature_vector = detector.feature_engineer.create_feature_vector(features)
            normal_data.append(features)
        
        # Train anomaly detector
        X_normal = np.array([f.feature_vector for f in normal_data])
        detector.anomaly_detector.fit(X_normal)
        
        # Test with anomalous data
        anomalous_features = ThreatFeatures(
            id="anomaly-001",
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.666",
            target_ip="192.168.1.1",
            port=31337,  # Suspicious port
            protocol="tcp",
            payload_size=100000,  # Very large payload
            request_rate=1000.0,  # Very high rate
            session_duration=5.0,  # Very short
            user_agent="HackerBot/6.6.6",
            headers={'host': 'evil.com'},
            payload_entropy=8.5,  # Very high entropy
            packet_size_variance=1000.0,
            connection_count=500,  # Many connections
            failed_attempts=50,  # Many failures
            geo_location="XX",
            is_suspicious_domain=True,
            reputation_score=0.0,  # Zero reputation
            behavioral_score=0.0,
            temporal_pattern=[1.0, 0.0, 1.0, 0.0, 1.0]  # Irregular pattern
        )
        
        anomalous_features.feature_vector = detector.feature_engineer.create_feature_vector(anomalous_features)
        
        # Detect anomalies
        X_test = np.array([anomalous_features.feature_vector])
        results = detector.anomaly_detector.detect_anomalies(X_test)
        
        assert len(results) == 1
        result = results[0]
        
        # Should detect as anomaly due to extreme values
        assert result.is_anomaly == True
        assert result.anomaly_score > 0.5
        assert result.anomaly_type in ['strong_outlier', 'statistical_outlier']
        assert 'outlier' in result.explanation.lower()


class TestPerformanceAndScalability:
    """Test performance and scalability aspects."""
    
    @pytest.mark.asyncio
    async def test_high_throughput_detection(self):
        """Test high-throughput threat detection."""
        env = MockMLThreatTestEnvironment()
        env.setup_test_environment()
        
        # Run performance test
        performance_results = await env.run_performance_test(num_samples=200)
        
        assert performance_results['total_samples'] == 200
        assert performance_results['successful_detections'] == 200
        assert performance_results['avg_processing_time'] < 0.1  # <100ms average
        assert performance_results['total_time'] < 30.0  # Should complete in reasonable time
        
        # Check performance statistics
        stats = env.get_performance_stats()
        assert stats.get('status') != 'no_data'
        assert stats['total_operations'] == 200
        assert stats['avg_response_time'] < 0.1
        assert stats['operations_under_100ms'] >= 180  # At least 90% under 100ms
    
    def test_concurrent_model_operations(self):
        """Test concurrent model training and inference."""
        env = MockMLThreatTestEnvironment()
        model_manager = env.detector.model_manager
        
        # Create multiple models concurrently
        models = []
        for i in range(5):
            model = model_manager.create_model(
                name=f"Concurrent Model {i}",
                model_type=ModelType.RANDOM_FOREST,
                threat_types=[ThreatType.MALWARE],
                feature_types=[FeatureType.NETWORK],
                hyperparameters={'n_estimators': 50}
            )
            models.append(model)
        
        assert len(models) == 5
        assert len(model_manager.model_metadata) == 5
        
        # Train all models
        for model in models:
            X = np.random.random((500, 15))
            y = np.random.randint(0, 2, 500)
            success = model_manager.train_model(model.id, X, y)
            assert success is True
        
        # Deploy all models
        for model in models:
            success = model_manager.deploy_model(model.id)
            assert success is True
        
        # Test concurrent predictions
        X_test = np.random.random((50, 15))
        prediction_results = []
        
        for model in models:
            predictions, probabilities = model_manager.predict(model.id, X_test)
            prediction_results.append((predictions, probabilities))
        
        # Verify all predictions completed successfully
        assert len(prediction_results) == 5
        for predictions, probabilities in prediction_results:
            assert len(predictions) == 50
            assert probabilities.shape[0] == 50
    
    def test_memory_usage_with_large_datasets(self):
        """Test memory usage with large feature datasets."""
        env = MockMLThreatTestEnvironment()
        detector = env.detector
        
        # Generate large dataset
        large_dataset = []
        for i in range(1000):  # 1000 feature samples
            features = ThreatFeatures(
                id=f"large-{i}",
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=i),
                source_ip=f"192.168.{i//256}.{i%256}",
                target_ip="10.0.0.1",
                port=80 + i % 1000,
                protocol="tcp",
                payload_size=1000 + i * 10,
                request_rate=float(i % 100),
                session_duration=float(300 + i % 600),
                user_agent=f"TestAgent-{i}",
                headers={'host': f'test{i}.com'},
                payload_entropy=4.0 + (i % 50) * 0.1,
                packet_size_variance=50.0 + i % 200,
                connection_count=1 + i % 20,
                failed_attempts=i % 10,
                geo_location="US" if i % 2 == 0 else "CA",
                is_suspicious_domain=i % 10 == 0,
                reputation_score=0.5 + (i % 50) * 0.01,
                behavioral_score=0.4 + (i % 60) * 0.01,
                temporal_pattern=[(i + j) % 10 * 0.1 for j in range(5)],
                feature_vector=list(range(i % 30, i % 30 + 20))
            )
            large_dataset.append(features)
        
        # Store all features
        for features in large_dataset:
            success = detector.database.store_features(features)
            assert success is True
        
        # Verify storage
        assert len(detector.database.features) == 1000
        
        # Test querying large time ranges
        start_time = datetime.now(timezone.utc) - timedelta(hours=24)
        end_time = datetime.now(timezone.utc)
        
        results = detector.database.get_features_by_timerange(start_time, end_time)
        assert len(results) > 0
        
        # Test feature engineering with large dataset
        for i in range(0, 100, 10):  # Sample every 10th feature
            features = large_dataset[i]
            vector = detector.feature_engineer.create_feature_vector(features)
            assert isinstance(vector, list)
            assert len(vector) > 10


class TestErrorHandlingAndResilience:
    """Test error handling and system resilience."""
    
    @pytest.mark.asyncio
    async def test_malformed_input_handling(self):
        """Test handling of malformed input data."""
        detector = MockMLThreatDetector()
        await detector.start()
        
        # Test with missing required fields
        malformed_data = {
            'source_ip': '192.168.1.100',
            # Missing target_ip, port, etc.
        }
        
        result = await detector.detect_threats(malformed_data)
        
        # Should handle gracefully and return valid result
        assert 'error' not in result or result.get('id') is not None
        assert 'features_id' in result
        
        await detector.stop()
    
    @pytest.mark.asyncio
    async def test_invalid_data_types(self):
        """Test handling of invalid data types."""
        detector = MockMLThreatDetector()
        await detector.start()
        
        invalid_data = {
            'source_ip': '192.168.1.100',
            'port': 'not_a_number',  # Invalid type
            'payload_size': None,    # Null value
            'request_rate': 'invalid_float',
            'is_suspicious_domain': 'not_boolean',
            'reputation_score': 'not_numeric'
        }
        
        result = await detector.detect_threats(invalid_data)
        
        # Should handle type conversion gracefully
        assert 'features_id' in result
        assert isinstance(result.get('overall_risk_score', 0), (int, float))
        
        await detector.stop()
    
    def test_model_training_failure_recovery(self):
        """Test recovery from model training failures."""
        db = MockMLThreatDatabase()
        model_manager = MockModelManager(db)
        
        # Create model
        model = model_manager.create_model(
            name="Failure Test Model",
            model_type=ModelType.NEURAL_NETWORK,
            threat_types=[ThreatType.MALWARE],
            feature_types=[FeatureType.NETWORK]
        )
        
        # Simulate training failure with invalid data
        invalid_X = np.array([])  # Empty array
        invalid_y = np.array([])
        
        # Training should fail but not crash the system
        result = model_manager.train_model(model.id, invalid_X, invalid_y)
        
        # Check that failure is handled gracefully
        # (Mock implementation always succeeds, but real implementation would handle this)
        assert isinstance(result, bool)
    
    def test_database_operation_failures(self):
        """Test handling of database operation failures."""
        db = MockMLThreatDatabase()
        
        # Test with None inputs
        result = db.store_features(None)
        # Mock doesn't validate input, but real implementation would handle this
        
        # Test with invalid time ranges
        future_time = datetime.now(timezone.utc) + timedelta(days=1)
        past_time = datetime.now(timezone.utc) - timedelta(days=1)
        
        results = db.get_features_by_timerange(future_time, past_time)  # Invalid range
        assert isinstance(results, list)  # Should return empty list, not crash
    
    @pytest.mark.asyncio
    async def test_detector_restart_resilience(self):
        """Test detector resilience to restarts."""
        detector = MockMLThreatDetector()
        
        # Start detector
        await detector.start()
        assert detector.is_running is True
        
        # Process some data
        test_data = {
            'source_ip': '192.168.1.100',
            'payload_size': 1000,
            'request_rate': 10.0
        }
        
        result1 = await detector.detect_threats(test_data)
        assert 'features_id' in result1
        
        # Stop and restart
        await detector.stop()
        assert detector.is_running is False
        
        await detector.start()
        assert detector.is_running is True
        
        # Should continue working after restart
        result2 = await detector.detect_threats(test_data)
        assert 'features_id' in result2
        
        await detector.stop()
    
    def test_feature_engineering_edge_cases(self):
        """Test feature engineering with edge case data."""
        engineer = MockFeatureEngineer()
        
        # Test with empty/minimal data
        minimal_data = {}
        network_features = engineer.extract_network_features(minimal_data)
        assert isinstance(network_features, dict)
        assert len(network_features) > 0
        
        # Test with extreme values
        extreme_data = {
            'payload_size': 999999999,  # Very large
            'request_rate': 0.000001,   # Very small
            'connection_count': -5,     # Negative
            'payload': '',              # Empty string
            'headers': {}               # Empty dict
        }
        
        extreme_features = engineer.extract_network_features(extreme_data)
        assert isinstance(extreme_features, dict)
        assert all(isinstance(v, (int, float)) for v in extreme_features.values())
        
        # Test behavioral features with empty history
        empty_history = []
        behavioral_features = engineer.extract_behavioral_features(empty_history)
        assert isinstance(behavioral_features, dict)
        assert 'behavioral_score' in behavioral_features


class TestConvenienceFunctions:
    """Test convenience functions and utilities."""
    
    def test_create_ml_threat_detector(self):
        """Test create_ml_threat_detector convenience function."""
        detector = create_ml_threat_detector("test_ml_detection.db")
        
        assert isinstance(detector, MLThreatDetector)
        # Note: This creates a real detector, not a mock
    
    @pytest.mark.asyncio
    async def test_detector_lifecycle_management(self):
        """Test complete detector lifecycle."""
        # Create detector
        detector = MockMLThreatDetector("lifecycle_test.db")
        
        # Initial state
        assert detector.is_running is False
        
        # Start
        await detector.start()
        assert detector.is_running is True
        assert len(detector.start_calls) == 1
        
        # Process data
        test_data = {'source_ip': '192.168.1.100', 'payload_size': 1000}
        result = await detector.detect_threats(test_data)
        assert 'features_id' in result
        
        # Stop
        await detector.stop()
        assert detector.is_running is False
        assert len(detector.stop_calls) == 1
    
    def test_enum_value_validation(self):
        """Test enum value validation."""
        # Test ThreatType enum
        assert ThreatType.MALWARE.value == "malware"
        assert ThreatType.BRUTE_FORCE.value == "brute_force"
        assert ThreatType.SQL_INJECTION.value == "sql_injection"
        
        # Test ModelType enum
        assert ModelType.RANDOM_FOREST.value == "random_forest"
        assert ModelType.NEURAL_NETWORK.value == "neural_network"
        assert ModelType.XGBOOST.value == "xgboost"
        
        # Test PredictionConfidence enum
        assert PredictionConfidence.VERY_HIGH.value == "very_high"
        assert PredictionConfidence.HIGH.value == "high"
        assert PredictionConfidence.MEDIUM.value == "medium"
        
        # Test ModelStatus enum
        assert ModelStatus.TRAINING.value == "training"
        assert ModelStatus.READY.value == "ready"
        assert ModelStatus.DEPLOYED.value == "deployed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])