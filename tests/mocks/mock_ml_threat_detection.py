"""Mock infrastructure for ML Threat Detection Engine testing."""

import asyncio
import json
import numpy as np
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, AsyncMock
import uuid

from src.fastapi_shield.ml_threat_detection import (
    ThreatFeatures, ThreatPrediction, MLModel, AnomalyDetectionResult,
    ThreatType, ModelType, FeatureType, ModelStatus, PredictionConfidence
)


class MockMLThreatDatabase:
    """Mock ML threat database for testing."""
    
    def __init__(self):
        self.features = {}
        self.predictions = {}
        self.models = {}
        self.anomalies = {}
        self.training_data = []
        self.storage_calls = []
        self.query_calls = []
        
    def store_features(self, features: ThreatFeatures) -> bool:
        """Mock store features."""
        if features is None:
            return False
        self.storage_calls.append(('features', features.id))
        self.features[features.id] = features
        return True
    
    def store_prediction(self, prediction: ThreatPrediction) -> bool:
        """Mock store prediction."""
        self.storage_calls.append(('prediction', prediction.id))
        self.predictions[prediction.id] = prediction
        return True
    
    def store_model(self, model: MLModel) -> bool:
        """Mock store model."""
        self.storage_calls.append(('model', model.id))
        self.models[model.id] = model
        return True
    
    def get_features_by_timerange(self, start_time: datetime, end_time: datetime) -> List[ThreatFeatures]:
        """Mock get features by time range."""
        self.query_calls.append(('features_timerange', start_time, end_time))
        
        results = []
        for features in self.features.values():
            if start_time <= features.timestamp <= end_time:
                results.append(features)
        
        return sorted(results, key=lambda x: x.timestamp, reverse=True)


class MockFeatureEngineer:
    """Mock feature engineer for testing."""
    
    def __init__(self):
        self.scalers = {}
        self.encoders = {}
        self.feature_selectors = {}
        self.extract_calls = []
        self.normalize_calls = []
        self.select_calls = []
    
    def extract_network_features(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        """Mock extract network features."""
        self.extract_calls.append(('network', raw_data))
        
        return {
            'payload_size': float(raw_data.get('payload_size', 0)),
            'port': float(raw_data.get('port', 80)),
            'connection_count': float(raw_data.get('connection_count', 1)),
            'request_rate': float(raw_data.get('request_rate', 1.0)),
            'burst_ratio': 1.5,
            'payload_entropy': 4.2,
            'payload_ascii_ratio': 0.95,
            'payload_contains_suspicious': 0.0,
            'header_count': 8.0,
            'has_suspicious_headers': 0.0,
            'user_agent_entropy': 3.8
        }
    
    def extract_behavioral_features(self, historical_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """Mock extract behavioral features."""
        self.extract_calls.append(('behavioral', len(historical_data)))
        
        if not historical_data:
            return {'behavioral_score': 0.0}
        
        return {
            'behavioral_score': 0.7,
            'request_frequency_std': 1.2,
            'time_regularity': 0.8,
            'resource_diversity': 0.6,
            'location_changes': 0,
            'location_entropy': 2.1,
            'avg_session_duration': 300.0,
            'session_duration_variance': 50.0,
            'total_failures': 2,
            'failure_rate': 0.1
        }
    
    def extract_temporal_features(self, timestamp: datetime, time_series_data: List[float]) -> Dict[str, float]:
        """Mock extract temporal features."""
        self.extract_calls.append(('temporal', timestamp))
        
        return {
            'hour_of_day': float(timestamp.hour),
            'day_of_week': float(timestamp.weekday()),
            'is_weekend': float(timestamp.weekday() >= 5),
            'is_business_hours': float(9 <= timestamp.hour <= 17),
            'ts_mean': 0.5,
            'ts_std': 0.2,
            'ts_skew': 0.1,
            'ts_kurtosis': -0.3,
            'trend_slope': 0.05,
            'autocorrelation': 0.3,
            'outlier_count': 1.0,
            'sudden_changes': 2.0
        }
    
    def create_feature_vector(self, features: ThreatFeatures) -> List[float]:
        """Mock create feature vector."""
        # Generate realistic feature vector based on input features
        # Handle None values gracefully
        base_vector = [
            (features.payload_size or 0) / 1000.0,
            features.request_rate or 0.0,
            (features.session_duration or 0) / 100.0,
            features.payload_entropy or 0.0,
            features.packet_size_variance or 0.0,
            features.connection_count or 0,
            features.failed_attempts or 0,
            features.reputation_score or 0.0,
            features.behavioral_score or 0.0
        ]
        
        # Add some derived features
        derived_features = [
            float(features.port or 80) / 65535.0,
            float(features.is_suspicious_domain or False),
            0.5,  # geo_location encoded
            0.8, 0.6, 0.4  # temporal features
        ]
        
        # Add statistical features
        if features.feature_vector:
            existing = np.array(features.feature_vector)
            stats = [np.mean(existing), np.std(existing), np.min(existing), np.max(existing)]
        else:
            stats = [0.5, 0.2, 0.0, 1.0]
        
        return base_vector + derived_features + stats
    
    def normalize_features(self, features: np.ndarray, scaler_id: str = "default") -> np.ndarray:
        """Mock normalize features."""
        self.normalize_calls.append((scaler_id, features.shape))
        
        # Simple mock normalization (subtract mean, divide by std)
        if scaler_id not in self.scalers:
            self.scalers[scaler_id] = {'mean': np.mean(features, axis=0), 'std': np.std(features, axis=0)}
        
        scaler = self.scalers[scaler_id]
        return (features - scaler['mean']) / (scaler['std'] + 1e-8)
    
    def select_features(self, X: np.ndarray, y: np.ndarray, k: int = 20, selector_id: str = "default") -> np.ndarray:
        """Mock select features."""
        self.select_calls.append((selector_id, X.shape, k))
        
        # Return first k features
        return X[:, :min(k, X.shape[1])]


class MockAnomalyDetector:
    """Mock anomaly detector for testing."""
    
    def __init__(self):
        self.isolation_forest = None
        self.one_class_svm = None
        self.dbscan = None
        self.is_fitted = False
        self.fit_calls = []
        self.detect_calls = []
        self.training_data = None
    
    def fit(self, X: np.ndarray) -> bool:
        """Mock fit anomaly detection models."""
        self.fit_calls.append(X.shape)
        self.training_data = X.copy()
        self.is_fitted = True
        return True
    
    def detect_anomalies(self, X: np.ndarray) -> List[AnomalyDetectionResult]:
        """Mock detect anomalies."""
        self.detect_calls.append(X.shape)
        
        if not self.is_fitted:
            return []
        
        results = []
        for i in range(len(X)):
            # Generate mock results based on data
            feature_sum = np.sum(X[i])
            is_anomaly = feature_sum > 10.0 or feature_sum < -5.0  # Simple threshold
            
            anomaly_score = abs(feature_sum - 5.0) / 10.0
            
            # Determine anomaly type based on score
            if anomaly_score > 0.8:
                anomaly_type = "strong_outlier"
            elif anomaly_score > 0.5:
                anomaly_type = "statistical_outlier"
            else:
                anomaly_type = "normal"
            
            result = AnomalyDetectionResult(
                id=str(uuid.uuid4()),
                features_id="",  # Will be set by caller
                is_anomaly=is_anomaly,
                anomaly_score=anomaly_score,
                anomaly_type=anomaly_type,
                detection_method="ensemble",
                timestamp=datetime.now(timezone.utc),
                explanation=f"Detected as {anomaly_type} outlier based on feature analysis (sum: {feature_sum:.2f})",
                related_patterns=[]
            )
            results.append(result)
        
        return results


class MockModelManager:
    """Mock model manager for testing."""
    
    def __init__(self, database):
        self.database = database
        self.models_dir = "mock_models"
        self.loaded_models = {}
        self.model_metadata = {}
        self.create_calls = []
        self.train_calls = []
        self.predict_calls = []
        self.deploy_calls = []
    
    def create_model(self, name: str, model_type: ModelType,
                    threat_types: List[ThreatType],
                    feature_types: List[FeatureType],
                    hyperparameters: Dict[str, Any] = None) -> MLModel:
        """Mock create model."""
        self.create_calls.append({
            'name': name,
            'model_type': model_type,
            'threat_types': threat_types,
            'feature_types': feature_types,
            'hyperparameters': hyperparameters
        })
        
        model_id = str(uuid.uuid4())
        model = MLModel(
            id=model_id,
            name=name,
            model_type=model_type,
            version="1.0.0",
            status=ModelStatus.TRAINING,
            threat_types=threat_types,
            feature_types=feature_types,
            accuracy=0.0,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            training_data_size=0,
            created_at=datetime.now(timezone.utc),
            last_trained=datetime.now(timezone.utc),
            last_updated=datetime.now(timezone.utc),
            model_path=f"mock_models/{model_id}.pkl",
            hyperparameters=hyperparameters or {},
            feature_columns=[],
            target_column="threat_type",
            preprocessing_config={},
            performance_metrics={}
        )
        
        self.model_metadata[model_id] = model
        self.database.store_model(model)
        return model
    
    def train_model(self, model_id: str, X: np.ndarray, y: np.ndarray) -> bool:
        """Mock train model."""
        self.train_calls.append({
            'model_id': model_id,
            'X_shape': X.shape,
            'y_shape': y.shape
        })
        
        model = self.model_metadata.get(model_id)
        if not model:
            return False
        
        # Mock training results
        model.accuracy = 0.85 + np.random.random() * 0.1  # 0.85-0.95
        model.precision = 0.82 + np.random.random() * 0.15  # 0.82-0.97
        model.recall = 0.80 + np.random.random() * 0.15  # 0.80-0.95
        model.f1_score = 2 * (model.precision * model.recall) / (model.precision + model.recall)
        model.training_data_size = len(X)
        model.status = ModelStatus.READY
        model.last_trained = datetime.now(timezone.utc)
        model.last_updated = datetime.now(timezone.utc)
        
        # Create mock model for predictions
        self.loaded_models[model_id] = MockSklearnModel(model.model_type)
        
        self.database.store_model(model)
        return True
    
    def predict(self, model_id: str, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Mock predict."""
        self.predict_calls.append({
            'model_id': model_id,
            'X_shape': X.shape
        })
        
        if model_id not in self.loaded_models:
            return np.array([]), np.array([])
        
        mock_model = self.loaded_models[model_id]
        predictions = mock_model.predict(X)
        probabilities = mock_model.predict_proba(X)
        
        return predictions, probabilities
    
    def get_feature_importance(self, model_id: str) -> Dict[str, float]:
        """Mock get feature importance."""
        if model_id not in self.loaded_models:
            return {}
        
        # Generate mock feature importance
        features = [
            'payload_size', 'request_rate', 'session_duration', 'payload_entropy',
            'connection_count', 'failed_attempts', 'reputation_score', 'behavioral_score'
        ]
        
        importance = np.random.random(len(features))
        importance = importance / np.sum(importance)  # Normalize to sum to 1
        
        return dict(zip(features, importance.tolist()))
    
    def deploy_model(self, model_id: str) -> bool:
        """Mock deploy model."""
        self.deploy_calls.append(model_id)
        
        model = self.model_metadata.get(model_id)
        if not model or model.status != ModelStatus.READY:
            return False
        
        model.status = ModelStatus.DEPLOYED
        model.last_updated = datetime.now(timezone.utc)
        self.database.store_model(model)
        
        return True


class MockSklearnModel:
    """Mock sklearn-compatible model for testing."""
    
    def __init__(self, model_type: ModelType):
        self.model_type = model_type
        self.feature_importances_ = None
        self.coef_ = None
        self.classes_ = np.array([0, 1, 2, 3, 4])  # Mock classes
        
        # Set appropriate attributes based on model type
        if model_type in [ModelType.RANDOM_FOREST, ModelType.XGBOOST]:
            self.feature_importances_ = np.random.random(20)
            self.feature_importances_ = self.feature_importances_ / np.sum(self.feature_importances_)
        elif model_type == ModelType.NEURAL_NETWORK:
            self.coef_ = [np.random.random((20, 10)), np.random.random((10, 5))]
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Mock predict method."""
        # Generate predictions based on input features
        predictions = []
        for i in range(len(X)):
            feature_sum = np.sum(X[i])
            # Map feature sum to threat type
            if feature_sum > 8:
                pred = 1  # Malware
            elif feature_sum > 6:
                pred = 2  # Brute force
            elif feature_sum > 4:
                pred = 3  # SQL injection
            elif feature_sum > 2:
                pred = 4  # DDoS
            else:
                pred = 0  # Normal/anomalous behavior
            
            predictions.append(pred)
        
        return np.array(predictions)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Mock predict_proba method."""
        predictions = self.predict(X)
        probabilities = []
        
        for pred in predictions:
            # Create probability distribution with highest prob for predicted class
            probs = np.random.random(5) * 0.2  # Base probabilities
            probs[pred] = 0.6 + np.random.random() * 0.3  # High prob for predicted class
            probs = probs / np.sum(probs)  # Normalize
            probabilities.append(probs)
        
        return np.array(probabilities)
    
    def fit(self, X, y):
        """Mock fit method."""
        return self


class MockPredictiveAnalyzer:
    """Mock predictive analyzer for testing."""
    
    def __init__(self, model_manager, feature_engineer):
        self.model_manager = model_manager
        self.feature_engineer = feature_engineer
        self.predict_calls = []
        self.assess_calls = []
        self.timeline_calls = []
        
    def predict_threats(self, features: ThreatFeatures) -> List[ThreatPrediction]:
        """Mock predict threats."""
        self.predict_calls.append(features.id)
        
        predictions = []
        
        # Get deployed models
        deployed_models = [
            model for model in self.model_manager.model_metadata.values()
            if model.status == ModelStatus.DEPLOYED
        ]
        
        if not deployed_models:
            return predictions
        
        for model in deployed_models[:3]:  # Limit to 3 models for testing
            # Create mock prediction based on features
            feature_sum = sum(features.feature_vector) if features.feature_vector else 5.0
            
            # Determine threat type based on feature characteristics
            if features.failed_attempts > 3:
                threat_type = ThreatType.BRUTE_FORCE
                probability = 0.8
            elif features.payload_entropy > 6.0:
                threat_type = ThreatType.MALWARE
                probability = 0.9
            elif 'script' in features.user_agent.lower() or features.payload_size > 10000:
                threat_type = ThreatType.XSS
                probability = 0.7
            elif features.request_rate > 100:
                threat_type = ThreatType.DDOS
                probability = 0.85
            else:
                threat_type = ThreatType.ANOMALOUS_BEHAVIOR
                probability = 0.6
            
            # Determine confidence based on probability
            if probability >= 0.9:
                confidence = PredictionConfidence.VERY_HIGH
            elif probability >= 0.8:
                confidence = PredictionConfidence.HIGH
            elif probability >= 0.6:
                confidence = PredictionConfidence.MEDIUM
            else:
                confidence = PredictionConfidence.LOW
            
            # Calculate risk score
            risk_score = probability * 0.8  # Threat severity factor
            
            prediction = ThreatPrediction(
                id=str(uuid.uuid4()),
                features_id=features.id,
                threat_type=threat_type,
                confidence=confidence,
                probability=probability,
                risk_score=risk_score,
                model_used=model.name,
                model_version=model.version,
                prediction_time=datetime.now(timezone.utc),
                feature_importance={
                    'request_rate': 0.3,
                    'payload_entropy': 0.25,
                    'failed_attempts': 0.2,
                    'reputation_score': 0.15,
                    'behavioral_score': 0.1
                },
                explanation=f"Predicted {threat_type.value} based on feature analysis",
                recommended_actions=self._generate_mock_actions(threat_type, risk_score)
            )
            
            predictions.append(prediction)
        
        return predictions
    
    def assess_risk(self, predictions: List[ThreatPrediction]) -> float:
        """Mock assess risk."""
        self.assess_calls.append(len(predictions))
        
        if not predictions:
            return 0.0
        
        # Weighted average of risk scores
        total_risk = sum(p.risk_score for p in predictions)
        return total_risk / len(predictions)
    
    def predict_attack_timeline(self, historical_features: List[ThreatFeatures]) -> Dict[str, Any]:
        """Mock predict attack timeline."""
        self.timeline_calls.append(len(historical_features))
        
        if len(historical_features) < 10:
            return {'status': 'insufficient_data'}
        
        # Mock timeline analysis
        risk_scores = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.7, 0.6, 0.8, 0.9]  # Mock increasing trend
        trend = np.polyfit(range(len(risk_scores)), risk_scores, 1)[0]
        
        return {
            'status': 'analysis_complete',
            'risk_trend': 'increasing' if trend > 0.01 else 'stable',
            'escalation_probability': 0.75,
            'predicted_next_attack': (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
            'confidence_interval': (0.6, 0.9),
            'recommendations': ['Enhance monitoring', 'Review security policies', 'Prepare incident response']
        }
    
    def _generate_mock_actions(self, threat_type: ThreatType, risk_score: float) -> List[str]:
        """Generate mock recommended actions."""
        actions = []
        
        if risk_score >= 0.8:
            actions.append("Immediate investigation required")
            actions.append("Consider blocking suspicious IP addresses")
        elif risk_score >= 0.6:
            actions.append("Enhanced monitoring recommended")
        
        threat_actions = {
            ThreatType.MALWARE: ["Run anti-malware scan", "Isolate affected systems"],
            ThreatType.BRUTE_FORCE: ["Implement rate limiting", "Review authentication logs"],
            ThreatType.XSS: ["Check web application security", "Update content filtering"],
            ThreatType.DDOS: ["Activate DDoS protection", "Monitor network capacity"],
            ThreatType.ANOMALOUS_BEHAVIOR: ["Continue monitoring", "Review user behavior"]
        }
        
        actions.extend(threat_actions.get(threat_type, []))
        return actions


class MockMLThreatDetector:
    """Mock ML threat detector for testing."""
    
    def __init__(self, db_path: str = "mock_ml_threat_detection.db"):
        self.database = MockMLThreatDatabase()
        self.feature_engineer = MockFeatureEngineer()
        self.anomaly_detector = MockAnomalyDetector()
        self.model_manager = MockModelManager(self.database)
        self.predictive_analyzer = MockPredictiveAnalyzer(self.model_manager, self.feature_engineer)
        
        self.processing_queue = asyncio.Queue()
        self.prediction_cache = {}
        self.cache_ttl = 300
        
        self.is_running = False
        self.detect_calls = []
        self.start_calls = []
        self.stop_calls = []
    
    async def start(self):
        """Mock start method."""
        self.start_calls.append(datetime.now(timezone.utc))
        self.is_running = True
    
    async def stop(self):
        """Mock stop method."""
        self.stop_calls.append(datetime.now(timezone.utc))
        self.is_running = False
    
    async def detect_threats(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mock detect threats."""
        self.detect_calls.append(raw_data.copy())
        
        start_time = time.time()
        
        # Extract features
        features = self._extract_mock_features(raw_data)
        self.database.store_features(features)
        
        # Mock anomaly detection
        feature_vector = self.feature_engineer.create_feature_vector(features)
        X = np.array([feature_vector])
        
        # Fit anomaly detector if not fitted
        if not self.anomaly_detector.is_fitted:
            # Generate some training data
            training_data = np.random.random((100, len(feature_vector)))
            self.anomaly_detector.fit(training_data)
        
        anomaly_results = self.anomaly_detector.detect_anomalies(X)
        for result in anomaly_results:
            result.features_id = features.id
        
        # Mock threat predictions
        predictions = self.predictive_analyzer.predict_threats(features)
        
        # Store predictions
        for prediction in predictions:
            self.database.store_prediction(prediction)
        
        # Calculate overall risk
        overall_risk = self.predictive_analyzer.assess_risk(predictions)
        
        processing_time = int((time.time() - start_time) * 1000)
        
        result = {
            'id': str(uuid.uuid4()),
            'features_id': features.id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'anomaly_detected': any(a.is_anomaly for a in anomaly_results),
            'anomaly_score': max([a.anomaly_score for a in anomaly_results]) if anomaly_results else 0.0,
            'threat_predictions': [p.to_dict() for p in predictions],
            'overall_risk_score': overall_risk,
            'risk_level': self._classify_risk_level(overall_risk),
            'recommended_actions': self._compile_recommendations(predictions),
            'processing_time_ms': processing_time,
            'models_used': len(predictions),
            'confidence': self._calculate_overall_confidence(predictions)
        }
        
        return result
    
    def _extract_mock_features(self, raw_data: Dict[str, Any]) -> ThreatFeatures:
        """Extract mock features from raw data."""
        
        # Helper function to safely convert to numeric values
        def safe_int(value, default=0):
            try:
                return int(value) if value is not None else default
            except (ValueError, TypeError):
                return default
        
        def safe_float(value, default=0.0):
            try:
                return float(value) if value is not None else default
            except (ValueError, TypeError):
                return default
        
        def safe_bool(value, default=False):
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() in ('true', '1', 'yes', 'on')
            try:
                return bool(value) if value is not None else default
            except (ValueError, TypeError):
                return default
        
        features = ThreatFeatures(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source_ip=str(raw_data.get('source_ip', '192.168.1.100')),
            target_ip=str(raw_data.get('target_ip', '10.0.0.1')),
            port=safe_int(raw_data.get('port'), 80),
            protocol=str(raw_data.get('protocol', 'tcp')),
            payload_size=safe_int(raw_data.get('payload_size'), 1000),
            request_rate=safe_float(raw_data.get('request_rate'), 10.0),
            session_duration=safe_float(raw_data.get('session_duration'), 300.0),
            user_agent=str(raw_data.get('user_agent', 'Mozilla/5.0')),
            headers=raw_data.get('headers', {'host': 'example.com'}) if isinstance(raw_data.get('headers'), dict) else {'host': 'example.com'},
            payload_entropy=safe_float(raw_data.get('payload_entropy'), 4.2),
            packet_size_variance=safe_float(raw_data.get('packet_size_variance'), 100.0),
            connection_count=safe_int(raw_data.get('connection_count'), 5),
            failed_attempts=safe_int(raw_data.get('failed_attempts'), 0),
            geo_location=str(raw_data.get('geo_location', 'US')),
            is_suspicious_domain=safe_bool(raw_data.get('is_suspicious_domain'), False),
            reputation_score=safe_float(raw_data.get('reputation_score'), 0.8),
            behavioral_score=safe_float(raw_data.get('behavioral_score'), 0.7),
            temporal_pattern=raw_data.get('temporal_pattern', [0.1, 0.2, 0.3, 0.4, 0.5]) if isinstance(raw_data.get('temporal_pattern'), list) else [0.1, 0.2, 0.3, 0.4, 0.5]
        )
        
        # Generate feature vector
        features.feature_vector = self.feature_engineer.create_feature_vector(features)
        
        return features
    
    def _classify_risk_level(self, risk_score: float) -> str:
        """Mock classify risk level."""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "minimal"
    
    def _compile_recommendations(self, predictions: List[ThreatPrediction]) -> List[str]:
        """Mock compile recommendations."""
        all_recommendations = []
        for prediction in predictions:
            all_recommendations.extend(prediction.recommended_actions)
        
        return list(set(all_recommendations))  # Remove duplicates
    
    def _calculate_overall_confidence(self, predictions: List[ThreatPrediction]) -> str:
        """Mock calculate overall confidence."""
        if not predictions:
            return "none"
        
        confidence_scores = {
            PredictionConfidence.VERY_LOW: 1,
            PredictionConfidence.LOW: 2,
            PredictionConfidence.MEDIUM: 3,
            PredictionConfidence.HIGH: 4,
            PredictionConfidence.VERY_HIGH: 5
        }
        
        avg_confidence = np.mean([confidence_scores[p.confidence] for p in predictions])
        
        if avg_confidence >= 4.5:
            return "very_high"
        elif avg_confidence >= 3.5:
            return "high"
        elif avg_confidence >= 2.5:
            return "medium"
        elif avg_confidence >= 1.5:
            return "low"
        else:
            return "very_low"


class MockMLThreatTestEnvironment:
    """Comprehensive mock environment for ML threat detection testing."""
    
    def __init__(self):
        self.detector = MockMLThreatDetector()
        
        # Test data
        self.test_features = self._generate_test_features()
        self.test_raw_data = self._generate_test_raw_data()
        self.test_models = self._generate_test_models()
        
        # Performance tracking
        self.performance_metrics = {
            'detection_calls': [],
            'response_times': [],
            'accuracy_scores': []
        }
    
    def _generate_test_features(self) -> List[ThreatFeatures]:
        """Generate test threat features."""
        features_list = []
        
        # Normal traffic
        for i in range(50):
            features = ThreatFeatures(
                id=f"normal-{i}",
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=i),
                source_ip=f"192.168.1.{100 + i % 50}",
                target_ip="10.0.0.1",
                port=80,
                protocol="tcp",
                payload_size=500 + i * 10,
                request_rate=1.0 + i * 0.1,
                session_duration=300.0,
                user_agent="Mozilla/5.0",
                headers={'host': 'example.com'},
                payload_entropy=4.0,
                packet_size_variance=50.0,
                connection_count=1,
                failed_attempts=0,
                geo_location="US",
                is_suspicious_domain=False,
                reputation_score=0.9,
                behavioral_score=0.8,
                temporal_pattern=[0.1, 0.2, 0.3, 0.4, 0.5]
            )
            features.feature_vector = list(range(20))  # Mock feature vector
            features_list.append(features)
        
        # Malicious traffic
        threat_types = [ThreatType.MALWARE, ThreatType.BRUTE_FORCE, ThreatType.SQL_INJECTION, ThreatType.XSS, ThreatType.DDOS]
        
        for i, threat_type in enumerate(threat_types):
            for j in range(10):
                features = ThreatFeatures(
                    id=f"{threat_type.value}-{j}",
                    timestamp=datetime.now(timezone.utc) - timedelta(minutes=j),
                    source_ip=f"10.0.{i}.{j + 1}",
                    target_ip="192.168.1.1",
                    port=80 + i * 100,
                    protocol="tcp",
                    payload_size=2000 + j * 100,
                    request_rate=50.0 + j * 5.0,
                    session_duration=60.0,
                    user_agent="BadBot/1.0" if threat_type == ThreatType.MALWARE else "Mozilla/5.0",
                    headers={'host': 'malicious.com'} if threat_type == ThreatType.MALWARE else {'host': 'example.com'},
                    payload_entropy=7.5 if threat_type == ThreatType.MALWARE else 4.0,
                    packet_size_variance=200.0,
                    connection_count=10 + j,
                    failed_attempts=5 + j if threat_type == ThreatType.BRUTE_FORCE else 0,
                    geo_location="XX",
                    is_suspicious_domain=True,
                    reputation_score=0.1,
                    behavioral_score=0.2,
                    temporal_pattern=[0.8, 0.9, 1.0, 0.9, 0.8]
                )
                features.feature_vector = [float(x * (i + 1)) for x in range(20)]  # Mock feature vector
                features.labels = [threat_type.value]
                features_list.append(features)
        
        return features_list
    
    def _generate_test_raw_data(self) -> List[Dict[str, Any]]:
        """Generate test raw data samples."""
        raw_data_list = []
        
        # Normal requests
        for i in range(20):
            raw_data = {
                'source_ip': f'192.168.1.{100 + i}',
                'target_ip': '10.0.0.1',
                'port': 80,
                'protocol': 'tcp',
                'payload_size': 500,
                'request_rate': 1.0,
                'session_duration': 300.0,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'headers': {'host': 'example.com', 'accept': 'text/html'},
                'payload': 'GET / HTTP/1.1',
                'connection_count': 1,
                'failed_attempts': 0,
                'geo_location': 'US',
                'is_suspicious_domain': False,
                'reputation_score': 0.9,
                'behavioral_score': 0.8,
                'temporal_pattern': [0.1, 0.2, 0.3, 0.4, 0.5]
            }
            raw_data_list.append(raw_data)
        
        # Malicious requests
        malicious_samples = [
            {
                'source_ip': '10.0.0.100',
                'payload_size': 5000,
                'request_rate': 100.0,
                'failed_attempts': 10,
                'user_agent': 'AttackBot/1.0',
                'reputation_score': 0.1,
                'payload': 'SELECT * FROM users WHERE id=1 OR 1=1'
            },
            {
                'source_ip': '10.0.0.101', 
                'payload_size': 10000,
                'request_rate': 200.0,
                'user_agent': 'script alert(1)',
                'payload': '<script>alert("XSS")</script>',
                'reputation_score': 0.05
            },
            {
                'source_ip': '10.0.0.102',
                'request_rate': 1000.0,
                'connection_count': 100,
                'payload_size': 50,
                'reputation_score': 0.0
            }
        ]
        
        for malicious in malicious_samples:
            # Merge with base data
            base_data = raw_data_list[0].copy()
            base_data.update(malicious)
            raw_data_list.append(base_data)
        
        return raw_data_list
    
    def _generate_test_models(self) -> List[Dict[str, Any]]:
        """Generate test model configurations."""
        models = []
        
        model_configs = [
            {
                'name': 'Random Forest Threat Detector',
                'model_type': ModelType.RANDOM_FOREST,
                'threat_types': [ThreatType.MALWARE, ThreatType.BRUTE_FORCE],
                'feature_types': [FeatureType.NETWORK, FeatureType.BEHAVIORAL],
                'hyperparameters': {'n_estimators': 100, 'max_depth': 10}
            },
            {
                'name': 'XGBoost Anomaly Detector',
                'model_type': ModelType.XGBOOST,
                'threat_types': [ThreatType.ANOMALOUS_BEHAVIOR, ThreatType.ZERO_DAY],
                'feature_types': [FeatureType.STATISTICAL, FeatureType.TEMPORAL],
                'hyperparameters': {'n_estimators': 200, 'learning_rate': 0.1}
            },
            {
                'name': 'Neural Network Classifier',
                'model_type': ModelType.NEURAL_NETWORK,
                'threat_types': [ThreatType.SQL_INJECTION, ThreatType.XSS],
                'feature_types': [FeatureType.PAYLOAD, FeatureType.CONTEXTUAL],
                'hyperparameters': {'hidden_layer_sizes': (100, 50), 'max_iter': 1000}
            }
        ]
        
        for config in model_configs:
            models.append(config)
        
        return models
    
    def setup_test_environment(self):
        """Setup complete test environment with models and data."""
        # Create and train test models
        for model_config in self.test_models:
            model = self.detector.model_manager.create_model(**model_config)
            
            # Generate training data
            X = np.random.random((1000, 20))  # 1000 samples, 20 features
            y = np.random.randint(0, 5, 1000)  # 5 classes
            
            # Train model
            success = self.detector.model_manager.train_model(model.id, X, y)
            if success:
                self.detector.model_manager.deploy_model(model.id)
        
        # Add test features to database
        for features in self.test_features:
            self.detector.database.store_features(features)
    
    def track_performance(self, operation: str, duration: float, accuracy: float = None):
        """Track performance metrics."""
        self.performance_metrics['detection_calls'].append({
            'operation': operation,
            'timestamp': time.time(),
            'duration': duration
        })
        
        self.performance_metrics['response_times'].append(duration)
        
        if accuracy is not None:
            self.performance_metrics['accuracy_scores'].append(accuracy)
    
    async def run_performance_test(self, num_samples: int = 100) -> Dict[str, Any]:
        """Run performance test with multiple samples."""
        await self.detector.start()
        
        start_time = time.time()
        results = []
        
        for i in range(num_samples):
            # Use test raw data cyclically
            raw_data = self.test_raw_data[i % len(self.test_raw_data)]
            
            detection_start = time.time()
            result = await self.detector.detect_threats(raw_data)
            detection_time = time.time() - detection_start
            
            results.append(result)
            self.track_performance('detect_threats', detection_time)
        
        total_time = time.time() - start_time
        
        await self.detector.stop()
        
        return {
            'total_samples': num_samples,
            'total_time': total_time,
            'avg_processing_time': total_time / num_samples,
            'successful_detections': len([r for r in results if 'error' not in r]),
            'anomalies_detected': len([r for r in results if r.get('anomaly_detected', False)]),
            'threat_predictions': sum(len(r.get('threat_predictions', [])) for r in results),
            'avg_response_time': np.mean(self.performance_metrics['response_times']) if self.performance_metrics['response_times'] else 0
        }
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        response_times = self.performance_metrics['response_times']
        
        if not response_times:
            return {'status': 'no_data'}
        
        return {
            'total_operations': len(response_times),
            'avg_response_time': np.mean(response_times),
            'max_response_time': np.max(response_times),
            'min_response_time': np.min(response_times),
            'p95_response_time': np.percentile(response_times, 95),
            'p99_response_time': np.percentile(response_times, 99),
            'operations_under_100ms': len([t for t in response_times if t < 0.1]),
            'accuracy_scores': self.performance_metrics['accuracy_scores']
        }
    
    def reset(self):
        """Reset the test environment."""
        self.detector = MockMLThreatDetector()
        self.performance_metrics = {
            'detection_calls': [],
            'response_times': [],
            'accuracy_scores': []
        }


# Export all mock classes
__all__ = [
    'MockMLThreatDatabase',
    'MockFeatureEngineer', 
    'MockAnomalyDetector',
    'MockModelManager',
    'MockSklearnModel',
    'MockPredictiveAnalyzer',
    'MockMLThreatDetector',
    'MockMLThreatTestEnvironment'
]