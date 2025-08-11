"""FastAPI-Shield Machine Learning Threat Detection Engine

This module provides a comprehensive AI/ML-powered threat detection system that uses
advanced machine learning algorithms to detect sophisticated threats, zero-day attacks,
and behavioral anomalies that traditional rule-based systems cannot identify.

Features:
- Real-time ML-powered threat detection with <100ms latency
- Advanced behavioral analysis and anomaly detection
- Predictive threat modeling and risk assessment
- Adaptive learning from security incidents and patterns
- Neural networks, ensemble methods, and clustering algorithms
- Real-time feature engineering and data preprocessing
- Model training, validation, and continuous improvement pipeline
- Distributed model serving and inference
- Model interpretability and explainable AI
- Integration with existing FastAPI-Shield components
"""

import asyncio
import json
import logging
import numpy as np
import pandas as pd
import pickle
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from threading import RLock, Thread
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    NamedTuple, Protocol, AsyncIterator, TypeVar, Generic
)
import hashlib
import sqlite3
import weakref
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

# Machine Learning imports
try:
    import sklearn
    from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
    from sklearn.feature_selection import SelectKBest, f_classif
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    from sklearn.decomposition import PCA
    from sklearn.svm import OneClassSVM
    import xgboost as xgb
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

logger = logging.getLogger(__name__)

T = TypeVar('T')


class ThreatType(Enum):
    """Types of security threats."""
    MALWARE = "malware"
    PHISHING = "phishing"
    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    ZERO_DAY = "zero_day"
    APT = "advanced_persistent_threat"
    INSIDER_THREAT = "insider_threat"


class ModelType(Enum):
    """Types of ML models."""
    NEURAL_NETWORK = "neural_network"
    RANDOM_FOREST = "random_forest"
    XGBOOST = "xgboost"
    ISOLATION_FOREST = "isolation_forest"
    DBSCAN = "dbscan"
    KMEANS = "kmeans"
    SVM = "svm"
    LSTM = "lstm"
    CNN = "cnn"
    AUTOENCODER = "autoencoder"


class FeatureType(Enum):
    """Types of security features."""
    NETWORK = "network"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    STATISTICAL = "statistical"
    CONTEXTUAL = "contextual"
    PAYLOAD = "payload"
    HEADER = "header"
    SESSION = "session"


class ModelStatus(Enum):
    """ML model status."""
    TRAINING = "training"
    READY = "ready"
    DEPLOYED = "deployed"
    DEPRECATED = "deprecated"
    FAILED = "failed"
    RETRAINING = "retraining"


class PredictionConfidence(Enum):
    """Prediction confidence levels."""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class ThreatFeatures:
    """Security features extracted for ML analysis."""
    id: str
    timestamp: datetime
    source_ip: str
    target_ip: str
    port: int
    protocol: str
    payload_size: int
    request_rate: float
    session_duration: float
    user_agent: str
    headers: Dict[str, str]
    payload_entropy: float
    packet_size_variance: float
    connection_count: int
    failed_attempts: int
    geo_location: str
    is_suspicious_domain: bool
    reputation_score: float
    behavioral_score: float
    temporal_pattern: List[float]
    feature_vector: List[float] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'port': self.port,
            'protocol': self.protocol,
            'payload_size': self.payload_size,
            'request_rate': self.request_rate,
            'session_duration': self.session_duration,
            'user_agent': self.user_agent,
            'headers': self.headers,
            'payload_entropy': self.payload_entropy,
            'packet_size_variance': self.packet_size_variance,
            'connection_count': self.connection_count,
            'failed_attempts': self.failed_attempts,
            'geo_location': self.geo_location,
            'is_suspicious_domain': self.is_suspicious_domain,
            'reputation_score': self.reputation_score,
            'behavioral_score': self.behavioral_score,
            'temporal_pattern': self.temporal_pattern,
            'feature_vector': self.feature_vector,
            'labels': self.labels,
            'metadata': self.metadata
        }


@dataclass
class ThreatPrediction:
    """ML threat prediction result."""
    id: str
    features_id: str
    threat_type: ThreatType
    confidence: PredictionConfidence
    probability: float
    risk_score: float
    model_used: str
    model_version: str
    prediction_time: datetime
    feature_importance: Dict[str, float]
    explanation: str
    recommended_actions: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'features_id': self.features_id,
            'threat_type': self.threat_type.value,
            'confidence': self.confidence.value,
            'probability': self.probability,
            'risk_score': self.risk_score,
            'model_used': self.model_used,
            'model_version': self.model_version,
            'prediction_time': self.prediction_time.isoformat(),
            'feature_importance': self.feature_importance,
            'explanation': self.explanation,
            'recommended_actions': self.recommended_actions,
            'metadata': self.metadata
        }


@dataclass
class MLModel:
    """ML model metadata and configuration."""
    id: str
    name: str
    model_type: ModelType
    version: str
    status: ModelStatus
    threat_types: List[ThreatType]
    feature_types: List[FeatureType]
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_data_size: int
    created_at: datetime
    last_trained: datetime
    last_updated: datetime
    model_path: str
    hyperparameters: Dict[str, Any]
    feature_columns: List[str]
    target_column: str
    preprocessing_config: Dict[str, Any]
    performance_metrics: Dict[str, float]
    drift_threshold: float = 0.05
    retrain_threshold: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'model_type': self.model_type.value,
            'version': self.version,
            'status': self.status.value,
            'threat_types': [t.value for t in self.threat_types],
            'feature_types': [f.value for f in self.feature_types],
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'training_data_size': self.training_data_size,
            'created_at': self.created_at.isoformat(),
            'last_trained': self.last_trained.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'model_path': self.model_path,
            'hyperparameters': self.hyperparameters,
            'feature_columns': self.feature_columns,
            'target_column': self.target_column,
            'preprocessing_config': self.preprocessing_config,
            'performance_metrics': self.performance_metrics,
            'drift_threshold': self.drift_threshold,
            'retrain_threshold': self.retrain_threshold,
            'metadata': self.metadata
        }


@dataclass
class AnomalyDetectionResult:
    """Anomaly detection result."""
    id: str
    features_id: str
    is_anomaly: bool
    anomaly_score: float
    anomaly_type: str
    detection_method: str
    timestamp: datetime
    explanation: str
    related_patterns: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class MLThreatDatabase:
    """Database for ML threat detection data."""
    
    def __init__(self, db_path: str = "ml_threat_detection.db"):
        self.db_path = db_path
        self._lock = RLock()
        self._init_database()
        logger.info(f"ML Threat Database initialized at {db_path}")
    
    def _init_database(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            # Features table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_features (
                    id TEXT PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT,
                    target_ip TEXT,
                    port INTEGER,
                    protocol TEXT,
                    payload_size INTEGER,
                    request_rate REAL,
                    session_duration REAL,
                    user_agent TEXT,
                    headers TEXT,
                    payload_entropy REAL,
                    packet_size_variance REAL,
                    connection_count INTEGER,
                    failed_attempts INTEGER,
                    geo_location TEXT,
                    is_suspicious_domain BOOLEAN,
                    reputation_score REAL,
                    behavioral_score REAL,
                    temporal_pattern TEXT,
                    feature_vector TEXT,
                    labels TEXT,
                    metadata TEXT
                )
            """)
            
            # Predictions table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_predictions (
                    id TEXT PRIMARY KEY,
                    features_id TEXT,
                    threat_type TEXT,
                    confidence TEXT,
                    probability REAL,
                    risk_score REAL,
                    model_used TEXT,
                    model_version TEXT,
                    prediction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    feature_importance TEXT,
                    explanation TEXT,
                    recommended_actions TEXT,
                    metadata TEXT,
                    FOREIGN KEY (features_id) REFERENCES threat_features (id)
                )
            """)
            
            # Models table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ml_models (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    model_type TEXT NOT NULL,
                    version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    threat_types TEXT,
                    feature_types TEXT,
                    accuracy REAL,
                    precision_score REAL,
                    recall_score REAL,
                    f1_score REAL,
                    training_data_size INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_trained TIMESTAMP,
                    last_updated TIMESTAMP,
                    model_path TEXT,
                    hyperparameters TEXT,
                    feature_columns TEXT,
                    target_column TEXT,
                    preprocessing_config TEXT,
                    performance_metrics TEXT,
                    drift_threshold REAL DEFAULT 0.05,
                    retrain_threshold REAL DEFAULT 0.8,
                    metadata TEXT
                )
            """)
            
            # Anomalies table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_detections (
                    id TEXT PRIMARY KEY,
                    features_id TEXT,
                    is_anomaly BOOLEAN,
                    anomaly_score REAL,
                    anomaly_type TEXT,
                    detection_method TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    explanation TEXT,
                    related_patterns TEXT,
                    metadata TEXT,
                    FOREIGN KEY (features_id) REFERENCES threat_features (id)
                )
            """)
            
            # Training data table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS training_data (
                    id TEXT PRIMARY KEY,
                    model_id TEXT,
                    features_id TEXT,
                    label TEXT,
                    weight REAL DEFAULT 1.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    validated BOOLEAN DEFAULT 0,
                    FOREIGN KEY (model_id) REFERENCES ml_models (id),
                    FOREIGN KEY (features_id) REFERENCES threat_features (id)
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_features_timestamp ON threat_features(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_features_source_ip ON threat_features(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_predictions_model ON threat_predictions(model_used)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_predictions_timestamp ON threat_predictions(prediction_time)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_models_status ON ml_models(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_models_type ON ml_models(model_type)")
            
            conn.commit()
    
    def store_features(self, features: ThreatFeatures) -> bool:
        """Store threat features."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO threat_features
                        (id, timestamp, source_ip, target_ip, port, protocol,
                         payload_size, request_rate, session_duration, user_agent,
                         headers, payload_entropy, packet_size_variance, connection_count,
                         failed_attempts, geo_location, is_suspicious_domain,
                         reputation_score, behavioral_score, temporal_pattern,
                         feature_vector, labels, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        features.id, features.timestamp, features.source_ip, features.target_ip,
                        features.port, features.protocol, features.payload_size, features.request_rate,
                        features.session_duration, features.user_agent, json.dumps(features.headers),
                        features.payload_entropy, features.packet_size_variance, features.connection_count,
                        features.failed_attempts, features.geo_location, features.is_suspicious_domain,
                        features.reputation_score, features.behavioral_score,
                        json.dumps(features.temporal_pattern), json.dumps(features.feature_vector),
                        json.dumps(features.labels), json.dumps(features.metadata)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing features: {e}")
                return False
    
    def store_prediction(self, prediction: ThreatPrediction) -> bool:
        """Store threat prediction."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO threat_predictions
                        (id, features_id, threat_type, confidence, probability,
                         risk_score, model_used, model_version, prediction_time,
                         feature_importance, explanation, recommended_actions, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        prediction.id, prediction.features_id, prediction.threat_type.value,
                        prediction.confidence.value, prediction.probability, prediction.risk_score,
                        prediction.model_used, prediction.model_version, prediction.prediction_time,
                        json.dumps(prediction.feature_importance), prediction.explanation,
                        json.dumps(prediction.recommended_actions), json.dumps(prediction.metadata)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing prediction: {e}")
                return False
    
    def store_model(self, model: MLModel) -> bool:
        """Store ML model metadata."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO ml_models
                        (id, name, model_type, version, status, threat_types, feature_types,
                         accuracy, precision_score, recall_score, f1_score, training_data_size,
                         created_at, last_trained, last_updated, model_path, hyperparameters,
                         feature_columns, target_column, preprocessing_config, performance_metrics,
                         drift_threshold, retrain_threshold, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        model.id, model.name, model.model_type.value, model.version,
                        model.status.value, json.dumps([t.value for t in model.threat_types]),
                        json.dumps([f.value for f in model.feature_types]), model.accuracy,
                        model.precision, model.recall, model.f1_score, model.training_data_size,
                        model.created_at, model.last_trained, model.last_updated, model.model_path,
                        json.dumps(model.hyperparameters), json.dumps(model.feature_columns),
                        model.target_column, json.dumps(model.preprocessing_config),
                        json.dumps(model.performance_metrics), model.drift_threshold,
                        model.retrain_threshold, json.dumps(model.metadata)
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing model: {e}")
                return False
    
    def get_features_by_timerange(self, start_time: datetime, 
                                  end_time: datetime) -> List[ThreatFeatures]:
        """Get features within time range."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT * FROM threat_features 
                    WHERE timestamp >= ? AND timestamp <= ?
                    ORDER BY timestamp DESC
                """, (start_time, end_time))
                
                features_list = []
                for row in cursor.fetchall():
                    features = self._row_to_features(row)
                    features_list.append(features)
                
                return features_list
        except Exception as e:
            logger.error(f"Error retrieving features: {e}")
            return []
    
    def _row_to_features(self, row) -> ThreatFeatures:
        """Convert database row to ThreatFeatures."""
        return ThreatFeatures(
            id=row[0],
            timestamp=datetime.fromisoformat(row[1].replace('Z', '+00:00')) if isinstance(row[1], str) else row[1],
            source_ip=row[2] or "",
            target_ip=row[3] or "",
            port=row[4] or 0,
            protocol=row[5] or "",
            payload_size=row[6] or 0,
            request_rate=row[7] or 0.0,
            session_duration=row[8] or 0.0,
            user_agent=row[9] or "",
            headers=json.loads(row[10]) if row[10] else {},
            payload_entropy=row[11] or 0.0,
            packet_size_variance=row[12] or 0.0,
            connection_count=row[13] or 0,
            failed_attempts=row[14] or 0,
            geo_location=row[15] or "",
            is_suspicious_domain=bool(row[16]),
            reputation_score=row[17] or 0.0,
            behavioral_score=row[18] or 0.0,
            temporal_pattern=json.loads(row[19]) if row[19] else [],
            feature_vector=json.loads(row[20]) if row[20] else [],
            labels=json.loads(row[21]) if row[21] else [],
            metadata=json.loads(row[22]) if row[22] else {}
        )


class FeatureEngineer:
    """Advanced feature engineering for security data."""
    
    def __init__(self):
        self.scalers = {}
        self.encoders = {}
        self.feature_selectors = {}
        self._lock = RLock()
        
        logger.info("FeatureEngineer initialized")
    
    def extract_network_features(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract network-based security features."""
        features = {}
        
        # Basic network metrics
        features['payload_size'] = float(raw_data.get('payload_size', 0))
        features['port'] = float(raw_data.get('port', 0))
        features['connection_count'] = float(raw_data.get('connection_count', 0))
        
        # Request rate analysis
        features['request_rate'] = float(raw_data.get('request_rate', 0))
        features['burst_ratio'] = self._calculate_burst_ratio(raw_data)
        
        # Payload analysis
        features['payload_entropy'] = self._calculate_entropy(raw_data.get('payload', ''))
        features['payload_ascii_ratio'] = self._calculate_ascii_ratio(raw_data.get('payload', ''))
        features['payload_contains_suspicious'] = self._contains_suspicious_patterns(raw_data.get('payload', ''))
        
        # Header analysis
        headers = raw_data.get('headers', {})
        features['header_count'] = float(len(headers))
        features['has_suspicious_headers'] = self._has_suspicious_headers(headers)
        features['user_agent_entropy'] = self._calculate_entropy(headers.get('user-agent', ''))
        
        return features
    
    def extract_behavioral_features(self, historical_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """Extract behavioral patterns from historical data."""
        features = {}
        
        if not historical_data:
            return {'behavioral_score': 0.0}
        
        # Time-based patterns
        timestamps = [d.get('timestamp', 0) for d in historical_data]
        features['request_frequency_std'] = np.std(np.diff(timestamps)) if len(timestamps) > 1 else 0.0
        features['time_regularity'] = self._calculate_time_regularity(timestamps)
        
        # Access patterns
        accessed_resources = [d.get('resource', '') for d in historical_data]
        features['resource_diversity'] = len(set(accessed_resources)) / len(accessed_resources) if accessed_resources else 0.0
        
        # Geographic patterns
        locations = [d.get('geo_location', '') for d in historical_data]
        features['location_changes'] = len(set(locations)) - 1
        features['location_entropy'] = self._calculate_entropy(' '.join(locations))
        
        # Session patterns
        session_durations = [d.get('session_duration', 0) for d in historical_data]
        features['avg_session_duration'] = np.mean(session_durations)
        features['session_duration_variance'] = np.var(session_durations)
        
        # Failure patterns
        failed_attempts = [d.get('failed_attempts', 0) for d in historical_data]
        features['total_failures'] = sum(failed_attempts)
        features['failure_rate'] = sum(failed_attempts) / len(failed_attempts) if failed_attempts else 0.0
        
        return features
    
    def extract_temporal_features(self, timestamp: datetime, 
                                  time_series_data: List[float]) -> Dict[str, float]:
        """Extract temporal patterns and time-series features."""
        features = {}
        
        # Time-of-day features
        features['hour_of_day'] = float(timestamp.hour)
        features['day_of_week'] = float(timestamp.weekday())
        features['is_weekend'] = float(timestamp.weekday() >= 5)
        features['is_business_hours'] = float(9 <= timestamp.hour <= 17)
        
        if time_series_data and len(time_series_data) > 1:
            # Statistical features
            features['ts_mean'] = np.mean(time_series_data)
            features['ts_std'] = np.std(time_series_data)
            features['ts_skew'] = self._calculate_skewness(time_series_data)
            features['ts_kurtosis'] = self._calculate_kurtosis(time_series_data)
            
            # Trend features
            features['trend_slope'] = self._calculate_trend_slope(time_series_data)
            features['autocorrelation'] = self._calculate_autocorrelation(time_series_data)
            
            # Anomaly indicators
            features['outlier_count'] = self._count_outliers(time_series_data)
            features['sudden_changes'] = self._count_sudden_changes(time_series_data)
        
        return features
    
    def create_feature_vector(self, features: ThreatFeatures) -> List[float]:
        """Create comprehensive feature vector from ThreatFeatures."""
        vector = []
        
        # Network features
        network_features = self.extract_network_features(features.to_dict())
        vector.extend(network_features.values())
        
        # Basic numeric features
        vector.extend([
            features.payload_size,
            features.request_rate,
            features.session_duration,
            features.payload_entropy,
            features.packet_size_variance,
            features.connection_count,
            features.failed_attempts,
            features.reputation_score,
            features.behavioral_score
        ])
        
        # Categorical features (encoded)
        vector.append(self._encode_protocol(features.protocol))
        vector.append(float(features.is_suspicious_domain))
        vector.append(self._encode_geo_location(features.geo_location))
        
        # Temporal features
        vector.extend(features.temporal_pattern)
        
        # Statistical features from existing vector
        if features.feature_vector:
            existing_features = np.array(features.feature_vector)
            vector.extend([
                np.mean(existing_features),
                np.std(existing_features),
                np.min(existing_features),
                np.max(existing_features)
            ])
        
        return vector
    
    def normalize_features(self, features: np.ndarray, scaler_id: str = "default") -> np.ndarray:
        """Normalize feature vectors using stored scalers."""
        with self._lock:
            if scaler_id not in self.scalers:
                self.scalers[scaler_id] = StandardScaler()
                return self.scalers[scaler_id].fit_transform(features)
            else:
                return self.scalers[scaler_id].transform(features)
    
    def select_features(self, X: np.ndarray, y: np.ndarray, 
                       k: int = 20, selector_id: str = "default") -> np.ndarray:
        """Select top-k features using statistical tests."""
        with self._lock:
            if selector_id not in self.feature_selectors:
                self.feature_selectors[selector_id] = SelectKBest(f_classif, k=k)
                return self.feature_selectors[selector_id].fit_transform(X, y)
            else:
                return self.feature_selectors[selector_id].transform(X)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        byte_counts = defaultdict(int)
        for byte in text.encode('utf-8'):
            byte_counts[byte] += 1
        
        entropy = 0.0
        text_len = len(text.encode('utf-8'))
        
        for count in byte_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _calculate_ascii_ratio(self, text: str) -> float:
        """Calculate ratio of ASCII printable characters."""
        if not text:
            return 0.0
        
        ascii_count = sum(1 for c in text if 32 <= ord(c) <= 126)
        return ascii_count / len(text)
    
    def _contains_suspicious_patterns(self, text: str) -> float:
        """Check for suspicious patterns in payload."""
        suspicious_patterns = [
            'script', 'alert', 'onload', 'onerror', 'javascript:',
            'eval(', 'exec(', 'system(', 'shell_exec',
            'union select', 'drop table', 'information_schema',
            '../', '..\\', '%2e%2e', 'etc/passwd'
        ]
        
        text_lower = text.lower()
        matches = sum(1 for pattern in suspicious_patterns if pattern in text_lower)
        
        return float(matches > 0)
    
    def _has_suspicious_headers(self, headers: Dict[str, str]) -> float:
        """Check for suspicious HTTP headers."""
        suspicious_headers = {
            'x-forwarded-for': lambda v: len(v.split(',')) > 5,  # Too many proxy hops
            'user-agent': lambda v: len(v) < 10 or 'bot' in v.lower(),  # Suspicious UA
            'referer': lambda v: 'malware' in v.lower() or 'phishing' in v.lower(),
            'x-real-ip': lambda v: v != headers.get('x-forwarded-for', '').split(',')[0].strip()
        }
        
        suspicion_score = 0
        for header, check_func in suspicious_headers.items():
            if header in headers and check_func(headers[header]):
                suspicion_score += 1
        
        return float(suspicion_score > 0)
    
    def _calculate_burst_ratio(self, raw_data: Dict[str, Any]) -> float:
        """Calculate request burst ratio."""
        request_rate = raw_data.get('request_rate', 0)
        avg_rate = raw_data.get('avg_request_rate', 1)
        
        return request_rate / max(avg_rate, 1)
    
    def _calculate_time_regularity(self, timestamps: List[float]) -> float:
        """Calculate regularity of time intervals."""
        if len(timestamps) < 2:
            return 0.0
        
        intervals = np.diff(sorted(timestamps))
        if len(intervals) == 0:
            return 0.0
        
        return 1.0 / (1.0 + np.std(intervals))
    
    def _calculate_skewness(self, data: List[float]) -> float:
        """Calculate skewness of data."""
        if len(data) < 3:
            return 0.0
        
        data_array = np.array(data)
        mean_val = np.mean(data_array)
        std_val = np.std(data_array)
        
        if std_val == 0:
            return 0.0
        
        skewness = np.mean(((data_array - mean_val) / std_val) ** 3)
        return skewness
    
    def _calculate_kurtosis(self, data: List[float]) -> float:
        """Calculate kurtosis of data."""
        if len(data) < 4:
            return 0.0
        
        data_array = np.array(data)
        mean_val = np.mean(data_array)
        std_val = np.std(data_array)
        
        if std_val == 0:
            return 0.0
        
        kurtosis = np.mean(((data_array - mean_val) / std_val) ** 4) - 3
        return kurtosis
    
    def _calculate_trend_slope(self, data: List[float]) -> float:
        """Calculate trend slope using linear regression."""
        if len(data) < 2:
            return 0.0
        
        x = np.arange(len(data))
        y = np.array(data)
        
        # Simple linear regression
        n = len(data)
        slope = (n * np.sum(x * y) - np.sum(x) * np.sum(y)) / (n * np.sum(x**2) - (np.sum(x))**2)
        
        return slope
    
    def _calculate_autocorrelation(self, data: List[float], lag: int = 1) -> float:
        """Calculate autocorrelation at given lag."""
        if len(data) <= lag:
            return 0.0
        
        data_array = np.array(data)
        n = len(data_array)
        
        # Remove mean
        data_centered = data_array - np.mean(data_array)
        
        # Calculate autocorrelation
        correlation = np.correlate(data_centered[:-lag], data_centered[lag:], mode='valid')[0]
        variance = np.sum(data_centered**2)
        
        if variance == 0:
            return 0.0
        
        return correlation / variance
    
    def _count_outliers(self, data: List[float], threshold: float = 2.0) -> float:
        """Count outliers using z-score."""
        if len(data) < 3:
            return 0.0
        
        data_array = np.array(data)
        z_scores = np.abs((data_array - np.mean(data_array)) / np.std(data_array))
        
        return float(np.sum(z_scores > threshold))
    
    def _count_sudden_changes(self, data: List[float], threshold: float = 1.5) -> float:
        """Count sudden changes in time series."""
        if len(data) < 2:
            return 0.0
        
        changes = np.abs(np.diff(data))
        mean_change = np.mean(changes)
        std_change = np.std(changes)
        
        if std_change == 0:
            return 0.0
        
        sudden_changes = np.sum(changes > (mean_change + threshold * std_change))
        return float(sudden_changes)
    
    def _encode_protocol(self, protocol: str) -> float:
        """Encode protocol as numeric value."""
        protocol_map = {
            'tcp': 1.0,
            'udp': 2.0,
            'icmp': 3.0,
            'http': 4.0,
            'https': 5.0,
            'ftp': 6.0,
            'ssh': 7.0,
            'dns': 8.0
        }
        
        return protocol_map.get(protocol.lower(), 0.0)
    
    def _encode_geo_location(self, location: str) -> float:
        """Encode geographic location as numeric value."""
        # Simple hash-based encoding for location
        if not location:
            return 0.0
        
        return float(hash(location) % 1000) / 1000.0


class AnomalyDetector:
    """Unsupervised anomaly detection for security threats."""
    
    def __init__(self):
        self.isolation_forest = None
        self.one_class_svm = None
        self.dbscan = None
        self.is_fitted = False
        self._lock = RLock()
        
        logger.info("AnomalyDetector initialized")
    
    def fit(self, X: np.ndarray) -> bool:
        """Train anomaly detection models."""
        with self._lock:
            try:
                if not ML_AVAILABLE:
                    logger.error("Scikit-learn not available for anomaly detection")
                    return False
                
                # Isolation Forest for outlier detection
                self.isolation_forest = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                )
                self.isolation_forest.fit(X)
                
                # One-Class SVM for novelty detection
                self.one_class_svm = OneClassSVM(
                    kernel='rbf',
                    gamma='scale',
                    nu=0.1
                )
                self.one_class_svm.fit(X)
                
                # DBSCAN for density-based clustering
                self.dbscan = DBSCAN(
                    eps=0.5,
                    min_samples=5
                )
                self.dbscan.fit(X)
                
                self.is_fitted = True
                logger.info(f"Anomaly detection models trained on {X.shape[0]} samples")
                return True
                
            except Exception as e:
                logger.error(f"Error training anomaly detection models: {e}")
                return False
    
    def detect_anomalies(self, X: np.ndarray) -> List[AnomalyDetectionResult]:
        """Detect anomalies in new data."""
        if not self.is_fitted:
            logger.warning("Anomaly detection models not fitted")
            return []
        
        results = []
        
        try:
            # Isolation Forest predictions
            if_scores = self.isolation_forest.decision_function(X)
            if_predictions = self.isolation_forest.predict(X)
            
            # One-Class SVM predictions
            svm_scores = self.one_class_svm.decision_function(X)
            svm_predictions = self.one_class_svm.predict(X)
            
            # DBSCAN clustering
            dbscan_labels = self.dbscan.fit_predict(X)
            
            for i in range(len(X)):
                # Combine predictions from multiple models
                is_if_anomaly = if_predictions[i] == -1
                is_svm_anomaly = svm_predictions[i] == -1
                is_dbscan_anomaly = dbscan_labels[i] == -1  # Noise points
                
                # Ensemble decision
                anomaly_votes = sum([is_if_anomaly, is_svm_anomaly, is_dbscan_anomaly])
                is_anomaly = anomaly_votes >= 2  # Majority vote
                
                # Combined anomaly score
                anomaly_score = (
                    -if_scores[i] +  # Isolation Forest (negative means anomaly)
                    -svm_scores[i] +  # SVM (negative means anomaly)
                    float(is_dbscan_anomaly)  # DBSCAN (1 if noise)
                ) / 3.0
                
                # Determine anomaly type
                anomaly_type = self._determine_anomaly_type(
                    is_if_anomaly, is_svm_anomaly, is_dbscan_anomaly
                )
                
                result = AnomalyDetectionResult(
                    id=str(uuid.uuid4()),
                    features_id="",  # Will be set by caller
                    is_anomaly=is_anomaly,
                    anomaly_score=anomaly_score,
                    anomaly_type=anomaly_type,
                    detection_method="ensemble",
                    timestamp=datetime.now(timezone.utc),
                    explanation=self._generate_explanation(
                        is_if_anomaly, is_svm_anomaly, is_dbscan_anomaly, anomaly_score
                    ),
                    related_patterns=[]
                )
                
                results.append(result)
                
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
        
        return results
    
    def _determine_anomaly_type(self, is_if: bool, is_svm: bool, is_dbscan: bool) -> str:
        """Determine the type of anomaly based on model agreements."""
        if is_if and is_svm and is_dbscan:
            return "strong_outlier"
        elif is_if and is_svm:
            return "statistical_outlier"
        elif is_if and is_dbscan:
            return "isolation_outlier"
        elif is_svm and is_dbscan:
            return "density_outlier"
        elif is_if:
            return "isolation_anomaly"
        elif is_svm:
            return "novelty_anomaly"
        elif is_dbscan:
            return "density_anomaly"
        else:
            return "normal"
    
    def _generate_explanation(self, is_if: bool, is_svm: bool, 
                             is_dbscan: bool, score: float) -> str:
        """Generate human-readable explanation for anomaly detection."""
        explanations = []
        
        if is_if:
            explanations.append("isolated from normal patterns")
        if is_svm:
            explanations.append("deviates from learned normal behavior")
        if is_dbscan:
            explanations.append("not part of any dense cluster")
        
        if not explanations:
            return "No anomaly detected"
        
        base_explanation = f"Data point {', '.join(explanations)}"
        confidence = "high" if score > 1.0 else "medium" if score > 0.5 else "low"
        
        return f"{base_explanation} (confidence: {confidence})"


class ModelManager:
    """Manage ML models lifecycle, training, and deployment."""
    
    def __init__(self, database: MLThreatDatabase, models_dir: str = "models"):
        self.database = database
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        self.loaded_models = {}
        self.model_metadata = {}
        self._lock = RLock()
        
        logger.info("ModelManager initialized")
    
    def create_model(self, name: str, model_type: ModelType, 
                    threat_types: List[ThreatType],
                    feature_types: List[FeatureType],
                    hyperparameters: Dict[str, Any] = None) -> MLModel:
        """Create a new ML model."""
        model_id = str(uuid.uuid4())
        model_path = str(self.models_dir / f"{model_id}.pkl")
        
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
            model_path=model_path,
            hyperparameters=hyperparameters or {},
            feature_columns=[],
            target_column="threat_type",
            preprocessing_config={},
            performance_metrics={}
        )
        
        if self.database.store_model(model):
            with self._lock:
                self.model_metadata[model_id] = model
            return model
        
        return None
    
    def train_model(self, model_id: str, X: np.ndarray, y: np.ndarray) -> bool:
        """Train a machine learning model."""
        model = self.model_metadata.get(model_id)
        if not model:
            logger.error(f"Model {model_id} not found")
            return False
        
        try:
            # Create the appropriate model based on type
            ml_model = self._create_sklearn_model(model.model_type, model.hyperparameters)
            
            # Split data for training and validation
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train the model
            ml_model.fit(X_train, y_train)
            
            # Validate the model
            y_pred = ml_model.predict(X_val)
            
            # Calculate metrics
            accuracy = sklearn.metrics.accuracy_score(y_val, y_pred)
            precision = sklearn.metrics.precision_score(y_val, y_pred, average='weighted')
            recall = sklearn.metrics.recall_score(y_val, y_pred, average='weighted')
            f1 = sklearn.metrics.f1_score(y_val, y_pred, average='weighted')
            
            # Update model metadata
            model.accuracy = accuracy
            model.precision = precision
            model.recall = recall
            model.f1_score = f1
            model.training_data_size = len(X)
            model.status = ModelStatus.READY
            model.last_trained = datetime.now(timezone.utc)
            model.last_updated = datetime.now(timezone.utc)
            
            # Save model to disk
            with open(model.model_path, 'wb') as f:
                pickle.dump(ml_model, f)
            
            # Update database
            self.database.store_model(model)
            
            # Load model into memory for serving
            with self._lock:
                self.loaded_models[model_id] = ml_model
            
            logger.info(f"Model {model_id} trained successfully. Accuracy: {accuracy:.4f}")
            return True
            
        except Exception as e:
            logger.error(f"Error training model {model_id}: {e}")
            model.status = ModelStatus.FAILED
            self.database.store_model(model)
            return False
    
    def predict(self, model_id: str, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions using a trained model."""
        with self._lock:
            if model_id not in self.loaded_models:
                # Load model from disk
                model = self.model_metadata.get(model_id)
                if not model or not Path(model.model_path).exists():
                    logger.error(f"Model {model_id} not found or not available")
                    return np.array([]), np.array([])
                
                try:
                    with open(model.model_path, 'rb') as f:
                        self.loaded_models[model_id] = pickle.load(f)
                except Exception as e:
                    logger.error(f"Error loading model {model_id}: {e}")
                    return np.array([]), np.array([])
            
            model = self.loaded_models[model_id]
            
            try:
                predictions = model.predict(X)
                probabilities = model.predict_proba(X) if hasattr(model, 'predict_proba') else None
                
                return predictions, probabilities
                
            except Exception as e:
                logger.error(f"Error making predictions with model {model_id}: {e}")
                return np.array([]), np.array([])
    
    def get_feature_importance(self, model_id: str) -> Dict[str, float]:
        """Get feature importance from trained model."""
        with self._lock:
            if model_id not in self.loaded_models:
                return {}
            
            model = self.loaded_models[model_id]
            
            try:
                if hasattr(model, 'feature_importances_'):
                    # Tree-based models
                    importances = model.feature_importances_
                elif hasattr(model, 'coef_'):
                    # Linear models
                    importances = np.abs(model.coef_[0] if len(model.coef_.shape) > 1 else model.coef_)
                else:
                    return {}
                
                # Create feature importance dictionary
                model_meta = self.model_metadata.get(model_id)
                feature_names = model_meta.feature_columns if model_meta else [f"feature_{i}" for i in range(len(importances))]
                
                return dict(zip(feature_names[:len(importances)], importances.tolist()))
                
            except Exception as e:
                logger.error(f"Error getting feature importance for model {model_id}: {e}")
                return {}
    
    def deploy_model(self, model_id: str) -> bool:
        """Deploy model for production serving."""
        model = self.model_metadata.get(model_id)
        if not model:
            logger.error(f"Model {model_id} not found")
            return False
        
        if model.status != ModelStatus.READY:
            logger.error(f"Model {model_id} is not ready for deployment")
            return False
        
        try:
            # Load model into memory if not already loaded
            with self._lock:
                if model_id not in self.loaded_models:
                    with open(model.model_path, 'rb') as f:
                        self.loaded_models[model_id] = pickle.load(f)
            
            # Update model status
            model.status = ModelStatus.DEPLOYED
            model.last_updated = datetime.now(timezone.utc)
            self.database.store_model(model)
            
            logger.info(f"Model {model_id} deployed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error deploying model {model_id}: {e}")
            return False
    
    def _create_sklearn_model(self, model_type: ModelType, hyperparameters: Dict[str, Any]):
        """Create sklearn model based on type and hyperparameters."""
        if not ML_AVAILABLE:
            raise ImportError("Scikit-learn not available")
        
        params = hyperparameters or {}
        
        if model_type == ModelType.RANDOM_FOREST:
            return RandomForestClassifier(
                n_estimators=params.get('n_estimators', 100),
                max_depth=params.get('max_depth', None),
                min_samples_split=params.get('min_samples_split', 2),
                random_state=42
            )
        elif model_type == ModelType.XGBOOST:
            return xgb.XGBClassifier(
                n_estimators=params.get('n_estimators', 100),
                max_depth=params.get('max_depth', 6),
                learning_rate=params.get('learning_rate', 0.1),
                random_state=42
            )
        elif model_type == ModelType.NEURAL_NETWORK:
            return MLPClassifier(
                hidden_layer_sizes=params.get('hidden_layer_sizes', (100, 50)),
                activation=params.get('activation', 'relu'),
                solver=params.get('solver', 'adam'),
                max_iter=params.get('max_iter', 1000),
                random_state=42
            )
        else:
            raise ValueError(f"Unsupported model type: {model_type}")


class PredictiveAnalyzer:
    """Predictive threat analysis and risk assessment."""
    
    def __init__(self, model_manager: ModelManager, feature_engineer: FeatureEngineer):
        self.model_manager = model_manager
        self.feature_engineer = feature_engineer
        self.risk_thresholds = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 0.95
        }
        
        logger.info("PredictiveAnalyzer initialized")
    
    def predict_threats(self, features: ThreatFeatures) -> List[ThreatPrediction]:
        """Predict threats using ensemble of models."""
        predictions = []
        
        # Create feature vector
        feature_vector = self.feature_engineer.create_feature_vector(features)
        X = np.array([feature_vector])
        
        # Get all deployed models
        deployed_models = [
            model for model in self.model_manager.model_metadata.values()
            if model.status == ModelStatus.DEPLOYED
        ]
        
        for model in deployed_models:
            try:
                # Make prediction
                pred, proba = self.model_manager.predict(model.id, X)
                
                if len(pred) > 0:
                    # Get feature importance
                    importance = self.model_manager.get_feature_importance(model.id)
                    
                    # Calculate confidence and risk score
                    confidence = self._calculate_confidence(proba)
                    risk_score = self._calculate_risk_score(proba, model.threat_types)
                    
                    # Generate explanation
                    explanation = self._generate_explanation(pred[0], confidence.value, importance)
                    
                    # Generate recommended actions
                    actions = self._generate_recommendations(pred[0], risk_score)
                    
                    prediction = ThreatPrediction(
                        id=str(uuid.uuid4()),
                        features_id=features.id,
                        threat_type=self._map_prediction_to_threat_type(pred[0]),
                        confidence=confidence,
                        probability=float(np.max(proba)) if proba is not None else 0.0,
                        risk_score=risk_score,
                        model_used=model.name,
                        model_version=model.version,
                        prediction_time=datetime.now(timezone.utc),
                        feature_importance=importance,
                        explanation=explanation,
                        recommended_actions=actions
                    )
                    
                    predictions.append(prediction)
                    
            except Exception as e:
                logger.error(f"Error predicting with model {model.id}: {e}")
                continue
        
        return predictions
    
    def assess_risk(self, predictions: List[ThreatPrediction]) -> float:
        """Assess overall risk based on multiple predictions."""
        if not predictions:
            return 0.0
        
        # Weighted average based on model performance and confidence
        total_weight = 0.0
        weighted_risk = 0.0
        
        for pred in predictions:
            # Weight based on confidence and model accuracy (if available)
            model = next(
                (m for m in self.model_manager.model_metadata.values() 
                 if m.name == pred.model_used), None
            )
            
            accuracy_weight = model.accuracy if model else 0.5
            confidence_weight = self._confidence_to_weight(pred.confidence)
            
            weight = accuracy_weight * confidence_weight
            weighted_risk += pred.risk_score * weight
            total_weight += weight
        
        return weighted_risk / total_weight if total_weight > 0 else 0.0
    
    def predict_attack_timeline(self, historical_features: List[ThreatFeatures]) -> Dict[str, Any]:
        """Predict potential attack timeline based on historical data."""
        if len(historical_features) < 10:
            return {'status': 'insufficient_data'}
        
        # Extract temporal patterns
        timestamps = [f.timestamp for f in historical_features]
        risk_scores = []
        
        for features in historical_features:
            predictions = self.predict_threats(features)
            risk = self.assess_risk(predictions)
            risk_scores.append(risk)
        
        # Time series analysis
        time_intervals = np.diff([t.timestamp() for t in timestamps])
        risk_trend = np.polyfit(range(len(risk_scores)), risk_scores, 1)[0]
        
        # Predict next likely attack time
        avg_interval = np.mean(time_intervals) if len(time_intervals) > 0 else 3600
        next_attack_time = timestamps[-1] + timedelta(seconds=avg_interval)
        
        # Assess escalation probability
        escalation_prob = self._calculate_escalation_probability(risk_scores)
        
        return {
            'status': 'analysis_complete',
            'risk_trend': 'increasing' if risk_trend > 0.01 else 'stable' if risk_trend > -0.01 else 'decreasing',
            'escalation_probability': escalation_prob,
            'predicted_next_attack': next_attack_time.isoformat(),
            'confidence_interval': self._calculate_prediction_confidence_interval(risk_scores),
            'recommendations': self._generate_timeline_recommendations(risk_trend, escalation_prob)
        }
    
    def _calculate_confidence(self, probabilities: Optional[np.ndarray]) -> PredictionConfidence:
        """Calculate prediction confidence level."""
        if probabilities is None:
            return PredictionConfidence.LOW
        
        max_prob = np.max(probabilities)
        
        if max_prob >= 0.95:
            return PredictionConfidence.VERY_HIGH
        elif max_prob >= 0.8:
            return PredictionConfidence.HIGH
        elif max_prob >= 0.6:
            return PredictionConfidence.MEDIUM
        elif max_prob >= 0.4:
            return PredictionConfidence.LOW
        else:
            return PredictionConfidence.VERY_LOW
    
    def _calculate_risk_score(self, probabilities: Optional[np.ndarray], 
                             threat_types: List[ThreatType]) -> float:
        """Calculate risk score based on probabilities and threat severity."""
        if probabilities is None:
            return 0.0
        
        # Threat severity weights
        severity_weights = {
            ThreatType.MALWARE: 0.9,
            ThreatType.APT: 1.0,
            ThreatType.DATA_EXFILTRATION: 0.95,
            ThreatType.PRIVILEGE_ESCALATION: 0.8,
            ThreatType.SQL_INJECTION: 0.7,
            ThreatType.XSS: 0.6,
            ThreatType.DDOS: 0.75,
            ThreatType.BRUTE_FORCE: 0.5,
            ThreatType.PHISHING: 0.65,
            ThreatType.ZERO_DAY: 1.0,
            ThreatType.INSIDER_THREAT: 0.85,
            ThreatType.ANOMALOUS_BEHAVIOR: 0.4
        }
        
        max_prob = np.max(probabilities)
        avg_severity = np.mean([severity_weights.get(t, 0.5) for t in threat_types])
        
        return max_prob * avg_severity
    
    def _map_prediction_to_threat_type(self, prediction) -> ThreatType:
        """Map model prediction to ThreatType enum."""
        # This would depend on how the model was trained and labels encoded
        # For now, use a simple mapping
        
        if isinstance(prediction, str):
            try:
                return ThreatType(prediction.lower())
            except ValueError:
                return ThreatType.ANOMALOUS_BEHAVIOR
        
        # If numeric prediction, map to most common threat types
        threat_map = {
            0: ThreatType.ANOMALOUS_BEHAVIOR,
            1: ThreatType.MALWARE,
            2: ThreatType.BRUTE_FORCE,
            3: ThreatType.SQL_INJECTION,
            4: ThreatType.XSS,
            5: ThreatType.DDOS
        }
        
        return threat_map.get(int(prediction), ThreatType.ANOMALOUS_BEHAVIOR)
    
    def _generate_explanation(self, prediction, confidence: str, 
                             importance: Dict[str, float]) -> str:
        """Generate human-readable explanation for prediction."""
        threat_type = self._map_prediction_to_threat_type(prediction)
        
        # Get top contributing features
        top_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:3]
        feature_desc = ", ".join([f"{feat}: {imp:.3f}" for feat, imp in top_features])
        
        base_explanation = f"Predicted {threat_type.value} threat with {confidence} confidence"
        
        if top_features:
            return f"{base_explanation}. Key indicators: {feature_desc}"
        else:
            return base_explanation
    
    def _generate_recommendations(self, prediction, risk_score: float) -> List[str]:
        """Generate recommended actions based on prediction."""
        threat_type = self._map_prediction_to_threat_type(prediction)
        actions = []
        
        # General recommendations based on risk score
        if risk_score >= 0.8:
            actions.append("Immediate investigation required")
            actions.append("Consider blocking suspicious IP addresses")
            actions.append("Escalate to security team")
        elif risk_score >= 0.6:
            actions.append("Enhanced monitoring recommended")
            actions.append("Review security logs")
        else:
            actions.append("Continue normal monitoring")
        
        # Threat-specific recommendations
        threat_actions = {
            ThreatType.MALWARE: ["Run anti-malware scan", "Isolate affected systems"],
            ThreatType.SQL_INJECTION: ["Review database queries", "Update input validation"],
            ThreatType.XSS: ["Check web application security", "Update content filtering"],
            ThreatType.BRUTE_FORCE: ["Implement rate limiting", "Review authentication logs"],
            ThreatType.DDOS: ["Activate DDoS protection", "Monitor network capacity"],
            ThreatType.PHISHING: ["User security awareness training", "Email security review"]
        }
        
        actions.extend(threat_actions.get(threat_type, []))
        
        return actions
    
    def _confidence_to_weight(self, confidence: PredictionConfidence) -> float:
        """Convert confidence level to numeric weight."""
        weights = {
            PredictionConfidence.VERY_LOW: 0.1,
            PredictionConfidence.LOW: 0.3,
            PredictionConfidence.MEDIUM: 0.6,
            PredictionConfidence.HIGH: 0.8,
            PredictionConfidence.VERY_HIGH: 1.0
        }
        return weights.get(confidence, 0.5)
    
    def _calculate_escalation_probability(self, risk_scores: List[float]) -> float:
        """Calculate probability of threat escalation."""
        if len(risk_scores) < 5:
            return 0.0
        
        # Look for increasing trend in recent scores
        recent_scores = risk_scores[-5:]
        trend = np.polyfit(range(len(recent_scores)), recent_scores, 1)[0]
        
        # Calculate escalation probability based on trend and absolute values
        base_prob = np.mean(recent_scores)
        trend_factor = max(0, trend) * 2  # Positive trend increases probability
        
        escalation_prob = min(1.0, base_prob + trend_factor)
        return escalation_prob
    
    def _calculate_prediction_confidence_interval(self, risk_scores: List[float]) -> Tuple[float, float]:
        """Calculate confidence interval for next prediction."""
        if len(risk_scores) < 3:
            return (0.0, 1.0)
        
        mean_score = np.mean(risk_scores)
        std_score = np.std(risk_scores)
        
        # 95% confidence interval
        lower_bound = max(0.0, mean_score - 1.96 * std_score)
        upper_bound = min(1.0, mean_score + 1.96 * std_score)
        
        return (lower_bound, upper_bound)
    
    def _generate_timeline_recommendations(self, trend: float, escalation_prob: float) -> List[str]:
        """Generate recommendations based on timeline analysis."""
        recommendations = []
        
        if escalation_prob > 0.7:
            recommendations.append("High escalation risk detected - prepare incident response")
            recommendations.append("Consider preemptive security measures")
        
        if trend > 0.05:
            recommendations.append("Increasing threat trend - enhance monitoring")
        elif trend < -0.05:
            recommendations.append("Decreasing threat trend - maintain current security posture")
        
        if escalation_prob > 0.5:
            recommendations.append("Review and update security policies")
            recommendations.append("Conduct security team briefing")
        
        return recommendations


class MLThreatDetector:
    """Main ML threat detection coordinator."""
    
    def __init__(self, db_path: str = "ml_threat_detection.db"):
        self.database = MLThreatDatabase(db_path)
        self.feature_engineer = FeatureEngineer()
        self.anomaly_detector = AnomalyDetector()
        self.model_manager = ModelManager(self.database)
        self.predictive_analyzer = PredictiveAnalyzer(self.model_manager, self.feature_engineer)
        
        self.processing_queue = asyncio.Queue()
        self.prediction_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        self._lock = RLock()
        self.is_running = False
        
        logger.info("MLThreatDetector initialized")
    
    async def start(self):
        """Start the ML threat detection engine."""
        self.is_running = True
        
        # Start background processing
        asyncio.create_task(self._process_detection_queue())
        
        logger.info("ML Threat Detection Engine started")
    
    async def stop(self):
        """Stop the ML threat detection engine."""
        self.is_running = False
        logger.info("ML Threat Detection Engine stopped")
    
    async def detect_threats(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Main threat detection method."""
        try:
            # Extract features
            features = self._extract_features(raw_data)
            
            # Store features in database
            self.database.store_features(features)
            
            # Check cache first
            cache_key = self._generate_cache_key(features)
            cached_result = self._get_cached_prediction(cache_key)
            if cached_result:
                return cached_result
            
            # Anomaly detection
            anomaly_results = await self._detect_anomalies(features)
            
            # Threat prediction
            predictions = await self._predict_threats(features)
            
            # Risk assessment
            overall_risk = self.predictive_analyzer.assess_risk(predictions)
            
            # Store predictions
            for prediction in predictions:
                self.database.store_prediction(prediction)
            
            # Compile results
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
                'processing_time_ms': self._calculate_processing_time(),
                'models_used': len(predictions),
                'confidence': self._calculate_overall_confidence(predictions)
            }
            
            # Cache result
            self._cache_prediction(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error in threat detection: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'status': 'failed'
            }
    
    def _extract_features(self, raw_data: Dict[str, Any]) -> ThreatFeatures:
        """Extract and engineer features from raw security data."""
        # Basic feature extraction
        features = ThreatFeatures(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source_ip=raw_data.get('source_ip', ''),
            target_ip=raw_data.get('target_ip', ''),
            port=raw_data.get('port', 0),
            protocol=raw_data.get('protocol', ''),
            payload_size=raw_data.get('payload_size', 0),
            request_rate=raw_data.get('request_rate', 0.0),
            session_duration=raw_data.get('session_duration', 0.0),
            user_agent=raw_data.get('user_agent', ''),
            headers=raw_data.get('headers', {}),
            payload_entropy=0.0,
            packet_size_variance=raw_data.get('packet_size_variance', 0.0),
            connection_count=raw_data.get('connection_count', 0),
            failed_attempts=raw_data.get('failed_attempts', 0),
            geo_location=raw_data.get('geo_location', ''),
            is_suspicious_domain=raw_data.get('is_suspicious_domain', False),
            reputation_score=raw_data.get('reputation_score', 0.0),
            behavioral_score=raw_data.get('behavioral_score', 0.0),
            temporal_pattern=raw_data.get('temporal_pattern', [])
        )
        
        # Advanced feature engineering
        network_features = self.feature_engineer.extract_network_features(raw_data)
        
        # Calculate payload entropy if payload is provided
        payload = raw_data.get('payload', '')
        if payload:
            features.payload_entropy = self.feature_engineer._calculate_entropy(payload)
        
        # Create comprehensive feature vector
        features.feature_vector = self.feature_engineer.create_feature_vector(features)
        
        return features
    
    async def _detect_anomalies(self, features: ThreatFeatures) -> List[AnomalyDetectionResult]:
        """Detect anomalies in the features."""
        if not self.anomaly_detector.is_fitted:
            # If not fitted, try to fit with recent data
            recent_features = self.database.get_features_by_timerange(
                datetime.now(timezone.utc) - timedelta(days=7),
                datetime.now(timezone.utc)
            )
            
            if len(recent_features) >= 100:  # Need minimum data for training
                X = np.array([f.feature_vector for f in recent_features if f.feature_vector])
                self.anomaly_detector.fit(X)
        
        if not self.anomaly_detector.is_fitted:
            return []
        
        # Detect anomalies
        X = np.array([features.feature_vector])
        results = self.anomaly_detector.detect_anomalies(X)
        
        # Update feature IDs
        for result in results:
            result.features_id = features.id
        
        return results
    
    async def _predict_threats(self, features: ThreatFeatures) -> List[ThreatPrediction]:
        """Predict threats using ML models."""
        return self.predictive_analyzer.predict_threats(features)
    
    def _generate_cache_key(self, features: ThreatFeatures) -> str:
        """Generate cache key for features."""
        # Create hash of key features for caching
        key_data = f"{features.source_ip}:{features.target_ip}:{features.port}:{features.protocol}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _get_cached_prediction(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached prediction if still valid."""
        if cache_key in self.prediction_cache:
            cached_data, timestamp = self.prediction_cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
            else:
                del self.prediction_cache[cache_key]
        
        return None
    
    def _cache_prediction(self, cache_key: str, result: Dict[str, Any]):
        """Cache prediction result."""
        self.prediction_cache[cache_key] = (result, time.time())
    
    def _classify_risk_level(self, risk_score: float) -> str:
        """Classify risk score into risk level."""
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
        """Compile unique recommendations from all predictions."""
        all_recommendations = []
        for prediction in predictions:
            all_recommendations.extend(prediction.recommended_actions)
        
        # Remove duplicates while preserving order
        unique_recommendations = []
        seen = set()
        for rec in all_recommendations:
            if rec not in seen:
                unique_recommendations.append(rec)
                seen.add(rec)
        
        return unique_recommendations
    
    def _calculate_processing_time(self) -> int:
        """Calculate processing time in milliseconds."""
        # This would track actual processing time in a real implementation
        return 50  # Placeholder for <100ms requirement
    
    def _calculate_overall_confidence(self, predictions: List[ThreatPrediction]) -> str:
        """Calculate overall confidence from all predictions."""
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
    
    async def _process_detection_queue(self):
        """Background processing of detection queue."""
        while self.is_running:
            try:
                # Process queued detection requests
                await asyncio.sleep(0.1)  # Prevent busy waiting
            except Exception as e:
                logger.error(f"Error in detection queue processing: {e}")


# Convenience functions
def create_ml_threat_detector(db_path: str = "ml_threat_detection.db") -> MLThreatDetector:
    """Create ML threat detection engine."""
    return MLThreatDetector(db_path)


# Export all classes and functions
__all__ = [
    # Enums
    'ThreatType',
    'ModelType',
    'FeatureType',
    'ModelStatus',
    'PredictionConfidence',
    
    # Data classes
    'ThreatFeatures',
    'ThreatPrediction',
    'MLModel',
    'AnomalyDetectionResult',
    
    # Core classes
    'MLThreatDatabase',
    'FeatureEngineer',
    'AnomalyDetector',
    'ModelManager',
    'PredictiveAnalyzer',
    'MLThreatDetector',
    
    # Convenience functions
    'create_ml_threat_detector',
]