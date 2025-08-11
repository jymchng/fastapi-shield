"""Machine learning-based security framework for FastAPI Shield.

This module provides comprehensive ML-powered security capabilities including
anomaly detection, threat prediction, adaptive security policies, and real-time
threat intelligence. It integrates with popular ML frameworks like scikit-learn
and TensorFlow to provide production-ready security automation.

Key Components:
    - RequestFeatureExtractor: Extracts ML features from HTTP requests
    - AnomalyDetectionEngine: ML-based anomaly detection with multiple algorithms
    - ThreatIntelligenceManager: Threat intelligence integration and scoring
    - AdaptiveSecurityManager: Dynamic security policy adaptation based on ML
    - ThreatPredictionEngine: Real-time threat prediction and scoring
    - MLSecurityShield: Complete ML-powered security shield
"""

import asyncio
import json
import logging
import time
import hashlib
import pickle
import os
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    NamedTuple, Protocol
)
import statistics
import numpy as np
from urllib.parse import urlparse, parse_qs
import re
import ipaddress
from threading import RLock, Thread
import queue
import warnings
warnings.filterwarnings('ignore', category=FutureWarning)

# ML framework imports
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.cluster import DBSCAN
    from sklearn.decomposition import PCA
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow import keras
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse

from fastapi_shield.shield import Shield, shield

logger = logging.getLogger(__name__)


class ThreatLevel(str, Enum):
    """Threat level classifications."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyType(str, Enum):
    """Types of detected anomalies."""
    REQUEST_PATTERN = "request_pattern"
    RATE_ANOMALY = "rate_anomaly"
    PAYLOAD_ANOMALY = "payload_anomaly"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    GEOGRAPHICAL_ANOMALY = "geographical_anomaly"
    TIME_ANOMALY = "time_anomaly"


class MLModelType(str, Enum):
    """Supported ML model types."""
    ISOLATION_FOREST = "isolation_forest"
    ONE_CLASS_SVM = "one_class_svm"
    AUTOENCODER = "autoencoder"
    DBSCAN = "dbscan"
    ENSEMBLE = "ensemble"


class SecurityAction(str, Enum):
    """Security actions based on ML analysis."""
    ALLOW = "allow"
    WARN = "warn"
    THROTTLE = "throttle"
    BLOCK = "block"
    CAPTCHA = "captcha"


class FeatureCategory(str, Enum):
    """Categories of extracted features."""
    REQUEST_METADATA = "request_metadata"
    PAYLOAD_FEATURES = "payload_features"
    BEHAVIORAL_FEATURES = "behavioral_features"
    NETWORK_FEATURES = "network_features"
    TEMPORAL_FEATURES = "temporal_features"


@dataclass
class RequestFeatures:
    """Extracted features from HTTP request for ML analysis."""
    
    # Request metadata features
    method: str = ""
    path: str = ""
    path_length: int = 0
    query_param_count: int = 0
    header_count: int = 0
    user_agent_length: int = 0
    content_length: int = 0
    
    # Network features
    client_ip: str = ""
    is_private_ip: bool = False
    geolocation_country: str = "unknown"
    
    # Payload features
    has_json_payload: bool = False
    has_form_payload: bool = False
    payload_entropy: float = 0.0
    suspicious_patterns: int = 0
    
    # Behavioral features
    request_rate: float = 0.0
    session_duration: float = 0.0
    unique_endpoints_accessed: int = 0
    error_rate: float = 0.0
    
    # Temporal features
    hour_of_day: int = 0
    day_of_week: int = 0
    is_weekend: bool = False
    
    # Security features
    has_potential_injection: bool = False
    has_suspicious_headers: bool = False
    has_unusual_encoding: bool = False
    
    # Aggregated features (computed over time windows)
    avg_request_size: float = 0.0
    request_frequency_variance: float = 0.0
    endpoint_diversity: float = 0.0
    
    def to_vector(self) -> np.ndarray:
        """Convert features to numerical vector for ML algorithms."""
        # Convert categorical features to numerical
        method_encoding = {
            'GET': 1, 'POST': 2, 'PUT': 3, 'DELETE': 4,
            'PATCH': 5, 'HEAD': 6, 'OPTIONS': 7
        }.get(self.method.upper(), 0)
        
        vector = np.array([
            # Request metadata (7 features)
            method_encoding,
            self.path_length,
            self.query_param_count,
            self.header_count,
            self.user_agent_length,
            self.content_length,
            
            # Network features (2 features)
            int(self.is_private_ip),
            hash(self.geolocation_country) % 1000,  # Simple country encoding
            
            # Payload features (4 features)
            int(self.has_json_payload),
            int(self.has_form_payload),
            self.payload_entropy,
            self.suspicious_patterns,
            
            # Behavioral features (4 features)
            self.request_rate,
            self.session_duration,
            self.unique_endpoints_accessed,
            self.error_rate,
            
            # Temporal features (3 features)
            self.hour_of_day,
            self.day_of_week,
            int(self.is_weekend),
            
            # Security features (3 features)
            int(self.has_potential_injection),
            int(self.has_suspicious_headers),
            int(self.has_unusual_encoding),
            
            # Aggregated features (3 features)
            self.avg_request_size,
            self.request_frequency_variance,
            self.endpoint_diversity
        ], dtype=np.float32)
        
        return vector


@dataclass 
class AnomalyResult:
    """Result of anomaly detection analysis."""
    is_anomaly: bool
    confidence_score: float  # 0.0 to 1.0
    anomaly_type: AnomalyType
    threat_level: ThreatLevel
    explanation: str
    features_contributing: List[str]
    recommended_action: SecurityAction
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "is_anomaly": self.is_anomaly,
            "confidence_score": self.confidence_score,
            "anomaly_type": self.anomaly_type.value,
            "threat_level": self.threat_level.value,
            "explanation": self.explanation,
            "features_contributing": self.features_contributing,
            "recommended_action": self.recommended_action.value
        }


@dataclass
class ThreatIntelligence:
    """Threat intelligence data point."""
    indicator: str
    indicator_type: str  # ip, domain, hash, etc.
    threat_level: ThreatLevel
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityMetrics:
    """ML security system metrics."""
    total_requests_analyzed: int = 0
    anomalies_detected: int = 0
    threats_blocked: int = 0
    false_positive_rate: float = 0.0
    model_accuracy: float = 0.0
    average_inference_time: float = 0.0
    adaptive_rules_created: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_requests_analyzed": self.total_requests_analyzed,
            "anomalies_detected": self.anomalies_detected,
            "threats_blocked": self.threats_blocked,
            "false_positive_rate": self.false_positive_rate,
            "model_accuracy": self.model_accuracy,
            "average_inference_time": self.average_inference_time,
            "adaptive_rules_created": self.adaptive_rules_created
        }


class RequestFeatureExtractor:
    """Extracts ML features from HTTP requests for security analysis."""
    
    def __init__(self):
        self.user_sessions: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'requests': deque(maxlen=100),
            'start_time': time.time(),
            'endpoints': set(),
            'errors': 0
        })
        self.request_history: deque = deque(maxlen=10000)
        self.suspicious_patterns = [
            r'(?i)(union\s+select|or\s+1\s*=\s*1|<script|javascript:)',  # SQL/XSS
            r'(?i)(\.\.\/|\.\.\\|%2e%2e%2f)',  # Path traversal
            r'(?i)(exec\s*\(|eval\s*\(|system\s*\()',  # Code execution
            r'(?i)(cmd\.exe|/bin/sh|/bin/bash)',  # Command injection
        ]
        self._lock = RLock()
    
    def extract_features(self, request: Request, client_ip: str = None) -> RequestFeatures:
        """Extract comprehensive features from HTTP request."""
        now = datetime.now()
        client_ip = client_ip or self._extract_client_ip(request)
        session_id = self._get_session_id(request, client_ip)
        
        with self._lock:
            # Update session tracking
            session = self.user_sessions[session_id]
            session['requests'].append({
                'timestamp': now,
                'path': request.url.path,
                'method': request.method,
                'size': self._get_content_length(request)
            })
            session['endpoints'].add(request.url.path)
            
            # Extract basic request features
            features = RequestFeatures(
                method=request.method,
                path=request.url.path,
                path_length=len(request.url.path),
                query_param_count=len(request.query_params),
                header_count=len(request.headers),
                user_agent_length=len(request.headers.get('user-agent', '')),
                content_length=self._get_content_length(request),
                client_ip=client_ip,
                is_private_ip=self._is_private_ip(client_ip),
                hour_of_day=now.hour,
                day_of_week=now.weekday(),
                is_weekend=(now.weekday() >= 5)
            )
            
            # Extract payload features
            self._extract_payload_features(request, features)
            
            # Extract behavioral features
            self._extract_behavioral_features(session, features)
            
            # Extract security features
            self._extract_security_features(request, features)
            
            # Extract aggregated features
            self._extract_aggregated_features(features)
            
            # Store in history
            self.request_history.append({
                'timestamp': now,
                'features': features,
                'client_ip': client_ip,
                'session_id': session_id
            })
            
            return features
    
    def _extract_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        return getattr(request.client, 'host', '127.0.0.1')
    
    def _get_session_id(self, request: Request, client_ip: str) -> str:
        """Generate session identifier."""
        session_cookie = request.cookies.get('session_id')
        if session_cookie:
            return hashlib.md5(session_cookie.encode()).hexdigest()
        
        user_agent = request.headers.get('user-agent', '')
        return hashlib.md5(f"{client_ip}-{user_agent}".encode()).hexdigest()
    
    def _get_content_length(self, request: Request) -> int:
        """Get request content length."""
        content_length = request.headers.get('content-length')
        if content_length:
            try:
                return int(content_length)
            except ValueError:
                pass
        return 0
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP address is private."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False
    
    def _extract_payload_features(self, request: Request, features: RequestFeatures):
        """Extract payload-related features."""
        content_type = request.headers.get('content-type', '').lower()
        features.has_json_payload = 'application/json' in content_type
        features.has_form_payload = 'application/x-www-form-urlencoded' in content_type
        
        # Calculate payload entropy (simplified)
        if hasattr(request, '_body') and request._body:
            payload = request._body.decode('utf-8', errors='ignore')
            features.payload_entropy = self._calculate_entropy(payload)
        
        # Count suspicious patterns
        full_url = str(request.url)
        for pattern in self.suspicious_patterns:
            if re.search(pattern, full_url):
                features.suspicious_patterns += 1
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _extract_behavioral_features(self, session: Dict, features: RequestFeatures):
        """Extract behavioral features from session data."""
        requests = session['requests']
        if not requests:
            return
        
        now = time.time()
        session_duration = now - session['start_time']
        
        # Calculate request rate (requests per minute)
        recent_requests = [r for r in requests 
                          if (now - r['timestamp'].timestamp()) < 300]  # Last 5 minutes
        features.request_rate = len(recent_requests) / 5.0  # Per minute
        
        features.session_duration = session_duration
        features.unique_endpoints_accessed = len(session['endpoints'])
        
        # Calculate error rate (simplified)
        if len(requests) > 0:
            features.error_rate = session.get('errors', 0) / len(requests)
    
    def _extract_security_features(self, request: Request, features: RequestFeatures):
        """Extract security-related features."""
        full_url = str(request.url).lower()
        headers = {k.lower(): v.lower() for k, v in request.headers.items()}
        
        # Check for potential injection attacks
        injection_patterns = [
            'union select', 'or 1=1', '<script', 'javascript:',
            '../', '..\\', 'exec(', 'eval(', 'system('
        ]
        features.has_potential_injection = any(pattern in full_url for pattern in injection_patterns)
        
        # Check for suspicious headers
        suspicious_headers = [
            'x-forwarded-host', 'x-cluster-client-ip', 'x-real-ip'
        ]
        features.has_suspicious_headers = any(header in headers for header in suspicious_headers)
        
        # Check for unusual encoding
        features.has_unusual_encoding = '%' in full_url and full_url.count('%') > 5
    
    def _extract_aggregated_features(self, features: RequestFeatures):
        """Extract aggregated features from historical data."""
        if len(self.request_history) < 10:
            return
        
        recent_requests = list(self.request_history)[-50:]  # Last 50 requests
        
        # Calculate average request size
        sizes = [r['features'].content_length for r in recent_requests]
        if sizes:
            features.avg_request_size = statistics.mean(sizes)
        
        # Calculate request frequency variance
        timestamps = [r['timestamp'].timestamp() for r in recent_requests]
        if len(timestamps) > 1:
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            if intervals:
                features.request_frequency_variance = statistics.variance(intervals)
        
        # Calculate endpoint diversity
        endpoints = set(r['features'].path for r in recent_requests)
        features.endpoint_diversity = len(endpoints) / len(recent_requests)


class AnomalyDetectionEngine:
    """ML-based anomaly detection engine with multiple algorithms."""
    
    def __init__(self, model_type: MLModelType = MLModelType.ENSEMBLE):
        self.model_type = model_type
        self.models: Dict[str, Any] = {}
        self.scalers: Dict[str, StandardScaler] = {}
        self.is_trained = False
        self.training_data: List[np.ndarray] = []
        self.training_labels: List[int] = []
        self._lock = RLock()
        
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn not available. Some ML features will be limited.")
            return
        
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models."""
        if not SKLEARN_AVAILABLE:
            return
        
        with self._lock:
            if self.model_type in [MLModelType.ISOLATION_FOREST, MLModelType.ENSEMBLE]:
                self.models['isolation_forest'] = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                )
                self.scalers['isolation_forest'] = StandardScaler()
            
            if self.model_type in [MLModelType.ONE_CLASS_SVM, MLModelType.ENSEMBLE]:
                self.models['one_class_svm'] = OneClassSVM(
                    kernel='rbf',
                    gamma='scale',
                    nu=0.1
                )
                self.scalers['one_class_svm'] = StandardScaler()
            
            if self.model_type in [MLModelType.DBSCAN, MLModelType.ENSEMBLE]:
                self.models['dbscan'] = DBSCAN(
                    eps=0.5,
                    min_samples=5
                )
                self.scalers['dbscan'] = StandardScaler()
    
    def add_training_data(self, features: RequestFeatures, is_anomaly: bool = False):
        """Add training data point."""
        if not SKLEARN_AVAILABLE:
            return
        
        with self._lock:
            vector = features.to_vector()
            self.training_data.append(vector)
            self.training_labels.append(1 if is_anomaly else 0)
            
            # Auto-train when we have enough data
            if len(self.training_data) >= 1000 and not self.is_trained:
                self.train_models()
    
    def train_models(self, force_retrain: bool = False):
        """Train anomaly detection models."""
        if not SKLEARN_AVAILABLE or (self.is_trained and not force_retrain):
            return
        
        if len(self.training_data) < 100:
            logger.warning("Not enough training data for ML models")
            return
        
        with self._lock:
            X = np.array(self.training_data)
            y = np.array(self.training_labels)
            
            # For unsupervised learning, we use only normal data
            normal_data = X[y == 0]
            
            for model_name, model in self.models.items():
                try:
                    logger.info(f"Training {model_name} model...")
                    
                    # Scale the data
                    scaler = self.scalers[model_name]
                    X_scaled = scaler.fit_transform(normal_data)
                    
                    if model_name == 'dbscan':
                        # DBSCAN doesn't need explicit training
                        pass
                    else:
                        # Train the model
                        model.fit(X_scaled)
                    
                    logger.info(f"Successfully trained {model_name}")
                    
                except Exception as e:
                    logger.error(f"Error training {model_name}: {e}")
            
            self.is_trained = True
            logger.info("Anomaly detection models trained successfully")
    
    def detect_anomaly(self, features: RequestFeatures) -> AnomalyResult:
        """Detect anomalies using trained models."""
        if not SKLEARN_AVAILABLE:
            return AnomalyResult(
                is_anomaly=False,
                confidence_score=0.0,
                anomaly_type=AnomalyType.REQUEST_PATTERN,
                threat_level=ThreatLevel.LOW,
                explanation="ML libraries not available",
                features_contributing=[],
                recommended_action=SecurityAction.ALLOW
            )
        
        if not self.is_trained:
            # Use rule-based detection as fallback
            return self._rule_based_detection(features)
        
        vector = features.to_vector()
        anomaly_scores = {}
        predictions = {}
        
        with self._lock:
            for model_name, model in self.models.items():
                try:
                    scaler = self.scalers[model_name]
                    X_scaled = scaler.transform(vector.reshape(1, -1))
                    
                    if model_name == 'isolation_forest':
                        pred = model.predict(X_scaled)[0]
                        score = model.decision_function(X_scaled)[0]
                        predictions[model_name] = pred == -1  # -1 indicates anomaly
                        anomaly_scores[model_name] = abs(score)
                        
                    elif model_name == 'one_class_svm':
                        pred = model.predict(X_scaled)[0]
                        score = model.decision_function(X_scaled)[0]
                        predictions[model_name] = pred == -1
                        anomaly_scores[model_name] = abs(score)
                        
                    elif model_name == 'dbscan':
                        # For DBSCAN, we check if the point would be an outlier
                        labels = model.fit_predict(X_scaled)
                        predictions[model_name] = labels[0] == -1
                        anomaly_scores[model_name] = 0.5 if labels[0] == -1 else 0.1
                        
                except Exception as e:
                    logger.error(f"Error in {model_name} prediction: {e}")
                    predictions[model_name] = False
                    anomaly_scores[model_name] = 0.0
        
        # Ensemble decision
        if self.model_type == MLModelType.ENSEMBLE:
            anomaly_votes = sum(predictions.values())
            is_anomaly = anomaly_votes >= (len(predictions) // 2 + 1)
            confidence_score = statistics.mean(anomaly_scores.values())
        else:
            model_name = self.model_type.value
            is_anomaly = predictions.get(model_name, False)
            confidence_score = anomaly_scores.get(model_name, 0.0)
        
        # Determine anomaly type and threat level
        anomaly_type = self._classify_anomaly_type(features)
        threat_level = self._assess_threat_level(confidence_score, features)
        
        # Generate explanation
        explanation = self._generate_explanation(features, anomaly_scores, predictions)
        
        # Get contributing features
        contributing_features = self._get_contributing_features(features, vector)
        
        # Recommend action
        recommended_action = self._recommend_action(threat_level, anomaly_type)
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            confidence_score=confidence_score,
            anomaly_type=anomaly_type,
            threat_level=threat_level,
            explanation=explanation,
            features_contributing=contributing_features,
            recommended_action=recommended_action
        )
    
    def _rule_based_detection(self, features: RequestFeatures) -> AnomalyResult:
        """Fallback rule-based anomaly detection."""
        anomaly_score = 0.0
        contributing_features = []
        
        # High request rate
        if features.request_rate > 100:  # More than 100 requests per minute
            anomaly_score += 0.3
            contributing_features.append("high_request_rate")
        
        # Suspicious patterns
        if features.suspicious_patterns > 0:
            anomaly_score += 0.4
            contributing_features.append("suspicious_patterns")
        
        # Potential injection
        if features.has_potential_injection:
            anomaly_score += 0.5
            contributing_features.append("potential_injection")
        
        # High payload entropy
        if features.payload_entropy > 7.0:
            anomaly_score += 0.2
            contributing_features.append("high_entropy")
        
        # Unusual encoding
        if features.has_unusual_encoding:
            anomaly_score += 0.3
            contributing_features.append("unusual_encoding")
        
        is_anomaly = anomaly_score > 0.5
        threat_level = self._assess_threat_level(anomaly_score, features)
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            confidence_score=min(anomaly_score, 1.0),
            anomaly_type=AnomalyType.REQUEST_PATTERN,
            threat_level=threat_level,
            explanation=f"Rule-based detection: {', '.join(contributing_features)}",
            features_contributing=contributing_features,
            recommended_action=self._recommend_action(threat_level, AnomalyType.REQUEST_PATTERN)
        )
    
    def _classify_anomaly_type(self, features: RequestFeatures) -> AnomalyType:
        """Classify the type of anomaly based on features."""
        if features.request_rate > 50:
            return AnomalyType.RATE_ANOMALY
        elif features.payload_entropy > 6.0 or features.suspicious_patterns > 0:
            return AnomalyType.PAYLOAD_ANOMALY
        elif features.has_potential_injection or features.has_suspicious_headers:
            return AnomalyType.REQUEST_PATTERN
        elif features.hour_of_day < 6 or features.hour_of_day > 22:
            return AnomalyType.TIME_ANOMALY
        else:
            return AnomalyType.BEHAVIORAL_ANOMALY
    
    def _assess_threat_level(self, confidence_score: float, features: RequestFeatures) -> ThreatLevel:
        """Assess threat level based on confidence and features."""
        if confidence_score > 0.8 or features.has_potential_injection:
            return ThreatLevel.CRITICAL
        elif confidence_score > 0.6 or features.suspicious_patterns > 2:
            return ThreatLevel.HIGH
        elif confidence_score > 0.4 or features.request_rate > 100:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _generate_explanation(self, features: RequestFeatures, scores: Dict, predictions: Dict) -> str:
        """Generate human-readable explanation."""
        explanations = []
        
        if any(predictions.values()):
            explanations.append("Multiple ML models detected anomalous behavior")
        
        if features.suspicious_patterns > 0:
            explanations.append(f"Found {features.suspicious_patterns} suspicious patterns")
        
        if features.request_rate > 50:
            explanations.append(f"High request rate: {features.request_rate:.1f}/min")
        
        if features.has_potential_injection:
            explanations.append("Potential injection attack detected")
        
        return ". ".join(explanations) or "Anomalous request pattern detected"
    
    def _get_contributing_features(self, features: RequestFeatures, vector: np.ndarray) -> List[str]:
        """Identify features contributing most to anomaly detection."""
        contributing = []
        
        # Simple feature importance based on values
        if features.request_rate > 50:
            contributing.append("request_rate")
        if features.suspicious_patterns > 0:
            contributing.append("suspicious_patterns")
        if features.payload_entropy > 6.0:
            contributing.append("payload_entropy")
        if features.path_length > 100:
            contributing.append("path_length")
        if features.has_potential_injection:
            contributing.append("potential_injection")
        
        return contributing[:5]  # Return top 5
    
    def _recommend_action(self, threat_level: ThreatLevel, anomaly_type: AnomalyType) -> SecurityAction:
        """Recommend security action based on threat assessment."""
        if threat_level == ThreatLevel.CRITICAL:
            return SecurityAction.BLOCK
        elif threat_level == ThreatLevel.HIGH:
            if anomaly_type in [AnomalyType.PAYLOAD_ANOMALY, AnomalyType.REQUEST_PATTERN]:
                return SecurityAction.BLOCK
            else:
                return SecurityAction.THROTTLE
        elif threat_level == ThreatLevel.MEDIUM:
            if anomaly_type == AnomalyType.RATE_ANOMALY:
                return SecurityAction.THROTTLE
            else:
                return SecurityAction.WARN
        else:
            return SecurityAction.ALLOW


class ThreatIntelligenceManager:
    """Manages threat intelligence data and scoring."""
    
    def __init__(self):
        self.threat_db: Dict[str, ThreatIntelligence] = {}
        self.ip_reputation: Dict[str, float] = {}  # IP -> reputation score (0-1)
        self.domain_reputation: Dict[str, float] = {}
        self.known_attack_patterns: Set[str] = set()
        self._lock = RLock()
        
        # Initialize with common attack patterns
        self._initialize_attack_patterns()
    
    def _initialize_attack_patterns(self):
        """Initialize with common attack patterns."""
        common_patterns = [
            # SQL Injection patterns
            "' or '1'='1",
            "union select",
            "drop table",
            "insert into",
            
            # XSS patterns
            "<script>",
            "javascript:",
            "onerror=",
            "onload=",
            
            # Command injection
            "; cat /etc/passwd",
            "&& dir",
            "| nc ",
            
            # Path traversal
            "../../../",
            "..\\..\\..\\",
            "%2e%2e%2f",
        ]
        
        self.known_attack_patterns.update(common_patterns)
    
    def add_threat_intelligence(self, threat: ThreatIntelligence):
        """Add threat intelligence data."""
        with self._lock:
            self.threat_db[threat.indicator] = threat
            
            # Update reputation scores
            if threat.indicator_type == "ip":
                reputation_score = 1.0 - (threat.confidence * 
                                        (1.0 if threat.threat_level == ThreatLevel.CRITICAL else
                                         0.8 if threat.threat_level == ThreatLevel.HIGH else
                                         0.6 if threat.threat_level == ThreatLevel.MEDIUM else 0.4))
                self.ip_reputation[threat.indicator] = max(0.0, reputation_score)
            
            elif threat.indicator_type == "domain":
                reputation_score = 1.0 - (threat.confidence * 
                                        (1.0 if threat.threat_level == ThreatLevel.CRITICAL else
                                         0.8 if threat.threat_level == ThreatLevel.HIGH else
                                         0.6 if threat.threat_level == ThreatLevel.MEDIUM else 0.4))
                self.domain_reputation[threat.indicator] = max(0.0, reputation_score)
    
    def score_request_threat(self, request: Request, client_ip: str) -> Tuple[float, List[str]]:
        """Score request threat level based on intelligence."""
        threat_score = 0.0
        threat_indicators = []
        
        with self._lock:
            # Check IP reputation
            if client_ip in self.ip_reputation:
                ip_score = 1.0 - self.ip_reputation[client_ip]
                threat_score += ip_score * 0.4
                if ip_score > 0.5:
                    threat_indicators.append(f"malicious_ip:{client_ip}")
            
            # Check for known attack patterns in URL and headers
            full_request = str(request.url) + " " + str(dict(request.headers))
            
            pattern_matches = 0
            for pattern in self.known_attack_patterns:
                if pattern.lower() in full_request.lower():
                    pattern_matches += 1
                    threat_indicators.append(f"attack_pattern:{pattern}")
            
            if pattern_matches > 0:
                threat_score += min(pattern_matches * 0.2, 0.6)
            
            # Check referer domain reputation
            referer = request.headers.get('referer', '')
            if referer:
                try:
                    domain = urlparse(referer).netloc
                    if domain in self.domain_reputation:
                        domain_score = 1.0 - self.domain_reputation[domain]
                        threat_score += domain_score * 0.2
                        if domain_score > 0.5:
                            threat_indicators.append(f"malicious_referer:{domain}")
                except Exception:
                    pass
            
            # Check user agent for known malicious patterns
            user_agent = request.headers.get('user-agent', '').lower()
            malicious_ua_patterns = [
                'sqlmap', 'nikto', 'nmap', 'masscan', 'nessus',
                'openvas', 'w3af', 'burpsuite', 'metasploit'
            ]
            
            for pattern in malicious_ua_patterns:
                if pattern in user_agent:
                    threat_score += 0.3
                    threat_indicators.append(f"malicious_ua:{pattern}")
                    break
        
        return min(threat_score, 1.0), threat_indicators
    
    def update_reputation(self, indicator: str, indicator_type: str, 
                         new_score: float, source: str = "feedback"):
        """Update reputation score based on feedback."""
        with self._lock:
            if indicator_type == "ip":
                current_score = self.ip_reputation.get(indicator, 0.5)
                # Weighted average with more weight to recent feedback
                updated_score = (current_score * 0.7) + (new_score * 0.3)
                self.ip_reputation[indicator] = max(0.0, min(1.0, updated_score))
            
            elif indicator_type == "domain":
                current_score = self.domain_reputation.get(indicator, 0.5)
                updated_score = (current_score * 0.7) + (new_score * 0.3)
                self.domain_reputation[indicator] = max(0.0, min(1.0, updated_score))
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get threat intelligence summary."""
        with self._lock:
            return {
                "total_indicators": len(self.threat_db),
                "ip_indicators": len(self.ip_reputation),
                "domain_indicators": len(self.domain_reputation),
                "attack_patterns": len(self.known_attack_patterns),
                "critical_threats": len([t for t in self.threat_db.values() 
                                       if t.threat_level == ThreatLevel.CRITICAL]),
                "high_threats": len([t for t in self.threat_db.values() 
                                   if t.threat_level == ThreatLevel.HIGH])
            }


class AdaptiveSecurityManager:
    """Manages adaptive security policies based on ML analysis."""
    
    def __init__(self, base_rate_limit: int = 100):
        self.base_rate_limit = base_rate_limit
        self.adaptive_rules: Dict[str, Dict[str, Any]] = {}
        self.client_profiles: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'trust_score': 0.5,
            'request_history': deque(maxlen=1000),
            'anomaly_count': 0,
            'last_seen': time.time(),
            'rate_limit': base_rate_limit
        })
        self._lock = RLock()
    
    def update_client_profile(self, client_ip: str, anomaly_result: AnomalyResult,
                            threat_score: float, request_features: RequestFeatures):
        """Update client profile based on analysis results."""
        with self._lock:
            profile = self.client_profiles[client_ip]
            profile['last_seen'] = time.time()
            profile['request_history'].append({
                'timestamp': time.time(),
                'anomaly': anomaly_result.is_anomaly,
                'threat_score': threat_score,
                'features': request_features
            })
            
            if anomaly_result.is_anomaly:
                profile['anomaly_count'] += 1
            
            # Update trust score
            self._update_trust_score(profile, anomaly_result, threat_score)
            
            # Adapt rate limiting
            self._adapt_rate_limiting(profile, client_ip)
            
            # Create adaptive rules if needed
            self._create_adaptive_rules(client_ip, profile, anomaly_result)
    
    def _update_trust_score(self, profile: Dict, anomaly_result: AnomalyResult, threat_score: float):
        """Update client trust score."""
        current_trust = profile['trust_score']
        
        if anomaly_result.is_anomaly:
            # Decrease trust based on threat level
            if anomaly_result.threat_level == ThreatLevel.CRITICAL:
                trust_delta = -0.3
            elif anomaly_result.threat_level == ThreatLevel.HIGH:
                trust_delta = -0.2
            elif anomaly_result.threat_level == ThreatLevel.MEDIUM:
                trust_delta = -0.1
            else:
                trust_delta = -0.05
        else:
            # Slowly increase trust for normal behavior
            trust_delta = 0.01
        
        # Factor in threat intelligence score
        trust_delta -= threat_score * 0.1
        
        profile['trust_score'] = max(0.0, min(1.0, current_trust + trust_delta))
    
    def _adapt_rate_limiting(self, profile: Dict, client_ip: str):
        """Adapt rate limiting based on trust score."""
        trust_score = profile['trust_score']
        
        if trust_score > 0.8:
            # High trust - increase rate limit
            new_rate_limit = int(self.base_rate_limit * 1.5)
        elif trust_score > 0.6:
            # Medium trust - normal rate limit
            new_rate_limit = self.base_rate_limit
        elif trust_score > 0.3:
            # Low trust - reduce rate limit
            new_rate_limit = int(self.base_rate_limit * 0.5)
        else:
            # Very low trust - strict rate limit
            new_rate_limit = int(self.base_rate_limit * 0.1)
        
        profile['rate_limit'] = max(1, new_rate_limit)
    
    def _create_adaptive_rules(self, client_ip: str, profile: Dict, anomaly_result: AnomalyResult):
        """Create adaptive security rules."""
        if not anomaly_result.is_anomaly:
            return
        
        rule_id = f"adaptive_{client_ip}_{int(time.time())}"
        
        # Create rule based on anomaly type
        if anomaly_result.anomaly_type == AnomalyType.RATE_ANOMALY:
            rule = {
                'type': 'rate_limit',
                'client_ip': client_ip,
                'limit': max(1, profile['rate_limit'] // 2),
                'duration': 300,  # 5 minutes
                'created': time.time(),
                'reason': 'Rate anomaly detected'
            }
        
        elif anomaly_result.anomaly_type == AnomalyType.PAYLOAD_ANOMALY:
            rule = {
                'type': 'payload_inspection',
                'client_ip': client_ip,
                'strict_validation': True,
                'duration': 600,  # 10 minutes
                'created': time.time(),
                'reason': 'Payload anomaly detected'
            }
        
        else:
            rule = {
                'type': 'enhanced_monitoring',
                'client_ip': client_ip,
                'log_all_requests': True,
                'duration': 300,
                'created': time.time(),
                'reason': f'{anomaly_result.anomaly_type.value} detected'
            }
        
        with self._lock:
            self.adaptive_rules[rule_id] = rule
    
    def get_client_rate_limit(self, client_ip: str) -> int:
        """Get adaptive rate limit for client."""
        with self._lock:
            return self.client_profiles[client_ip]['rate_limit']
    
    def get_client_trust_score(self, client_ip: str) -> float:
        """Get client trust score."""
        with self._lock:
            return self.client_profiles[client_ip]['trust_score']
    
    def should_apply_strict_validation(self, client_ip: str) -> bool:
        """Check if strict validation should be applied."""
        with self._lock:
            current_time = time.time()
            
            # Check for active payload inspection rules
            for rule in self.adaptive_rules.values():
                if (rule.get('client_ip') == client_ip and 
                    rule.get('type') == 'payload_inspection' and
                    current_time - rule['created'] < rule['duration']):
                    return True
            
            # Also apply if trust score is very low
            return self.client_profiles[client_ip]['trust_score'] < 0.2
    
    def cleanup_expired_rules(self):
        """Remove expired adaptive rules."""
        current_time = time.time()
        expired_rules = []
        
        with self._lock:
            for rule_id, rule in self.adaptive_rules.items():
                if current_time - rule['created'] > rule.get('duration', 300):
                    expired_rules.append(rule_id)
            
            for rule_id in expired_rules:
                del self.adaptive_rules[rule_id]
    
    def get_adaptive_stats(self) -> Dict[str, Any]:
        """Get adaptive security statistics."""
        with self._lock:
            trust_scores = [p['trust_score'] for p in self.client_profiles.values()]
            
            return {
                'total_clients': len(self.client_profiles),
                'active_rules': len(self.adaptive_rules),
                'avg_trust_score': statistics.mean(trust_scores) if trust_scores else 0.0,
                'high_trust_clients': len([s for s in trust_scores if s > 0.8]),
                'low_trust_clients': len([s for s in trust_scores if s < 0.3]),
                'rule_types': {
                    rule['type']: len([r for r in self.adaptive_rules.values() if r['type'] == rule['type']])
                    for rule in self.adaptive_rules.values()
                }
            }


class ThreatPredictionEngine:
    """Real-time threat prediction engine using ML."""
    
    def __init__(self):
        self.prediction_model = None
        self.feature_scaler = None
        self.sequence_length = 10  # Number of recent requests to consider
        self.client_sequences: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.sequence_length))
        self._lock = RLock()
        
        if TENSORFLOW_AVAILABLE:
            self._build_prediction_model()
    
    def _build_prediction_model(self):
        """Build neural network for threat prediction."""
        if not TENSORFLOW_AVAILABLE:
            return
        
        # Simple LSTM model for sequence prediction
        model = keras.Sequential([
            keras.layers.LSTM(64, return_sequences=True, input_shape=(self.sequence_length, 30)),
            keras.layers.LSTM(32),
            keras.layers.Dense(16, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(1, activation='sigmoid')  # Binary classification
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        self.prediction_model = model
        self.feature_scaler = StandardScaler() if SKLEARN_AVAILABLE else None
    
    def add_request_sequence(self, client_ip: str, features: RequestFeatures, is_threat: bool = False):
        """Add request to client sequence for prediction training."""
        with self._lock:
            vector = features.to_vector()
            
            self.client_sequences[client_ip].append({
                'features': vector,
                'is_threat': is_threat,
                'timestamp': time.time()
            })
    
    def predict_threat_probability(self, client_ip: str, current_features: RequestFeatures) -> float:
        """Predict probability of threat based on request sequence."""
        if not TENSORFLOW_AVAILABLE or self.prediction_model is None:
            return self._fallback_prediction(client_ip, current_features)
        
        with self._lock:
            sequence = list(self.client_sequences[client_ip])
            
            if len(sequence) < self.sequence_length:
                # Not enough history, use heuristic
                return self._heuristic_prediction(current_features)
            
            try:
                # Prepare sequence data
                X = np.array([item['features'] for item in sequence])
                X = X.reshape(1, self.sequence_length, -1)
                
                # Scale if scaler is available
                if self.feature_scaler and hasattr(self.feature_scaler, 'transform'):
                    # Reshape for scaling
                    original_shape = X.shape
                    X_reshaped = X.reshape(-1, X.shape[-1])
                    X_scaled = self.feature_scaler.transform(X_reshaped)
                    X = X_scaled.reshape(original_shape)
                
                # Predict
                prediction = self.prediction_model.predict(X, verbose=0)[0][0]
                return float(prediction)
                
            except Exception as e:
                logger.error(f"Error in threat prediction: {e}")
                return self._heuristic_prediction(current_features)
    
    def _fallback_prediction(self, client_ip: str, features: RequestFeatures) -> float:
        """Fallback prediction when TensorFlow is not available."""
        return self._heuristic_prediction(features)
    
    def _heuristic_prediction(self, features: RequestFeatures) -> float:
        """Heuristic-based threat prediction."""
        threat_score = 0.0
        
        # High request rate indicator
        if features.request_rate > 60:
            threat_score += 0.3
        
        # Suspicious patterns
        if features.suspicious_patterns > 0:
            threat_score += features.suspicious_patterns * 0.15
        
        # Injection attempts
        if features.has_potential_injection:
            threat_score += 0.4
        
        # Unusual encoding
        if features.has_unusual_encoding:
            threat_score += 0.2
        
        # High entropy payload
        if features.payload_entropy > 6.0:
            threat_score += 0.25
        
        # Time-based anomalies
        if features.hour_of_day < 6 or features.hour_of_day > 22:
            threat_score += 0.1
        
        return min(threat_score, 1.0)
    
    def train_prediction_model(self, force_retrain: bool = False):
        """Train the threat prediction model."""
        if not TENSORFLOW_AVAILABLE or not self.prediction_model:
            return
        
        # Collect training data from sequences
        training_sequences = []
        training_labels = []
        
        with self._lock:
            for client_sequences in self.client_sequences.values():
                if len(client_sequences) >= self.sequence_length:
                    sequences_list = list(client_sequences)
                    
                    for i in range(len(sequences_list) - self.sequence_length + 1):
                        sequence = sequences_list[i:i + self.sequence_length]
                        
                        # Use features as input
                        X_sequence = np.array([item['features'] for item in sequence])
                        training_sequences.append(X_sequence)
                        
                        # Use any threat in sequence as label
                        has_threat = any(item['is_threat'] for item in sequence)
                        training_labels.append(1 if has_threat else 0)
        
        if len(training_sequences) < 100:
            logger.warning("Not enough sequences for training prediction model")
            return
        
        try:
            X = np.array(training_sequences)
            y = np.array(training_labels)
            
            # Scale features
            if self.feature_scaler and SKLEARN_AVAILABLE:
                original_shape = X.shape
                X_reshaped = X.reshape(-1, X.shape[-1])
                X_scaled = self.feature_scaler.fit_transform(X_reshaped)
                X = X_scaled.reshape(original_shape)
            
            # Train model
            logger.info("Training threat prediction model...")
            self.prediction_model.fit(
                X, y,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            logger.info("Threat prediction model trained successfully")
            
        except Exception as e:
            logger.error(f"Error training prediction model: {e}")


class MLSecurityShield(Shield):
    """Complete ML-powered security shield for FastAPI."""
    
    def __init__(
        self,
        model_type: MLModelType = MLModelType.ENSEMBLE,
        enable_threat_intelligence: bool = True,
        enable_adaptive_policies: bool = True,
        enable_threat_prediction: bool = True,
        base_rate_limit: int = 100,
        **kwargs
    ):
        # Create shield function
        def shield_func(request: Request):
            return self._ml_security_analysis(request)
        
        super().__init__(shield_func, **kwargs)
        
        # Initialize components
        self.feature_extractor = RequestFeatureExtractor()
        self.anomaly_engine = AnomalyDetectionEngine(model_type)
        self.threat_intelligence = ThreatIntelligenceManager() if enable_threat_intelligence else None
        self.adaptive_manager = AdaptiveSecurityManager(base_rate_limit) if enable_adaptive_policies else None
        self.prediction_engine = ThreatPredictionEngine() if enable_threat_prediction else None
        
        # Metrics and monitoring
        self.metrics = SecurityMetrics()
        self.performance_metrics: deque = deque(maxlen=1000)
        
        # Background tasks
        self._running = False
        self._background_thread: Optional[Thread] = None
        
        self.start_background_tasks()
    
    async def _ml_security_analysis(self, request: Request) -> Optional[Response]:
        """Main ML security analysis."""
        start_time = time.perf_counter()
        client_ip = self._extract_client_ip(request)
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(request, client_ip)
            
            # Anomaly detection
            anomaly_result = self.anomaly_engine.detect_anomaly(features)
            
            # Threat intelligence scoring
            threat_score = 0.0
            threat_indicators = []
            if self.threat_intelligence:
                threat_score, threat_indicators = self.threat_intelligence.score_request_threat(request, client_ip)
            
            # Threat prediction
            prediction_score = 0.0
            if self.prediction_engine:
                prediction_score = self.prediction_engine.predict_threat_probability(client_ip, features)
                self.prediction_engine.add_request_sequence(
                    client_ip, features, 
                    is_threat=(anomaly_result.is_anomaly or threat_score > 0.7)
                )
            
            # Update adaptive policies
            if self.adaptive_manager:
                self.adaptive_manager.update_client_profile(
                    client_ip, anomaly_result, threat_score, features
                )
            
            # Combine all scores for final decision
            combined_score = max(
                anomaly_result.confidence_score,
                threat_score,
                prediction_score
            )
            
            # Update metrics
            self.metrics.total_requests_analyzed += 1
            if anomaly_result.is_anomaly:
                self.metrics.anomalies_detected += 1
            
            # Record performance
            processing_time = (time.perf_counter() - start_time) * 1000
            self.performance_metrics.append(processing_time)
            self.metrics.average_inference_time = statistics.mean(self.performance_metrics)
            
            # Determine response based on combined analysis
            return self._determine_response(
                request, client_ip, anomaly_result, threat_score, 
                prediction_score, combined_score, threat_indicators
            )
            
        except Exception as e:
            logger.error(f"Error in ML security analysis: {e}")
            return None  # Allow request on error
    
    def _determine_response(
        self,
        request: Request,
        client_ip: str,
        anomaly_result: AnomalyResult,
        threat_score: float,
        prediction_score: float,
        combined_score: float,
        threat_indicators: List[str]
    ) -> Optional[Response]:
        """Determine appropriate response based on ML analysis."""
        
        # Critical threats - immediate block
        if (combined_score > 0.9 or 
            anomaly_result.threat_level == ThreatLevel.CRITICAL or
            threat_score > 0.8):
            
            self.metrics.threats_blocked += 1
            
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by ML security analysis",
                    "threat_level": anomaly_result.threat_level.value,
                    "confidence": combined_score,
                    "indicators": threat_indicators[:3],  # Limit exposure
                    "request_id": str(uuid.uuid4())
                }
            )
        
        # High threats - rate limiting/throttling
        elif combined_score > 0.7 or anomaly_result.recommended_action == SecurityAction.THROTTLE:
            # Add rate limiting headers
            if self.adaptive_manager:
                rate_limit = self.adaptive_manager.get_client_rate_limit(client_ip)
                response = JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limited due to suspicious activity",
                        "retry_after": 60,
                        "request_id": str(uuid.uuid4())
                    }
                )
                response.headers["X-RateLimit-Limit"] = str(rate_limit)
                response.headers["X-RateLimit-Remaining"] = "0"
                response.headers["Retry-After"] = "60"
                return response
        
        # Medium threats - warnings and enhanced monitoring
        elif combined_score > 0.4:
            logger.warning(
                f"Suspicious activity detected from {client_ip}: "
                f"anomaly={anomaly_result.is_anomaly}, "
                f"threat_score={threat_score:.3f}, "
                f"prediction={prediction_score:.3f}"
            )
            
            # Add warning headers but allow request
            # This would be handled by middleware in practice
            return None
        
        # Low/no threat - allow with monitoring
        else:
            # Training data - add as normal behavior
            self.anomaly_engine.add_training_data(
                self.feature_extractor.extract_features(request, client_ip),
                is_anomaly=False
            )
            
            return None  # Allow request
    
    def _extract_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        return getattr(request.client, 'host', '127.0.0.1')
    
    def start_background_tasks(self):
        """Start background maintenance tasks."""
        if self._running:
            return
        
        self._running = True
        self._background_thread = Thread(target=self._background_worker, daemon=True)
        self._background_thread.start()
    
    def stop_background_tasks(self):
        """Stop background tasks."""
        self._running = False
        if self._background_thread:
            self._background_thread.join(timeout=5)
    
    def _background_worker(self):
        """Background worker for maintenance tasks."""
        while self._running:
            try:
                # Train models periodically
                if len(self.anomaly_engine.training_data) >= 500:
                    self.anomaly_engine.train_models()
                
                if self.prediction_engine and TENSORFLOW_AVAILABLE:
                    self.prediction_engine.train_prediction_model()
                
                # Cleanup expired adaptive rules
                if self.adaptive_manager:
                    self.adaptive_manager.cleanup_expired_rules()
                
                # Calculate model accuracy (simplified)
                if self.performance_metrics:
                    self.metrics.model_accuracy = min(1.0 - (self.metrics.anomalies_detected / 
                                                           max(self.metrics.total_requests_analyzed, 1)), 1.0)
                
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in background worker: {e}")
                time.sleep(60)  # Wait 1 minute on error
    
    def add_threat_feedback(self, request_id: str, is_false_positive: bool):
        """Add feedback for threat detection accuracy."""
        # This would be used to improve model accuracy
        # Implementation would store feedback and retrain models
        if is_false_positive:
            self.metrics.false_positive_rate = min(
                self.metrics.false_positive_rate + 0.001, 
                1.0
            )
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get comprehensive security metrics."""
        base_metrics = self.metrics.to_dict()
        
        additional_metrics = {}
        
        if self.threat_intelligence:
            additional_metrics['threat_intelligence'] = self.threat_intelligence.get_threat_summary()
        
        if self.adaptive_manager:
            additional_metrics['adaptive_security'] = self.adaptive_manager.get_adaptive_stats()
        
        if self.anomaly_engine:
            additional_metrics['ml_models'] = {
                'is_trained': self.anomaly_engine.is_trained,
                'training_samples': len(self.anomaly_engine.training_data),
                'model_type': self.anomaly_engine.model_type.value
            }
        
        return {**base_metrics, **additional_metrics}
    
    def export_model(self, filepath: str):
        """Export trained models for backup/deployment."""
        model_data = {
            'anomaly_engine': {
                'models': self.anomaly_engine.models if SKLEARN_AVAILABLE else {},
                'scalers': self.anomaly_engine.scalers if SKLEARN_AVAILABLE else {},
                'is_trained': self.anomaly_engine.is_trained
            },
            'threat_intelligence': {
                'ip_reputation': self.threat_intelligence.ip_reputation if self.threat_intelligence else {},
                'domain_reputation': self.threat_intelligence.domain_reputation if self.threat_intelligence else {},
                'attack_patterns': list(self.threat_intelligence.known_attack_patterns) if self.threat_intelligence else []
            },
            'metrics': self.metrics.to_dict()
        }
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"Models exported to {filepath}")
        except Exception as e:
            logger.error(f"Error exporting models: {e}")
    
    def load_model(self, filepath: str):
        """Load previously trained models."""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            # Load anomaly detection models
            if SKLEARN_AVAILABLE and 'anomaly_engine' in model_data:
                engine_data = model_data['anomaly_engine']
                self.anomaly_engine.models = engine_data.get('models', {})
                self.anomaly_engine.scalers = engine_data.get('scalers', {})
                self.anomaly_engine.is_trained = engine_data.get('is_trained', False)
            
            # Load threat intelligence
            if self.threat_intelligence and 'threat_intelligence' in model_data:
                ti_data = model_data['threat_intelligence']
                self.threat_intelligence.ip_reputation = ti_data.get('ip_reputation', {})
                self.threat_intelligence.domain_reputation = ti_data.get('domain_reputation', {})
                self.threat_intelligence.known_attack_patterns = set(ti_data.get('attack_patterns', []))
            
            logger.info(f"Models loaded from {filepath}")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")


# Convenience functions

def create_ml_security_shield(
    model_type: MLModelType = MLModelType.ENSEMBLE,
    enable_all_features: bool = True,
    **kwargs
) -> MLSecurityShield:
    """Create ML security shield with common configuration."""
    return MLSecurityShield(
        model_type=model_type,
        enable_threat_intelligence=enable_all_features,
        enable_adaptive_policies=enable_all_features,
        enable_threat_prediction=enable_all_features,
        **kwargs
    )


def ml_security_shield_decorator(
    model_type: MLModelType = MLModelType.ENSEMBLE,
    **kwargs
):
    """Decorator for creating ML security shields."""
    def decorator(func):
        shield_instance = create_ml_security_shield(model_type=model_type, **kwargs)
        return shield_instance(func)
    return decorator