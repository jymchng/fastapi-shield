"""Mock infrastructure for testing ML security functionality.

This module provides mock implementations of ML frameworks, threat intelligence
sources, and security infrastructure components to enable comprehensive testing
of the ML security system without requiring actual ML libraries or external
threat intelligence feeds.
"""

import time
import random
import hashlib
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from datetime import datetime, timedelta
import numpy as np
from unittest.mock import Mock, MagicMock
from fastapi import Request
from fastapi.testclient import TestClient
import uuid
import re
from urllib.parse import urlencode, parse_qs

from fastapi_shield.ml_security import (
    RequestFeatures, AnomalyResult, ThreatLevel, AnomalyType,
    SecurityAction, ThreatIntelligence, SecurityMetrics
)


@dataclass
class MockMLModel:
    """Mock ML model for testing."""
    name: str
    is_trained: bool = False
    training_data: List[np.ndarray] = field(default_factory=list)
    training_labels: List[int] = field(default_factory=list)
    prediction_accuracy: float = 0.85
    
    def fit(self, X, y=None):
        """Mock model training."""
        self.training_data = list(X) if hasattr(X, '__iter__') else [X]
        self.training_labels = list(y) if y is not None and hasattr(y, '__iter__') else [y] if y is not None else []
        self.is_trained = True
        time.sleep(0.01)  # Simulate training time
    
    def predict(self, X):
        """Mock prediction."""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        if not hasattr(X, '__iter__') or isinstance(X, str):
            X = [X]
        
        predictions = []
        for sample in X:
            # Simulate prediction logic
            if hasattr(sample, '__iter__') and not isinstance(sample, str):
                feature_sum = sum(float(x) for x in sample if isinstance(x, (int, float)))
                # Simple rule: anomaly if feature sum is high
                prediction = -1 if feature_sum > 50 else 1
            else:
                prediction = random.choice([-1, 1])
            
            # Add some randomness based on accuracy
            if random.random() > self.prediction_accuracy:
                prediction = -prediction
            
            predictions.append(prediction)
        
        return np.array(predictions)
    
    def decision_function(self, X):
        """Mock decision function."""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        if not hasattr(X, '__iter__') or isinstance(X, str):
            X = [X]
        
        scores = []
        for sample in X:
            if hasattr(sample, '__iter__') and not isinstance(sample, str):
                feature_sum = sum(float(x) for x in sample if isinstance(x, (int, float)))
                score = (feature_sum - 25) / 25.0  # Normalize around 25
            else:
                score = random.uniform(-2, 2)
            
            scores.append(score)
        
        return np.array(scores)


@dataclass
class MockScaler:
    """Mock StandardScaler for testing."""
    mean_: Optional[np.ndarray] = None
    scale_: Optional[np.ndarray] = None
    is_fitted: bool = False
    
    def fit(self, X, y=None):
        """Mock scaler fitting."""
        X_array = np.array(X)
        self.mean_ = np.mean(X_array, axis=0)
        self.scale_ = np.std(X_array, axis=0)
        self.scale_[self.scale_ == 0] = 1.0  # Avoid division by zero
        self.is_fitted = True
        return self
    
    def transform(self, X):
        """Mock scaling transformation."""
        if not self.is_fitted:
            raise ValueError("Scaler not fitted")
        
        X_array = np.array(X)
        return (X_array - self.mean_) / self.scale_
    
    def fit_transform(self, X, y=None):
        """Mock fit and transform."""
        return self.fit(X, y).transform(X)


class MockIsolationForest:
    """Mock Isolation Forest for testing."""
    
    def __init__(self, contamination=0.1, random_state=42, n_estimators=100):
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.is_fitted = False
        self.threshold = 0.0
    
    def fit(self, X, y=None):
        """Mock fitting."""
        self.is_fitted = True
        # Set threshold based on contamination rate
        self.threshold = -0.5 if self.contamination > 0.1 else -0.3
        return self
    
    def predict(self, X):
        """Mock prediction."""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        
        X_array = np.array(X)
        if len(X_array.shape) == 1:
            X_array = X_array.reshape(1, -1)
        
        predictions = []
        for sample in X_array:
            # Simple heuristic: anomaly if sum of features is high
            feature_sum = np.sum(sample)
            prediction = -1 if feature_sum > 50 else 1
            predictions.append(prediction)
        
        return np.array(predictions)
    
    def decision_function(self, X):
        """Mock decision function."""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        
        X_array = np.array(X)
        if len(X_array.shape) == 1:
            X_array = X_array.reshape(1, -1)
        
        scores = []
        for sample in X_array:
            feature_sum = np.sum(sample)
            score = (25 - feature_sum) / 25.0  # Higher negative score = more anomalous
            scores.append(score)
        
        return np.array(scores)


class MockOneClassSVM:
    """Mock One-Class SVM for testing."""
    
    def __init__(self, kernel='rbf', gamma='scale', nu=0.1):
        self.kernel = kernel
        self.gamma = gamma
        self.nu = nu
        self.is_fitted = False
    
    def fit(self, X, y=None):
        """Mock fitting."""
        self.is_fitted = True
        return self
    
    def predict(self, X):
        """Mock prediction."""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        
        X_array = np.array(X)
        if len(X_array.shape) == 1:
            X_array = X_array.reshape(1, -1)
        
        predictions = []
        for sample in X_array:
            # Different heuristic than Isolation Forest
            variance = np.var(sample)
            prediction = -1 if variance > 100 else 1
            predictions.append(prediction)
        
        return np.array(predictions)
    
    def decision_function(self, X):
        """Mock decision function."""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        
        X_array = np.array(X)
        if len(X_array.shape) == 1:
            X_array = X_array.reshape(1, -1)
        
        scores = []
        for sample in X_array:
            variance = np.var(sample)
            score = (50 - variance) / 50.0
            scores.append(score)
        
        return np.array(scores)


class MockDBSCAN:
    """Mock DBSCAN for testing."""
    
    def __init__(self, eps=0.5, min_samples=5):
        self.eps = eps
        self.min_samples = min_samples
    
    def fit_predict(self, X):
        """Mock fit and predict."""
        X_array = np.array(X)
        if len(X_array.shape) == 1:
            X_array = X_array.reshape(1, -1)
        
        # Simple clustering simulation
        labels = []
        for sample in X_array:
            # Outliers have label -1
            feature_sum = np.sum(sample)
            if feature_sum > 70 or feature_sum < 10:
                labels.append(-1)  # Outlier
            else:
                labels.append(0)   # Normal cluster
        
        return np.array(labels)


class MockTensorFlowModel:
    """Mock TensorFlow/Keras model for testing."""
    
    def __init__(self):
        self.layers = []
        self.is_compiled = False
        self.is_fitted = False
        self.history = None
    
    def compile(self, optimizer='adam', loss='binary_crossentropy', metrics=None):
        """Mock model compilation."""
        self.optimizer = optimizer
        self.loss = loss
        self.metrics = metrics or []
        self.is_compiled = True
    
    def fit(self, X, y, epochs=10, batch_size=32, validation_split=0.2, verbose=1):
        """Mock model training."""
        if not self.is_compiled:
            raise ValueError("Model not compiled")
        
        # Simulate training
        time.sleep(0.1)  # Simulate training time
        self.is_fitted = True
        
        # Mock training history
        self.history = Mock()
        self.history.history = {
            'loss': [random.uniform(0.4, 0.8) for _ in range(epochs)],
            'accuracy': [random.uniform(0.7, 0.95) for _ in range(epochs)],
            'val_loss': [random.uniform(0.5, 0.9) for _ in range(epochs)],
            'val_accuracy': [random.uniform(0.6, 0.9) for _ in range(epochs)]
        }
        
        return self.history
    
    def predict(self, X, verbose=0):
        """Mock prediction."""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        
        X_array = np.array(X)
        if len(X_array.shape) == 3:  # Sequence data
            predictions = []
            for sequence in X_array:
                # Simple prediction based on sequence statistics
                sequence_mean = np.mean(sequence)
                prediction = random.uniform(0.3, 0.7) if sequence_mean < 30 else random.uniform(0.6, 0.95)
                predictions.append([prediction])
            return np.array(predictions)
        else:
            # Regular prediction
            predictions = []
            for sample in X_array:
                prediction = random.uniform(0.2, 0.8)
                predictions.append([prediction])
            return np.array(predictions)


class MockThreatIntelligenceAPI:
    """Mock threat intelligence API for testing."""
    
    def __init__(self):
        self.malicious_ips = {
            "192.168.1.100": {"threat_level": "high", "confidence": 0.9, "source": "test"},
            "10.0.0.50": {"threat_level": "medium", "confidence": 0.7, "source": "test"},
            "203.0.113.195": {"threat_level": "critical", "confidence": 0.95, "source": "test"}
        }
        
        self.malicious_domains = {
            "evil.example.com": {"threat_level": "high", "confidence": 0.85, "source": "test"},
            "malware.test": {"threat_level": "critical", "confidence": 0.92, "source": "test"}
        }
        
        self.attack_patterns = [
            "' OR '1'='1",
            "UNION SELECT",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "cmd.exe",
            "/bin/sh"
        ]
        
        self.request_count = 0
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Mock IP reputation check."""
        self.request_count += 1
        
        if ip in self.malicious_ips:
            return {
                "malicious": True,
                "reputation_score": 0.1,  # Low score = bad reputation
                **self.malicious_ips[ip]
            }
        
        return {
            "malicious": False,
            "reputation_score": 0.8,  # High score = good reputation
            "threat_level": "low",
            "confidence": 0.3,
            "source": "test"
        }
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Mock domain reputation check."""
        self.request_count += 1
        
        if domain in self.malicious_domains:
            return {
                "malicious": True,
                "reputation_score": 0.2,
                **self.malicious_domains[domain]
            }
        
        return {
            "malicious": False,
            "reputation_score": 0.75,
            "threat_level": "low",
            "confidence": 0.4,
            "source": "test"
        }
    
    def scan_for_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Mock pattern scanning."""
        self.request_count += 1
        found_patterns = []
        
        content_lower = content.lower()
        for pattern in self.attack_patterns:
            if pattern.lower() in content_lower:
                found_patterns.append({
                    "pattern": pattern,
                    "type": "injection" if "union" in pattern.lower() or "or" in pattern.lower() else
                           "xss" if "script" in pattern.lower() else
                           "traversal" if ".." in pattern else "command",
                    "severity": "high"
                })
        
        return found_patterns


class MockSecurityEventGenerator:
    """Generates mock security events for testing."""
    
    def __init__(self):
        self.event_templates = {
            "sql_injection": {
                "path": "/api/users",
                "query_params": {"id": "1' OR '1'='1"},
                "user_agent": "sqlmap/1.4.7",
                "method": "GET",
                "threat_level": "high"
            },
            "xss_attack": {
                "path": "/search",
                "query_params": {"q": "<script>alert('xss')</script>"},
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "method": "GET",
                "threat_level": "medium"
            },
            "path_traversal": {
                "path": "/files",
                "query_params": {"file": "../../../etc/passwd"},
                "user_agent": "curl/7.68.0",
                "method": "GET",
                "threat_level": "high"
            },
            "brute_force": {
                "path": "/login",
                "json_payload": {"username": "admin", "password": "password123"},
                "user_agent": "Python-requests/2.25.1",
                "method": "POST",
                "threat_level": "medium",
                "rate": "high"  # Generate multiple requests
            },
            "normal_request": {
                "path": "/api/products",
                "query_params": {"category": "electronics", "limit": "10"},
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "method": "GET",
                "threat_level": "low"
            }
        }
    
    def generate_request(self, event_type: str = "normal_request", 
                        client_ip: str = "192.168.1.1") -> Dict[str, Any]:
        """Generate mock security event request."""
        if event_type not in self.event_templates:
            event_type = "normal_request"
        
        template = self.event_templates[event_type].copy()
        
        return {
            "method": template.get("method", "GET"),
            "path": template.get("path", "/"),
            "query_params": template.get("query_params", {}),
            "headers": {
                "user-agent": template.get("user_agent", "test-client/1.0"),
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "accept-language": "en-US,en;q=0.5",
                "host": "testserver"
            },
            "client_ip": client_ip,
            "json_payload": template.get("json_payload"),
            "threat_level": template.get("threat_level", "low"),
            "timestamp": time.time()
        }
    
    def generate_attack_sequence(self, attack_type: str, count: int = 10,
                               client_ip: str = "192.168.1.100") -> List[Dict[str, Any]]:
        """Generate sequence of attack requests."""
        requests = []
        
        for i in range(count):
            request = self.generate_request(attack_type, client_ip)
            
            # Add variations for sequence
            if attack_type == "brute_force":
                request["json_payload"]["password"] = f"password{i}"
                request["headers"]["x-forwarded-for"] = client_ip
            
            elif attack_type == "sql_injection":
                variations = [
                    "1' OR '1'='1",
                    "1; DROP TABLE users--",
                    "1' UNION SELECT * FROM passwords--",
                    f"1' OR 1={i+1}--"
                ]
                request["query_params"]["id"] = variations[i % len(variations)]
            
            requests.append(request)
        
        return requests
    
    def generate_normal_traffic(self, count: int = 50, 
                              base_ip: str = "192.168.1.") -> List[Dict[str, Any]]:
        """Generate normal traffic pattern."""
        requests = []
        
        paths = ["/", "/api/products", "/api/users", "/search", "/about", "/contact"]
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        
        for i in range(count):
            client_ip = f"{base_ip}{random.randint(1, 254)}"
            
            request = {
                "method": random.choice(["GET", "POST"]),
                "path": random.choice(paths),
                "query_params": {"page": str(random.randint(1, 10))},
                "headers": {
                    "user-agent": random.choice(user_agents),
                    "accept": "text/html,application/xhtml+xml",
                    "host": "testserver"
                },
                "client_ip": client_ip,
                "threat_level": "low",
                "timestamp": time.time() + i * random.uniform(0.1, 2.0)
            }
            
            requests.append(request)
        
        return requests


class MockMLSecurityTestEnvironment:
    """Complete test environment for ML security testing."""
    
    def __init__(self):
        self.threat_api = MockThreatIntelligenceAPI()
        self.event_generator = MockSecurityEventGenerator()
        self.request_history: List[Dict[str, Any]] = []
        
        # Performance tracking
        self.processing_times: List[float] = []
        self.accuracy_scores: List[float] = []
        
    def simulate_real_time_attack(self, attack_type: str, duration_seconds: int = 60,
                                 requests_per_second: int = 5) -> List[Dict[str, Any]]:
        """Simulate real-time attack scenario."""
        attack_requests = []
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            # Generate burst of attack requests
            burst_size = random.randint(1, requests_per_second * 2)
            
            for _ in range(burst_size):
                request = self.event_generator.generate_request(
                    attack_type, 
                    client_ip=f"203.0.113.{random.randint(1, 50)}"
                )
                request["timestamp"] = time.time()
                attack_requests.append(request)
                
                # Small delay between requests in burst
                time.sleep(random.uniform(0.01, 0.1))
            
            # Longer delay between bursts
            time.sleep(random.uniform(0.2, 1.0))
        
        return attack_requests
    
    def create_mixed_traffic_scenario(self, total_requests: int = 1000,
                                    attack_ratio: float = 0.1) -> List[Dict[str, Any]]:
        """Create realistic mixed traffic scenario."""
        attack_count = int(total_requests * attack_ratio)
        normal_count = total_requests - attack_count
        
        # Generate normal traffic
        normal_requests = self.event_generator.generate_normal_traffic(normal_count)
        
        # Generate attack traffic
        attack_types = ["sql_injection", "xss_attack", "path_traversal", "brute_force"]
        attack_requests = []
        
        for _ in range(attack_count):
            attack_type = random.choice(attack_types)
            attack_request = self.event_generator.generate_request(
                attack_type,
                client_ip=f"203.0.113.{random.randint(100, 200)}"
            )
            attack_requests.append(attack_request)
        
        # Mix and sort by timestamp
        all_requests = normal_requests + attack_requests
        all_requests.sort(key=lambda x: x["timestamp"])
        
        return all_requests
    
    def measure_performance(self, ml_shield, test_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Measure ML shield performance."""
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        processing_times = []
        
        for request_data in test_requests:
            # Create mock request
            mock_request = self.create_mock_request(request_data)
            
            # Measure processing time
            start_time = time.perf_counter()
            
            # This would be the actual ML analysis
            # For testing, we simulate the analysis
            is_threat_actual = request_data["threat_level"] in ["medium", "high", "critical"]
            
            processing_time = (time.perf_counter() - start_time) * 1000
            processing_times.append(processing_time)
            
            # Simulate ML shield decision (mock)
            threat_detected = self.simulate_threat_detection(request_data)
            
            # Calculate metrics
            if is_threat_actual and threat_detected:
                true_positives += 1
            elif not is_threat_actual and threat_detected:
                false_positives += 1
            elif not is_threat_actual and not threat_detected:
                true_negatives += 1
            else:  # is_threat_actual and not threat_detected
                false_negatives += 1
        
        # Calculate performance metrics
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (true_positives + true_negatives) / len(test_requests)
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "avg_processing_time": sum(processing_times) / len(processing_times),
            "max_processing_time": max(processing_times),
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives,
            "total_requests": len(test_requests)
        }
    
    def create_mock_request(self, request_data: Dict[str, Any]) -> Mock:
        """Create mock FastAPI Request object."""
        mock_request = Mock(spec=Request)
        
        # Set up request attributes
        mock_request.method = request_data.get("method", "GET")
        mock_request.url.path = request_data.get("path", "/")
        mock_request.query_params = request_data.get("query_params", {})
        mock_request.headers = request_data.get("headers", {})
        
        # Mock client
        mock_request.client = Mock()
        mock_request.client.host = request_data.get("client_ip", "127.0.0.1")
        
        # Mock cookies
        mock_request.cookies = request_data.get("cookies", {})
        
        # Mock URL string representation
        query_string = urlencode(request_data.get("query_params", {}))
        full_url = request_data.get("path", "/")
        if query_string:
            full_url += "?" + query_string
        mock_request.url.__str__ = lambda: full_url
        
        # Mock body for POST requests
        if request_data.get("json_payload"):
            mock_request._body = json.dumps(request_data["json_payload"]).encode()
        else:
            mock_request._body = b""
        
        return mock_request
    
    def simulate_threat_detection(self, request_data: Dict[str, Any]) -> bool:
        """Simulate threat detection logic for testing."""
        # Simple heuristic for testing
        threat_indicators = 0
        
        # Check for SQL injection patterns
        query_params = request_data.get("query_params", {})
        for value in query_params.values():
            if any(pattern in str(value).lower() for pattern in ["or '1'='1", "union select", "drop table"]):
                threat_indicators += 2
        
        # Check for XSS patterns
        for value in query_params.values():
            if any(pattern in str(value).lower() for pattern in ["<script", "javascript:", "alert("]):
                threat_indicators += 2
        
        # Check for suspicious user agents
        user_agent = request_data.get("headers", {}).get("user-agent", "").lower()
        if any(tool in user_agent for tool in ["sqlmap", "nikto", "curl"]):
            threat_indicators += 1
        
        # Check client IP reputation
        client_ip = request_data.get("client_ip", "")
        if client_ip in ["192.168.1.100", "203.0.113.195"]:  # Known bad IPs
            threat_indicators += 1
        
        # Determine threat based on indicators
        return threat_indicators >= 2
    
    def generate_performance_report(self, results: Dict[str, Any]) -> str:
        """Generate performance report."""
        report = f"""
ML Security Shield Performance Report
=====================================

Accuracy Metrics:
- Overall Accuracy: {results['accuracy']:.3f}
- Precision: {results['precision']:.3f}
- Recall: {results['recall']:.3f}
- F1 Score: {results['f1_score']:.3f}

Performance Metrics:
- Average Processing Time: {results['avg_processing_time']:.2f} ms
- Maximum Processing Time: {results['max_processing_time']:.2f} ms

Detection Results:
- True Positives: {results['true_positives']}
- False Positives: {results['false_positives']}
- True Negatives: {results['true_negatives']}
- False Negatives: {results['false_negatives']}
- Total Requests: {results['total_requests']}

False Positive Rate: {results['false_positives'] / (results['false_positives'] + results['true_negatives']) * 100:.1f}%
False Negative Rate: {results['false_negatives'] / (results['false_negatives'] + results['true_positives']) * 100:.1f}%
        """
        return report.strip()


# Helper functions for creating test data

def create_test_request_features(**kwargs) -> RequestFeatures:
    """Create RequestFeatures for testing."""
    from fastapi_shield.ml_security import RequestFeatures
    
    defaults = {
        "method": "GET",
        "path": "/api/test",
        "path_length": 9,
        "query_param_count": 0,
        "header_count": 5,
        "user_agent_length": 50,
        "content_length": 0,
        "client_ip": "192.168.1.1",
        "is_private_ip": True,
        "hour_of_day": 12,
        "day_of_week": 2,
        "is_weekend": False,
        "has_json_payload": False,
        "has_form_payload": False,
        "payload_entropy": 0.0,
        "suspicious_patterns": 0,
        "request_rate": 5.0,
        "session_duration": 300.0,
        "unique_endpoints_accessed": 3,
        "error_rate": 0.0,
        "has_potential_injection": False,
        "has_suspicious_headers": False,
        "has_unusual_encoding": False,
        "avg_request_size": 1024.0,
        "request_frequency_variance": 2.5,
        "endpoint_diversity": 0.6
    }
    
    defaults.update(kwargs)
    return RequestFeatures(**defaults)


def create_malicious_request_features(**kwargs) -> RequestFeatures:
    """Create malicious RequestFeatures for testing."""
    malicious_defaults = {
        "suspicious_patterns": 2,
        "has_potential_injection": True,
        "payload_entropy": 7.5,
        "request_rate": 120.0,
        "has_unusual_encoding": True,
        "user_agent_length": 20  # Suspicious short user agent
    }
    
    malicious_defaults.update(kwargs)
    return create_test_request_features(**malicious_defaults)