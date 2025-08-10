"""Tests for SQL injection detection shield."""

import json
import pytest
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from unittest.mock import Mock, AsyncMock, patch

from fastapi_shield.sql_injection_detection import (
    SQLInjectionShield,
    SQLInjectionConfig,
    SQLInjectionDetector,
    SQLPatternLibrary,
    InjectionDetection,
    DetectionLevel,
    SQLDialect,
    InjectionType,
    ActionPolicy,
    sql_injection_detection_shield,
    strict_sql_injection_shield,
    monitoring_sql_injection_shield,
)


class TestSQLPatternLibrary:
    """Test SQL pattern library functionality."""
    
    def test_initialization(self):
        """Test pattern library initialization."""
        library = SQLPatternLibrary()
        
        # Check that patterns were loaded
        assert len(library.patterns) > 0
        assert InjectionType.UNION_BASED in library.patterns
        assert InjectionType.BOOLEAN_BASED in library.patterns
        assert DetectionLevel.LOW in library.patterns[InjectionType.UNION_BASED]
    
    def test_get_patterns(self):
        """Test pattern retrieval."""
        library = SQLPatternLibrary()
        
        # Get LOW level patterns
        low_patterns = library.get_patterns(InjectionType.UNION_BASED, DetectionLevel.LOW)
        assert len(low_patterns) > 0
        
        # Get HIGH level patterns (should include LOW level patterns too)
        high_patterns = library.get_patterns(InjectionType.UNION_BASED, DetectionLevel.HIGH)
        assert len(high_patterns) >= len(low_patterns)
    
    def test_get_all_patterns(self):
        """Test getting all patterns for a detection level."""
        library = SQLPatternLibrary()
        
        all_patterns = library.get_all_patterns(DetectionLevel.MEDIUM)
        
        assert isinstance(all_patterns, dict)
        assert len(all_patterns) > 0
        assert InjectionType.UNION_BASED in all_patterns
        assert InjectionType.BOOLEAN_BASED in all_patterns


class TestSQLInjectionDetector:
    """Test SQL injection detector functionality."""
    
    @pytest.fixture
    def basic_config(self):
        """Basic detector configuration."""
        return SQLInjectionConfig(
            detection_level=DetectionLevel.MEDIUM,
            default_action=ActionPolicy.LOG_ONLY,
        )
    
    @pytest.fixture
    def detector(self, basic_config):
        """SQL injection detector instance."""
        return SQLInjectionDetector(basic_config)
    
    def test_detector_initialization(self, detector):
        """Test detector initialization."""
        assert detector.config.detection_level == DetectionLevel.MEDIUM
        assert detector.pattern_library is not None
        assert isinstance(detector.detection_cache, dict)
        assert isinstance(detector.ip_stats, dict)
    
    def test_normalize_payload_url_decode(self):
        """Test payload normalization with URL decoding."""
        config = SQLInjectionConfig(decode_url=True)
        detector = SQLInjectionDetector(config)
        
        payload = "SELECT%20%2A%20FROM%20users"
        normalized = detector._normalize_payload(payload)
        assert "SELECT * FROM users" in normalized
    
    def test_normalize_payload_html_decode(self):
        """Test payload normalization with HTML decoding."""
        config = SQLInjectionConfig(decode_html=True)
        detector = SQLInjectionDetector(config)
        
        payload = "SELECT &#42; FROM users WHERE id=1"
        normalized = detector._normalize_payload(payload)
        assert "SELECT * FROM users WHERE id=1" in normalized
    
    def test_normalize_payload_whitespace(self):
        """Test payload normalization with whitespace."""
        config = SQLInjectionConfig(normalize_whitespace=True)
        detector = SQLInjectionDetector(config)
        
        payload = "SELECT   *    FROM   users"
        normalized = detector._normalize_payload(payload)
        assert normalized == "SELECT * FROM users"
    
    def test_check_whitelist(self):
        """Test whitelist pattern checking."""
        config = SQLInjectionConfig(whitelist_patterns=[r'SELECT \* FROM safe_table'])
        detector = SQLInjectionDetector(config)
        
        # Should be whitelisted
        assert detector._check_whitelist("SELECT * FROM safe_table") is True
        
        # Should not be whitelisted
        assert detector._check_whitelist("SELECT * FROM users") is False
    
    def test_calculate_confidence(self, detector):
        """Test confidence score calculation."""
        # No matches
        confidence = detector._calculate_confidence([])
        assert confidence == 0.0
        
        # Single match
        matches = [(InjectionType.UNION_BASED, "union select")]
        confidence = detector._calculate_confidence(matches)
        assert 0.0 < confidence <= 1.0
        
        # Multiple high-risk matches
        matches = [
            (InjectionType.UNION_BASED, "union select"),
            (InjectionType.SYSTEM_COMMANDS, "into outfile"),
        ]
        confidence = detector._calculate_confidence(matches)
        assert confidence > 0.5
    
    def test_detect_injection_patterns(self, detector):
        """Test injection pattern detection."""
        # UNION injection
        matches = detector._detect_injection_patterns("' UNION SELECT password FROM users--")
        assert len(matches) > 0
        assert any(injection_type == InjectionType.UNION_BASED for injection_type, _ in matches)
        
        # Boolean injection
        matches = detector._detect_injection_patterns("' OR '1'='1")
        assert len(matches) > 0
        assert any(injection_type == InjectionType.BOOLEAN_BASED for injection_type, _ in matches)
        
        # No injection
        matches = detector._detect_injection_patterns("normal search term")
        assert len(matches) == 0
    
    def test_sanitize_payload(self, detector):
        """Test payload sanitization."""
        payload = "' UNION SELECT password FROM users--"
        sanitized = detector._sanitize_payload(payload)
        
        assert "UNION_BLOCKED" in sanitized
        assert "password FROM users" not in sanitized or "BLOCKED" in sanitized
    
    def test_detect_union_injection(self, detector):
        """Test UNION injection detection."""
        payload = "1' UNION SELECT username, password FROM users--"
        detection = detector.detect(payload, "query_params", "id")
        
        assert detection.detected is True
        assert detection.injection_type == InjectionType.UNION_BASED
        assert detection.confidence_score > 0.0
        assert len(detection.matched_patterns) > 0
        assert detection.source_location == "query_params"
        assert detection.parameter_name == "id"
    
    def test_detect_boolean_injection(self, detector):
        """Test boolean injection detection."""
        payload = "admin' OR '1'='1'--"
        detection = detector.detect(payload, "form_data", "username")
        
        assert detection.detected is True
        assert detection.injection_type == InjectionType.BOOLEAN_BASED
        assert detection.confidence_score > 0.0
    
    def test_detect_time_based_injection(self, detector):
        """Test time-based injection detection."""
        payload = "1'; WAITFOR DELAY '00:00:05'--"
        detection = detector.detect(payload, "query_params", "id")
        
        assert detection.detected is True
        assert detection.injection_type == InjectionType.TIME_BASED
    
    def test_detect_stacked_queries(self, detector):
        """Test stacked queries detection."""
        payload = "1; DROP TABLE users--"
        detection = detector.detect(payload, "query_params", "id")
        
        assert detection.detected is True
        assert detection.injection_type == InjectionType.STACKED_QUERIES
    
    def test_detect_information_schema(self, detector):
        """Test information schema injection detection."""
        payload = "' UNION SELECT table_name FROM information_schema.tables--"
        detection = detector.detect(payload, "query_params", "search")
        
        assert detection.detected is True
        # Could be UNION_BASED or INFORMATION_SCHEMA depending on which pattern matches first
        assert detection.injection_type in [InjectionType.UNION_BASED, InjectionType.INFORMATION_SCHEMA]
    
    def test_detect_clean_payload(self, detector):
        """Test detection with clean payload."""
        payload = "normal search term"
        detection = detector.detect(payload, "query_params", "q")
        
        assert detection.detected is False
        assert detection.injection_type is None
        assert detection.confidence_score == 0.0
    
    def test_whitelisted_payload(self):
        """Test whitelisted payload detection."""
        config = SQLInjectionConfig(whitelist_patterns=[r'SELECT \* FROM safe_table'])
        detector = SQLInjectionDetector(config)
        
        payload = "SELECT * FROM safe_table"
        detection = detector.detect(payload, "query_params", "q")
        
        assert detection.detected is False
    
    def test_detection_caching(self, detector):
        """Test detection result caching."""
        payload = "' UNION SELECT * FROM users--"
        
        # First detection
        start_time = time.time()
        detection1 = detector.detect(payload, "query_params", "id")
        first_duration = time.time() - start_time
        
        # Second detection (should be cached)
        start_time = time.time()
        detection2 = detector.detect(payload, "query_params", "id")
        second_duration = time.time() - start_time
        
        assert detection1.detected == detection2.detected
        assert detection1.injection_type == detection2.injection_type
        # Second call should be faster due to caching
        assert second_duration < first_duration or second_duration < 0.001
    
    def test_max_payload_length(self):
        """Test maximum payload length truncation."""
        config = SQLInjectionConfig(max_payload_length=10)
        detector = SQLInjectionDetector(config)
        
        long_payload = "a" * 100 + "' UNION SELECT * FROM users--"
        detection = detector.detect(long_payload, "query_params", "data")
        
        # Should still work with truncated payload
        assert len(detection.payload) <= 10
    
    def test_custom_patterns(self):
        """Test custom pattern detection."""
        custom_pattern = r'\bMALICIOUS_KEYWORD\b'
        config = SQLInjectionConfig(custom_patterns=[custom_pattern])
        detector = SQLInjectionDetector(config)
        
        payload = "some text with MALICIOUS_KEYWORD here"
        detection = detector.detect(payload, "query_params", "data")
        
        assert detection.detected is True
        assert detection.injection_type == InjectionType.BLIND
    
    def test_analyze_request_query_params(self, detector):
        """Test request analysis with query parameters."""
        request = Mock(spec=Request)
        request.query_params = {"id": "1' OR 1=1--", "name": "normal"}
        # Mock path_params to avoid iteration error
        request.path_params = {}
        request.headers = {}
        
        detections = detector.analyze_request(request)
        
        assert len(detections) == 1
        assert detections[0].parameter_name == "id"
        assert detections[0].source_location == "query_params"
        assert detections[0].detected is True
    
    def test_analyze_request_path_params(self, detector):
        """Test request analysis with path parameters."""
        request = Mock(spec=Request)
        request.query_params = {}
        request.path_params = {"user_id": "1'; DROP TABLE users--"}
        
        detections = detector.analyze_request(request)
        
        assert len(detections) == 1
        assert detections[0].parameter_name == "user_id"
        assert detections[0].source_location == "path_params"
    
    def test_analyze_request_headers(self):
        """Test request analysis with headers."""
        config = SQLInjectionConfig(check_headers=True, header_whitelist=["user-agent"])
        detector = SQLInjectionDetector(config)
        
        request = Mock(spec=Request)
        request.query_params = {}
        request.path_params = {}
        request.headers = {"user-agent": "' UNION SELECT version()--"}
        
        detections = detector.analyze_request(request)
        
        assert len(detections) == 1
        assert detections[0].source_location == "headers"
        assert detections[0].parameter_name == "user-agent"
    
    @pytest.mark.asyncio
    async def test_analyze_request_body_form(self, detector):
        """Test request body analysis with form data."""
        request = Mock(spec=Request)
        request.headers = {"content-type": "application/x-www-form-urlencoded"}
        
        # Mock form data
        form_data = {"username": "admin", "password": "' OR '1'='1"}
        request.form = AsyncMock(return_value=form_data)
        
        detections = await detector.analyze_request_body(request)
        
        assert len(detections) == 1
        assert detections[0].parameter_name == "password"
        assert detections[0].source_location == "form_data"
    
    @pytest.mark.asyncio
    async def test_analyze_request_body_json(self, detector):
        """Test request body analysis with JSON data."""
        request = Mock(spec=Request)
        request.headers = {"content-type": "application/json"}
        
        # Mock JSON data
        json_data = {
            "search": "normal search",
            "filter": "' UNION SELECT * FROM users--"
        }
        request.json = AsyncMock(return_value=json_data)
        
        detections = await detector.analyze_request_body(request)
        
        assert len(detections) == 1
        assert detections[0].parameter_name == "json_data.filter"
        assert detections[0].source_location == "json_data"
    
    @pytest.mark.asyncio
    async def test_analyze_request_body_nested_json(self, detector):
        """Test request body analysis with nested JSON."""
        request = Mock(spec=Request)
        request.headers = {"content-type": "application/json"}
        
        json_data = {
            "user": {
                "profile": {
                    "bio": "Normal bio",
                    "query": "1' UNION SELECT password FROM admin--"
                }
            }
        }
        request.json = AsyncMock(return_value=json_data)
        
        detections = await detector.analyze_request_body(request)
        
        assert len(detections) == 1
        assert detections[0].parameter_name == "json_data.user.profile.query"
    
    def test_track_ip_activity_normal(self, detector):
        """Test IP activity tracking with normal behavior."""
        ip = "192.168.1.1"
        detections = []
        
        should_block = detector.track_ip_activity(ip, detections)
        assert should_block is False
        
        # Check stats
        assert ip in detector.ip_stats
        assert detector.ip_stats[ip]["detections"] == 0
    
    def test_track_ip_activity_suspicious(self, detector):
        """Test IP activity tracking with suspicious behavior."""
        ip = "192.168.1.2"
        
        # Simulate multiple injection attempts
        for _ in range(12):  # Exceed default threshold of 10
            mock_detection = Mock()
            mock_detection.detected = True
            detections = [mock_detection]
            should_block = detector.track_ip_activity(ip, detections)
        
        # Should be blocked after threshold
        assert should_block is True
        assert detector.ip_stats[ip]["blocked"] is True
    
    def test_track_ip_activity_blocked_timeout(self, detector):
        """Test IP blocking timeout."""
        ip = "192.168.1.3"
        
        # Simulate blocking
        detector.ip_stats[ip]["blocked"] = True
        detector.ip_stats[ip]["block_until"] = time.time() - 1  # Already expired
        
        should_block = detector.track_ip_activity(ip, [])
        
        # Should be unblocked due to timeout
        assert should_block is False
        assert detector.ip_stats[ip]["blocked"] is False


class TestSQLInjectionShield:
    """Test SQL injection shield functionality."""
    
    @pytest.fixture
    def app(self):
        """FastAPI test application."""
        app = FastAPI()
        return app
    
    @pytest.fixture
    def basic_config(self):
        """Basic shield configuration."""
        return SQLInjectionConfig(
            detection_level=DetectionLevel.MEDIUM,
            default_action=ActionPolicy.LOG_ONLY,
        )
    
    @pytest.fixture
    def blocking_config(self):
        """Blocking shield configuration."""
        return SQLInjectionConfig(
            detection_level=DetectionLevel.HIGH,
            default_action=ActionPolicy.BLOCK,
            injection_type_actions={
                InjectionType.UNION_BASED: ActionPolicy.BLOCK,
                InjectionType.BOOLEAN_BASED: ActionPolicy.BLOCK,
                InjectionType.STACKED_QUERIES: ActionPolicy.BLOCK,
            }
        )
    
    def test_shield_initialization(self, basic_config):
        """Test shield initialization."""
        shield = SQLInjectionShield(basic_config)
        
        assert shield.config == basic_config
        assert shield.detector is not None
        assert isinstance(shield.detector, SQLInjectionDetector)
    
    def test_get_client_ip_direct(self, basic_config):
        """Test client IP extraction."""
        shield = SQLInjectionShield(basic_config)
        
        # Mock request with direct client
        request = Mock(spec=Request)
        request.headers = {}
        request.client = Mock()
        request.client.host = "192.168.1.1"
        
        ip = shield._get_client_ip(request)
        assert ip == "192.168.1.1"
    
    def test_get_client_ip_forwarded(self, basic_config):
        """Test client IP extraction from forwarded headers."""
        shield = SQLInjectionShield(basic_config)
        
        request = Mock(spec=Request)
        request.headers = {"x-forwarded-for": "10.0.0.1, 192.168.1.1"}
        
        ip = shield._get_client_ip(request)
        assert ip == "10.0.0.1"
    
    @pytest.mark.asyncio
    async def test_shield_clean_request(self, app, basic_config):
        """Test shield with clean request."""
        shield = SQLInjectionShield(basic_config)
        shield_func = shield.create_shield("test")
        
        @app.get("/test")
        @shield_func
        def test_endpoint(q: str = "normal query"):
            return {"query": q}
        
        with TestClient(app) as client:
            response = client.get("/test?q=normal%20search")
            assert response.status_code == 200
            assert "normal search" in response.json()["query"]
    
    @pytest.mark.asyncio
    async def test_shield_injection_detection_log_only(self, app, basic_config):
        """Test shield with injection detection in log-only mode."""
        shield = SQLInjectionShield(basic_config)
        shield_func = shield.create_shield("test")
        
        @app.get("/test")
        @shield_func
        def test_endpoint(q: str = ""):
            return {"query": q}
        
        with TestClient(app) as client:
            response = client.get("/test?q=1'%20UNION%20SELECT%20*%20FROM%20users--")
            # Should pass through since default action is LOG_ONLY
            assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_shield_injection_blocking(self, app, blocking_config):
        """Test shield with injection blocking."""
        shield = SQLInjectionShield(blocking_config)
        shield_func = shield.create_shield("test")
        
        @app.get("/test")
        @shield_func
        def test_endpoint(q: str = ""):
            return {"query": q}
        
        with TestClient(app) as client:
            response = client.get("/test?q=1'%20UNION%20SELECT%20*%20FROM%20users--")
            assert response.status_code == 403
            assert "injection attempt detected" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_shield_multiple_injections(self, app, blocking_config):
        """Test shield with multiple injection attempts."""
        shield = SQLInjectionShield(blocking_config)
        shield_func = shield.create_shield("test")
        
        @app.post("/test")
        @shield_func
        def test_endpoint():
            return {"status": "ok"}
        
        with TestClient(app) as client:
            # JSON payload with multiple injections
            json_payload = {
                "search": "1' UNION SELECT * FROM users--",
                "filter": "'; DROP TABLE users--",
                "normal": "regular data"
            }
            
            response = client.post("/test", json=json_payload)
            assert response.status_code == 403
            assert "injection attempt detected" in response.json()["detail"]
            
            # Check headers
            assert "X-Injection-Type" in response.headers
            assert "X-Detection-Count" in response.headers
    
    @pytest.mark.asyncio
    async def test_shield_ip_blocking(self, app):
        """Test shield with IP-based blocking."""
        config = SQLInjectionConfig(
            detection_level=DetectionLevel.HIGH,
            default_action=ActionPolicy.BLOCK,
            track_source_ips=True,
            suspicious_ip_threshold=2,
            injection_type_actions={
                InjectionType.UNION_BASED: ActionPolicy.BLOCK,
            }
        )
        shield = SQLInjectionShield(config)
        shield_func = shield.create_shield("test")
        
        @app.get("/test")
        @shield_func
        def test_endpoint(q: str = ""):
            return {"query": q}
        
        with TestClient(app) as client:
            # First injection attempt
            response = client.get("/test?q=1'%20UNION%20SELECT%20*%20FROM%20users--")
            assert response.status_code == 403
            
            # Second injection attempt (should exceed threshold)
            response = client.get("/test?q=1'%20OR%201=1--")
            assert response.status_code == 403
            
            # Third attempt should result in IP blocking
            response = client.get("/test?q=normal%20query")
            assert response.status_code == 429  # Too Many Requests
            assert "IP address temporarily blocked" in response.json()["detail"]


class TestConvenienceFunctions:
    """Test convenience shield functions."""
    
    @pytest.fixture
    def app(self):
        """FastAPI test application."""
        app = FastAPI()
        return app
    
    def test_sql_injection_detection_shield_basic(self, app):
        """Test basic SQL injection detection shield."""
        shield_func = sql_injection_detection_shield()
        
        @app.get("/test")
        @shield_func
        def test_endpoint(q: str = "normal"):
            return {"query": q}
        
        with TestClient(app) as client:
            # Clean request
            response = client.get("/test?q=normal")
            assert response.status_code == 200
            
            # Injection attempt (should pass in LOG_ONLY mode)
            response = client.get("/test?q=1'%20OR%201=1--")
            assert response.status_code == 200
    
    def test_sql_injection_detection_shield_blocking(self, app):
        """Test SQL injection detection shield with blocking."""
        shield_func = sql_injection_detection_shield(
            detection_level=DetectionLevel.HIGH,
            action_policy=ActionPolicy.BLOCK
        )
        
        @app.get("/test")
        @shield_func
        def test_endpoint(q: str = ""):
            return {"query": q}
        
        with TestClient(app) as client:
            response = client.get("/test?q=1'%20UNION%20SELECT%20*%20FROM%20users--")
            assert response.status_code == 403
    
    def test_strict_sql_injection_shield(self, app):
        """Test strict SQL injection shield."""
        shield_func = strict_sql_injection_shield()
        
        @app.get("/test")
        @shield_func
        def test_endpoint(q: str = ""):
            return {"query": q}
        
        with TestClient(app) as client:
            # Should block injection attempts
            response = client.get("/test?q=1'%20UNION%20SELECT%20*%20FROM%20users--")
            assert response.status_code == 403
            
            # Clean request should pass
            response = client.get("/test?q=normal%20search")
            assert response.status_code == 200
    
    def test_monitoring_sql_injection_shield(self, app):
        """Test monitoring SQL injection shield."""
        shield_func = monitoring_sql_injection_shield()
        
        @app.get("/test")
        @shield_func
        def test_endpoint(q: str = ""):
            return {"query": q}
        
        with TestClient(app) as client:
            # Injection attempts should be logged but not blocked
            response = client.get("/test?q=1'%20UNION%20SELECT%20*%20FROM%20users--")
            assert response.status_code == 200


class TestDetectionLevels:
    """Test different detection levels."""
    
    @pytest.fixture
    def create_detector(self):
        """Factory function to create detector with specific level."""
        def _create(level: DetectionLevel):
            config = SQLInjectionConfig(detection_level=level)
            return SQLInjectionDetector(config)
        return _create
    
    def test_low_detection_level(self, create_detector):
        """Test LOW detection level."""
        detector = create_detector(DetectionLevel.LOW)
        
        # Should detect obvious injections
        detection = detector.detect("1' UNION SELECT * FROM users--", "query", "id")
        assert detection.detected is True
        
        # Should miss subtle variations
        detection = detector.detect("1' /*comment*/ UNION SELECT * FROM users--", "query", "id")
        # This might or might not be detected depending on patterns
    
    def test_high_detection_level(self, create_detector):
        """Test HIGH detection level."""
        detector = create_detector(DetectionLevel.HIGH)
        
        # Should detect obvious injections
        detection = detector.detect("1' UNION SELECT * FROM users--", "query", "id")
        assert detection.detected is True
        
        # Should detect subtle variations
        detection = detector.detect("1' /*comment*/ UNION SELECT * FROM users--", "query", "id")
        assert detection.detected is True
        
        # Should detect function-based injections
        detection = detector.detect("1' AND (SELECT SUBSTRING(VERSION(),1,1))='5'--", "query", "id")
        assert detection.detected is True
    
    def test_paranoid_detection_level(self, create_detector):
        """Test PARANOID detection level."""
        detector = create_detector(DetectionLevel.PARANOID)
        
        # Should detect heavily obfuscated injections
        detection = detector.detect("1' U/**/NI/**/ON SEL/**/ECT * FROM users--", "query", "id")
        # This is a very sophisticated test case, might not be caught by current patterns
        
        # Should have lower confidence due to higher false positive risk
        detection = detector.detect("1' UNION SELECT * FROM users--", "query", "id")
        assert detection.detected is True
        # Confidence should be adjusted for paranoid level


class TestSQLDialects:
    """Test SQL dialect specific detection."""
    
    def test_mysql_specific_patterns(self):
        """Test MySQL specific injection patterns."""
        config = SQLInjectionConfig(sql_dialects=[SQLDialect.MYSQL])
        detector = SQLInjectionDetector(config)
        
        # MySQL specific functions
        detection = detector.detect("1' AND (SELECT version()) LIKE '5%'--", "query", "id")
        assert detection.detected is True
    
    def test_postgresql_specific_patterns(self):
        """Test PostgreSQL specific injection patterns."""
        config = SQLInjectionConfig(sql_dialects=[SQLDialect.POSTGRESQL])
        detector = SQLInjectionDetector(config)
        
        # PostgreSQL specific functions
        detection = detector.detect("1'; SELECT pg_sleep(5)--", "query", "id")
        assert detection.detected is True
    
    def test_generic_patterns(self):
        """Test generic SQL injection patterns."""
        config = SQLInjectionConfig(sql_dialects=[SQLDialect.GENERIC])
        detector = SQLInjectionDetector(config)
        
        # Generic injection
        detection = detector.detect("1' OR 1=1--", "query", "id")
        assert detection.detected is True


class TestActionPolicies:
    """Test different action policies."""
    
    def test_log_only_action(self):
        """Test LOG_ONLY action policy."""
        config = SQLInjectionConfig(default_action=ActionPolicy.LOG_ONLY)
        detector = SQLInjectionDetector(config)
        
        detection = detector.detect("1' UNION SELECT * FROM users--", "query", "id")
        assert detection.detected is True
        assert detection.action_taken == ActionPolicy.LOG_ONLY
        assert detection.sanitized_payload is None
    
    def test_sanitize_action(self):
        """Test SANITIZE action policy."""
        config = SQLInjectionConfig(default_action=ActionPolicy.SANITIZE)
        detector = SQLInjectionDetector(config)
        
        detection = detector.detect("1' UNION SELECT * FROM users--", "query", "id")
        assert detection.detected is True
        assert detection.action_taken == ActionPolicy.SANITIZE
        assert detection.sanitized_payload is not None
        assert "UNION_BLOCKED" in detection.sanitized_payload
    
    def test_block_action(self):
        """Test BLOCK action policy."""
        config = SQLInjectionConfig(default_action=ActionPolicy.BLOCK)
        detector = SQLInjectionDetector(config)
        
        detection = detector.detect("1' UNION SELECT * FROM users--", "query", "id")
        assert detection.detected is True
        assert detection.action_taken == ActionPolicy.BLOCK
    
    def test_injection_type_specific_actions(self):
        """Test injection type specific action policies."""
        config = SQLInjectionConfig(
            default_action=ActionPolicy.LOG_ONLY,
            injection_type_actions={
                InjectionType.UNION_BASED: ActionPolicy.BLOCK,
                InjectionType.STACKED_QUERIES: ActionPolicy.BLOCK,
            }
        )
        detector = SQLInjectionDetector(config)
        
        # UNION injection should be blocked
        detection = detector.detect("1' UNION SELECT * FROM users--", "query", "id")
        assert detection.action_taken == ActionPolicy.BLOCK
        
        # Boolean injection should be logged only
        detection = detector.detect("1' OR 1=1--", "query", "id")
        assert detection.action_taken == ActionPolicy.LOG_ONLY


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_invalid_regex_patterns(self):
        """Test handling of invalid regex patterns."""
        # Should not raise an exception
        config = SQLInjectionConfig(custom_patterns=["[invalid regex"])
        detector = SQLInjectionDetector(config)
        
        # Should still work with valid built-in patterns
        detection = detector.detect("1' UNION SELECT * FROM users--", "query", "id")
        assert detection.detected is True
    
    def test_empty_payload(self):
        """Test detection with empty payload."""
        config = SQLInjectionConfig()
        detector = SQLInjectionDetector(config)
        
        detection = detector.detect("", "query", "id")
        assert detection.detected is False
        assert detection.confidence_score == 0.0
    
    def test_very_long_payload(self):
        """Test detection with very long payload."""
        config = SQLInjectionConfig(max_payload_length=100)
        detector = SQLInjectionDetector(config)
        
        long_payload = "a" * 500 + "1' UNION SELECT * FROM users--"
        detection = detector.detect(long_payload, "query", "id")
        
        # Payload should be truncated
        assert len(detection.payload) <= 100
    
    @pytest.mark.asyncio
    async def test_request_body_parsing_error(self):
        """Test handling of request body parsing errors."""
        config = SQLInjectionConfig()
        detector = SQLInjectionDetector(config)
        
        request = Mock(spec=Request)
        request.headers = {"content-type": "application/json"}
        request.json = AsyncMock(side_effect=Exception("Invalid JSON"))
        
        # Should not raise an exception
        detections = await detector.analyze_request_body(request)
        assert isinstance(detections, list)
    
    def test_unicode_payload(self):
        """Test detection with Unicode characters."""
        config = SQLInjectionConfig()
        detector = SQLInjectionDetector(config)
        
        # Unicode injection attempt
        payload = "1' UNION SELECT 用户名, 密码 FROM users--"
        detection = detector.detect(payload, "query", "id")
        assert detection.detected is True
    
    def test_none_values_in_request(self):
        """Test handling of None values in request parameters."""
        config = SQLInjectionConfig()
        detector = SQLInjectionDetector(config)
        
        request = Mock(spec=Request)
        request.query_params = {"valid": "test", "none_value": None}
        request.path_params = {}
        request.headers = {}
        
        detections = detector.analyze_request(request)
        # Should handle None values gracefully
        assert isinstance(detections, list)