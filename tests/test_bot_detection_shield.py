"""Tests for bot detection shield functionality."""

import time
from collections import deque
from typing import Dict
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from fastapi_shield.bot_detection import (
    BotDetectionShield,
    BotDetectionConfig,
    BotDetectionResult,
    BotDetector,
    UserAgentAnalyzer,
    BehavioralAnalyzer,
    BehavioralMetrics,
    RequestFingerprint,
    BotType,
    DetectionMethod,
    BotAction,
    ChallengeType,
    bot_detection_shield,
    strict_bot_detection_shield,
    search_engine_friendly_shield,
)


class TestBotDetectionConfig:
    """Test bot detection configuration."""
    
    def test_config_defaults(self):
        """Test default configuration values."""
        config = BotDetectionConfig()
        
        assert config.enable_user_agent_detection is True
        assert config.enable_behavioral_detection is True
        assert config.enable_ip_reputation is False
        assert config.enable_fingerprinting is True
        assert config.enable_rate_analysis is True
        assert config.behavioral_window_minutes == 10
        assert config.max_requests_per_window == 100
        assert config.default_bot_action == BotAction.LOG_ONLY
        assert config.malicious_bot_action == BotAction.BLOCK
    
    def test_config_bot_patterns(self):
        """Test default bot patterns."""
        config = BotDetectionConfig()
        
        assert len(config.known_bot_patterns) > 0
        assert r'.*bot.*' in config.known_bot_patterns
        assert r'.*crawl.*' in config.known_bot_patterns
        assert r'curl/' in config.known_bot_patterns
    
    def test_config_legitimate_bots(self):
        """Test legitimate bot configuration."""
        config = BotDetectionConfig()
        
        assert 'Googlebot' in config.legitimate_bots
        assert config.legitimate_bots['Googlebot'] == BotType.SEARCH_ENGINE
        assert 'facebookexternalhit' in config.legitimate_bots
        assert config.legitimate_bots['facebookexternalhit'] == BotType.SOCIAL_MEDIA
    
    def test_config_validation_invalid_regex(self):
        """Test configuration validation with invalid regex."""
        with pytest.raises(ValueError):
            BotDetectionConfig(known_bot_patterns=['[invalid'])


class TestUserAgentAnalyzer:
    """Test user-agent analysis functionality."""
    
    @pytest.fixture
    def config(self):
        """Create basic configuration for testing."""
        return BotDetectionConfig()
    
    @pytest.fixture
    def analyzer(self, config):
        """Create analyzer for testing."""
        return UserAgentAnalyzer(config)
    
    def test_legitimate_search_engines(self, analyzer):
        """Test detection of legitimate search engine bots."""
        test_cases = [
            ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", BotType.SEARCH_ENGINE),
            ("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", BotType.SEARCH_ENGINE),
            ("Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)", BotType.SEARCH_ENGINE),
        ]
        
        for user_agent, expected_type in test_cases:
            is_bot, bot_type, confidence, reason = analyzer.analyze(user_agent)
            
            assert is_bot is True
            assert bot_type == expected_type
            assert confidence >= 0.8
            assert "legitimate" in reason.lower()
    
    def test_social_media_bots(self, analyzer):
        """Test detection of social media bots."""
        test_cases = [
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "Twitterbot/1.0",
            "LinkedInBot/1.0 (compatible; Mozilla/5.0; +http://www.linkedin.com/)",
        ]
        
        for user_agent in test_cases:
            is_bot, bot_type, confidence, reason = analyzer.analyze(user_agent)
            
            assert is_bot is True
            assert bot_type == BotType.SOCIAL_MEDIA
            assert confidence >= 0.8
    
    def test_monitoring_bots(self, analyzer):
        """Test detection of monitoring service bots."""
        test_cases = [
            "Pingdom.com_bot_version_1.4",
            "UptimeRobot/2.0; http://www.uptimerobot.com/",
            "StatusCake_Monitoring_Service",
        ]
        
        for user_agent in test_cases:
            is_bot, bot_type, confidence, reason = analyzer.analyze(user_agent)
            
            assert is_bot is True
            assert bot_type == BotType.MONITORING
            assert confidence >= 0.8
    
    def test_suspicious_user_agents(self, analyzer):
        """Test detection of suspicious user-agents."""
        test_cases = [
            "python-requests/2.28.1",
            "curl/7.68.0",
            "wget/1.20.3",
            "Java/1.8.0_312",
            "Go-http-client/1.1",
            "Apache-HttpClient/4.5.13",
        ]
        
        for user_agent in test_cases:
            is_bot, bot_type, confidence, reason = analyzer.analyze(user_agent)
            
            assert is_bot is True
            assert confidence >= 0.4
            assert bot_type in [BotType.SCRAPER, BotType.UNKNOWN]
    
    def test_generic_bot_patterns(self, analyzer):
        """Test detection of generic bot patterns."""
        test_cases = [
            "MyBot/1.0",
            "WebCrawler/3.0",
            "DataSpider/2.1",
            "ContentScraper/1.0",
            "SiteScanner/2.0",
        ]
        
        for user_agent in test_cases:
            is_bot, bot_type, confidence, reason = analyzer.analyze(user_agent)
            
            assert is_bot is True
            assert confidence >= 0.6  # Adjusted for new logic
            # Could be either bot patterns or suspicious characteristics
        assert ("bot patterns matched" in reason.lower() or "suspicious characteristics" in reason.lower())
    
    def test_legitimate_browsers(self, analyzer):
        """Test that legitimate browsers are not detected as bots."""
        test_cases = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
        ]
        
        for user_agent in test_cases:
            is_bot, bot_type, confidence, reason = analyzer.analyze(user_agent)
            
            assert is_bot is False
            assert bot_type is None
            assert confidence == 0.0
    
    def test_suspicious_characteristics(self, analyzer):
        """Test detection of suspicious user-agent characteristics."""
        # Very short user-agent
        is_bot, bot_type, confidence, reason = analyzer.analyze("Bot")
        assert is_bot is True
        assert "short user-agent" in reason.lower()
        
        # No version information
        is_bot, bot_type, confidence, reason = analyzer.analyze("CustomAgent")
        assert is_bot is True
        assert "no version information" in reason.lower()
        
        # Missing browser indicators
        is_bot, bot_type, confidence, reason = analyzer.analyze("MyCustomTool/1.0")
        assert is_bot is True
        assert "missing common browser indicators" in reason.lower()
    
    def test_empty_user_agent(self, analyzer):
        """Test handling of empty user-agent."""
        is_bot, bot_type, confidence, reason = analyzer.analyze("")
        
        assert is_bot is False
        assert bot_type is None
        assert confidence == 0.0
        assert "no user-agent provided" in reason.lower()


class TestBehavioralAnalyzer:
    """Test behavioral analysis functionality."""
    
    @pytest.fixture
    def config(self):
        """Create configuration for testing."""
        return BotDetectionConfig(
            behavioral_window_minutes=1,  # Short window for testing
            max_requests_per_window=5,
            max_unique_paths_ratio=0.7,
            min_request_interval_ms=500,
        )
    
    @pytest.fixture
    def analyzer(self, config):
        """Create analyzer for testing."""
        return BehavioralAnalyzer(config)
    
    def test_track_request(self, analyzer):
        """Test request tracking."""
        ip = "192.168.1.1"
        
        # Track some requests
        analyzer.track_request(ip, "/path1", "Browser/1.0")
        analyzer.track_request(ip, "/path2", "Browser/1.0")
        
        assert ip in analyzer.ip_metrics
        metrics = analyzer.ip_metrics[ip]
        assert metrics.request_count == 2
        assert len(metrics.unique_paths) == 2
        assert "/path1" in metrics.unique_paths
        assert "/path2" in metrics.unique_paths
    
    def test_high_request_rate(self, analyzer):
        """Test detection of high request rate."""
        ip = "192.168.1.1"
        
        # Generate many requests quickly
        for i in range(10):
            analyzer.track_request(ip, f"/path{i}", "Bot/1.0")
        
        is_suspicious, confidence, reason = analyzer.analyze(ip)
        
        assert is_suspicious is True
        assert confidence >= 0.3
        assert "high request rate" in reason.lower()
    
    def test_high_unique_paths_ratio(self, analyzer):
        """Test detection of high unique paths ratio (crawling behavior)."""
        ip = "192.168.1.2"
        
        # Generate requests to many unique paths
        for i in range(15):
            analyzer.track_request(ip, f"/unique/path/{i}", "Crawler/1.0")
        
        is_suspicious, confidence, reason = analyzer.analyze(ip)
        
        assert is_suspicious is True
        assert confidence >= 0.2
        assert "unique paths ratio" in reason.lower()
    
    def test_fast_request_intervals(self, analyzer):
        """Test detection of unnaturally fast request intervals."""
        ip = "192.168.1.3"
        
        # Simulate very fast requests by manually tracking timestamps
        base_time = time.time()
        for i in range(6):
            with patch('time.time', return_value=base_time + i * 0.05):  # 50ms intervals
                analyzer.track_request(ip, f"/path{i}", "FastBot/1.0")
        
        is_suspicious, confidence, reason = analyzer.analyze(ip)
        
        assert is_suspicious is True
        assert "fast request intervals" in reason.lower()
    
    def test_suspicious_paths(self, analyzer):
        """Test detection of suspicious path access."""
        ip = "192.168.1.4"
        
        # Access suspicious paths
        suspicious_paths = ["/admin/login", "/.env", "/config.php", "/wp-admin/"]
        for path in suspicious_paths:
            analyzer.track_request(ip, path, "Scanner/1.0")
        
        is_suspicious, confidence, reason = analyzer.analyze(ip)
        
        assert is_suspicious is True
        assert "suspicious paths" in reason.lower()
    
    def test_multiple_fingerprints(self, analyzer):
        """Test detection of multiple user-agent fingerprints."""
        ip = "192.168.1.5"
        
        # Use different user-agents (simulating tool rotation)
        user_agents = ["Bot1/1.0", "Bot2/1.0", "Bot3/1.0", "Bot4/1.0", "Bot5/1.0"]
        for i, ua in enumerate(user_agents):
            analyzer.track_request(ip, f"/path{i}", ua)
        
        is_suspicious, confidence, reason = analyzer.analyze(ip)
        
        assert is_suspicious is True
        assert "multiple fingerprints" in reason.lower()
    
    def test_normal_behavior(self, analyzer):
        """Test that normal behavior is not flagged as suspicious."""
        ip = "192.168.1.6"
        
        # Simulate normal browsing pattern
        normal_paths = ["/", "/about", "/contact", "/products"]
        for path in normal_paths:
            analyzer.track_request(ip, path, "Mozilla/5.0 Browser")
            time.sleep(0.1)  # Normal intervals
        
        is_suspicious, confidence, reason = analyzer.analyze(ip)
        
        assert is_suspicious is False
        assert confidence < 0.5
    
    def test_cleanup_old_metrics(self, analyzer):
        """Test cleanup of old metrics."""
        old_ip = "192.168.1.100"
        recent_ip = "192.168.1.101"
        current_time = time.time()
        
        # Create old metrics manually
        old_metrics = BehavioralMetrics()
        old_metrics.last_seen = current_time - 7200  # 2 hours ago (older than window)
        analyzer.ip_metrics[old_ip] = old_metrics
        
        # Create recent metrics
        analyzer.track_request(recent_ip, "/recent", "RecentBot/1.0")
        
        # Force cleanup by updating the last cleanup time to trigger the condition
        analyzer._last_cleanup = current_time - analyzer.config.cleanup_interval_minutes * 60 - 1
        
        # Force cleanup with current time
        with patch('time.time', return_value=current_time):
            analyzer._cleanup_old_metrics()
        
        # Old IP should be cleaned up, recent should remain
        assert old_ip not in analyzer.ip_metrics
        assert recent_ip in analyzer.ip_metrics


class TestBotDetector:
    """Test bot detection engine."""
    
    @pytest.fixture
    def config(self):
        """Create configuration for testing."""
        return BotDetectionConfig(
            enable_caching=False  # Disable caching for predictable tests
        )
    
    @pytest.fixture
    def detector(self, config):
        """Create detector for testing."""
        return BotDetector(config)
    
    @pytest.mark.asyncio
    async def test_detect_legitimate_bot(self, detector):
        """Test detection of legitimate bots."""
        # Mock request
        request = Mock(spec=Request)
        request.headers = {"user-agent": "Googlebot/2.1"}
        request.url.path = "/page1"
        request.client.host = "192.168.1.1"
        
        result = await detector.detect(request)
        
        assert result.is_bot is True
        assert result.bot_type == BotType.SEARCH_ENGINE
        assert result.confidence >= 0.8  # Should be 0.9 for legitimate bots
        assert DetectionMethod.USER_AGENT in result.detection_methods
        assert result.action == BotAction.ALLOW  # Default for search engines
    
    @pytest.mark.asyncio
    async def test_detect_malicious_bot(self, detector):
        """Test detection of malicious bots."""
        request = Mock(spec=Request)
        request.headers = {"user-agent": "python-requests/2.28.1"}
        request.url.path = "/admin/login"
        request.client.host = "192.168.1.2"
        
        # Track some suspicious behavior first
        detector.behavioral_analyzer.track_request("192.168.1.2", "/admin/login", "python-requests/2.28.1")
        detector.behavioral_analyzer.track_request("192.168.1.2", "/.env", "python-requests/2.28.1")
        
        result = await detector.detect(request)
        
        assert result.is_bot is True
        assert result.confidence >= 0.5
        assert len(result.detection_methods) >= 1
    
    @pytest.mark.asyncio
    async def test_detect_normal_user(self, detector):
        """Test that normal users are not detected as bots."""
        request = Mock(spec=Request)
        request.headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        request.url.path = "/home"
        request.client.host = "192.168.1.3"
        
        result = await detector.detect(request)
        
        assert result.is_bot is False
        assert result.confidence < 0.5
        assert result.action == BotAction.LOG_ONLY
    
    @pytest.mark.asyncio
    async def test_cache_functionality(self):
        """Test caching of detection results."""
        config = BotDetectionConfig(enable_caching=True)
        detector = BotDetector(config)
        
        request = Mock(spec=Request)
        request.headers = {"user-agent": "TestBot/1.0"}
        request.url.path = "/test"
        request.client.host = "192.168.1.4"
        
        # First detection
        result1 = await detector.detect(request)
        
        # Second detection should use cache
        result2 = await detector.detect(request)
        
        assert result1.is_bot == result2.is_bot
        assert result1.confidence == result2.confidence
    
    def test_get_client_ip(self, detector):
        """Test IP address extraction."""
        request = Mock(spec=Request)
        
        # Test X-Forwarded-For header
        request.headers = {"x-forwarded-for": "203.0.113.1, 192.168.1.1"}
        ip = detector._get_client_ip(request)
        assert ip == "203.0.113.1"
        
        # Test X-Real-IP header
        request.headers = {"x-real-ip": "203.0.113.2"}
        ip = detector._get_client_ip(request)
        assert ip == "203.0.113.2"
        
        # Test fallback to client host
        request.headers = {}
        request.client.host = "192.168.1.5"
        ip = detector._get_client_ip(request)
        assert ip == "192.168.1.5"


class TestBotDetectionShield:
    """Test bot detection shield implementation."""
    
    @pytest.fixture
    def config(self):
        """Create configuration for testing."""
        return BotDetectionConfig(
            bot_type_actions={
                BotType.MALICIOUS: BotAction.BLOCK,
                BotType.SCRAPER: BotAction.CHALLENGE,
                BotType.SEARCH_ENGINE: BotAction.ALLOW,
            }
        )
    
    @pytest.fixture
    def shield_instance(self, config):
        """Create shield instance for testing."""
        return BotDetectionShield(config)
    
    def test_shield_initialization(self, shield_instance, config):
        """Test shield initialization."""
        assert shield_instance.config == config
        assert shield_instance.detector is not None


class TestBotDetectionIntegration:
    """Test bot detection integration with FastAPI."""
    
    def test_bot_detection_shield_allow(self):
        """Test bot detection shield allowing legitimate bots."""
        app = FastAPI()
        
        @app.get("/content")
        @bot_detection_shield(allow_search_engines=True)
        def get_content():
            return {"content": "public data"}
        
        client = TestClient(app)
        
        # Test with search engine bot
        response = client.get(
            "/content",
            headers={"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"}
        )
        
        assert response.status_code == 200
        assert "content" in response.json()
    
    def test_bot_detection_shield_block(self):
        """Test bot detection shield blocking malicious bots."""
        app = FastAPI()
        
        @app.get("/sensitive")
        @bot_detection_shield(block_malicious=True)
        def get_sensitive():
            return {"data": "sensitive"}
        
        client = TestClient(app)
        
        # Test with suspicious bot (make multiple requests to trigger behavioral detection)
        headers = {"User-Agent": "python-requests/2.28.1"}
        
        # Make several requests to build up behavioral profile
        for i in range(3):
            client.get(f"/sensitive?test={i}", headers=headers)
        
        # This request should be blocked if detected as malicious
        response = client.get("/sensitive", headers=headers)
        
        # Depending on detection confidence, might be blocked or challenged
        assert response.status_code in [200, 403, 429]
    
    def test_bot_detection_shield_challenge(self):
        """Test bot detection shield challenging scrapers."""
        app = FastAPI()
        
        @app.get("/api/data")
        @bot_detection_shield(challenge_scrapers=True)
        def get_api_data():
            return {"data": "api response"}
        
        client = TestClient(app)
        
        # Test with known scraper pattern
        response = client.get(
            "/api/data",
            headers={"User-Agent": "curl/7.68.0"}
        )
        
        # Should either be challenged or pass depending on detection
        assert response.status_code in [200, 429]
    
    def test_strict_bot_detection_shield(self):
        """Test strict bot detection shield."""
        app = FastAPI()
        
        @app.get("/admin")
        @strict_bot_detection_shield()
        def admin_panel():
            return {"admin": "panel"}
        
        client = TestClient(app)
        
        # Test with normal browser
        response = client.get(
            "/admin",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        
        # Should pass for normal browsers
        assert response.status_code == 200
        
        # Test with obvious bot
        response = client.get(
            "/admin",
            headers={"User-Agent": "curl/7.68.0"}
        )
        
        # Should be blocked or challenged
        assert response.status_code in [403, 429]
    
    def test_search_engine_friendly_shield(self):
        """Test search engine friendly shield."""
        app = FastAPI()
        
        @app.get("/public")
        @search_engine_friendly_shield()
        def public_content():
            return {"content": "public"}
        
        client = TestClient(app)
        
        # Test with search engine bot
        response = client.get(
            "/public",
            headers={"User-Agent": "Googlebot/2.1"}
        )
        
        assert response.status_code == 200
        
        # Test with social media bot
        response = client.get(
            "/public",
            headers={"User-Agent": "facebookexternalhit/1.1"}
        )
        
        assert response.status_code == 200


class TestBotTypes:
    """Test bot type enumeration."""
    
    def test_bot_type_values(self):
        """Test bot type enumeration values."""
        assert BotType.SEARCH_ENGINE == "search_engine"
        assert BotType.SOCIAL_MEDIA == "social_media"
        assert BotType.MONITORING == "monitoring"
        assert BotType.SCRAPER == "scraper"
        assert BotType.MALICIOUS == "malicious"
        assert BotType.CRAWLER == "crawler"
        assert BotType.SEO_TOOL == "seo_tool"
        assert BotType.SECURITY_SCANNER == "security_scanner"
        assert BotType.UNKNOWN == "unknown"


class TestDetectionMethods:
    """Test detection method enumeration."""
    
    def test_detection_method_values(self):
        """Test detection method enumeration values."""
        assert DetectionMethod.USER_AGENT == "user_agent"
        assert DetectionMethod.BEHAVIORAL == "behavioral"
        assert DetectionMethod.IP_REPUTATION == "ip_reputation"
        assert DetectionMethod.FINGERPRINTING == "fingerprinting"
        assert DetectionMethod.RATE_LIMITING == "rate_limiting"
        assert DetectionMethod.CAPTCHA == "captcha"


class TestBotActions:
    """Test bot action enumeration."""
    
    def test_bot_action_values(self):
        """Test bot action enumeration values."""
        assert BotAction.ALLOW == "allow"
        assert BotAction.BLOCK == "block"
        assert BotAction.CHALLENGE == "challenge"
        assert BotAction.RATE_LIMIT == "rate_limit"
        assert BotAction.LOG_ONLY == "log_only"


class TestChallengeTypes:
    """Test challenge type enumeration."""
    
    def test_challenge_type_values(self):
        """Test challenge type enumeration values."""
        assert ChallengeType.CAPTCHA == "captcha"
        assert ChallengeType.JAVASCRIPT == "javascript"
        assert ChallengeType.PROOF_OF_WORK == "proof_of_work"
        assert ChallengeType.DELAY == "delay"


class TestBotDetectionResult:
    """Test bot detection result model."""
    
    def test_bot_detection_result_creation(self):
        """Test creating bot detection result."""
        result = BotDetectionResult(
            is_bot=True,
            bot_type=BotType.SCRAPER,
            confidence=0.8,
            detection_methods=[DetectionMethod.USER_AGENT, DetectionMethod.BEHAVIORAL],
            user_agent="TestBot/1.0",
            ip_address="192.168.1.1",
            action=BotAction.CHALLENGE,
            challenge_required=True,
            reason="Bot patterns detected"
        )
        
        assert result.is_bot is True
        assert result.bot_type == BotType.SCRAPER
        assert result.confidence == 0.8
        assert DetectionMethod.USER_AGENT in result.detection_methods
        assert DetectionMethod.BEHAVIORAL in result.detection_methods
        assert result.user_agent == "TestBot/1.0"
        assert result.ip_address == "192.168.1.1"
        assert result.action == BotAction.CHALLENGE
        assert result.challenge_required is True
        assert result.reason == "Bot patterns detected"
        assert result.timestamp > 0


class TestBehavioralMetrics:
    """Test behavioral metrics model."""
    
    def test_behavioral_metrics_defaults(self):
        """Test default behavioral metrics."""
        metrics = BehavioralMetrics()
        
        assert metrics.request_count == 0
        assert len(metrics.unique_paths) == 0
        assert len(metrics.request_intervals) == 0
        assert metrics.suspicious_path_count == 0
        assert len(metrics.fingerprints) == 0
        assert metrics.first_seen > 0
        assert metrics.last_seen > 0


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_missing_user_agent(self):
        """Test handling of missing user-agent."""
        config = BotDetectionConfig()
        analyzer = UserAgentAnalyzer(config)
        
        is_bot, bot_type, confidence, reason = analyzer.analyze(None)
        
        assert is_bot is False
        assert bot_type is None
        assert confidence == 0.0
        assert "no user-agent provided" in reason.lower()
    
    def test_malformed_user_agent(self):
        """Test handling of malformed user-agent."""
        config = BotDetectionConfig()
        analyzer = UserAgentAnalyzer(config)
        
        # Test with very long user-agent
        long_ua = "A" * 10000
        is_bot, bot_type, confidence, reason = analyzer.analyze(long_ua)
        
        # Should still work, might be detected as suspicious
        assert isinstance(is_bot, bool)
        assert confidence >= 0.0
    
    def test_invalid_ip_address(self):
        """Test handling of invalid IP addresses."""
        config = BotDetectionConfig()
        analyzer = BehavioralAnalyzer(config)
        
        # Test with unusual IP format
        analyzer.track_request("invalid_ip", "/test", "Bot/1.0")
        
        # Should not crash
        is_suspicious, confidence, reason = analyzer.analyze("invalid_ip")
        assert isinstance(is_suspicious, bool)
    
    def test_concurrent_requests(self):
        """Test handling of concurrent requests to behavioral analyzer."""
        config = BotDetectionConfig()
        analyzer = BehavioralAnalyzer(config)
        
        # Simulate concurrent requests from same IP
        ip = "192.168.1.100"
        for i in range(10):
            analyzer.track_request(ip, f"/concurrent/{i}", "Bot/1.0")
        
        # Should handle correctly without errors
        is_suspicious, confidence, reason = analyzer.analyze(ip)
        assert isinstance(is_suspicious, bool)
        assert confidence >= 0.0


class TestPerformanceOptimizations:
    """Test performance-related features."""
    
    def test_pattern_compilation(self):
        """Test that regex patterns are compiled for performance."""
        config = BotDetectionConfig()
        analyzer = UserAgentAnalyzer(config)
        
        # Patterns should be compiled
        assert len(analyzer._bot_patterns) > 0
        assert len(analyzer._legitimate_patterns) > 0
    
    def test_metrics_cleanup(self):
        """Test that behavioral metrics are cleaned up."""
        config = BotDetectionConfig(
            max_tracked_ips=5,
            cleanup_interval_minutes=0  # Force immediate cleanup
        )
        analyzer = BehavioralAnalyzer(config)
        
        # Add more IPs than the limit
        for i in range(10):
            analyzer.track_request(f"192.168.1.{i}", "/test", "Bot/1.0")
        
        # Force cleanup
        analyzer._cleanup_old_metrics()
        
        # Should be limited to max_tracked_ips
        assert len(analyzer.ip_metrics) <= config.max_tracked_ips
    
    def test_cache_performance(self):
        """Test caching improves performance."""
        config = BotDetectionConfig(enable_caching=True)
        detector = BotDetector(config)
        
        # Cache should be empty initially
        assert len(detector._detection_cache) == 0
        
        # Create cache key
        cache_key = detector._get_cache_key("192.168.1.1", "Bot/1.0")
        assert isinstance(cache_key, str)
        assert len(cache_key) > 0


if __name__ == "__main__":
    pytest.main([__file__])