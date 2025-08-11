"""Mock infrastructure for threat intelligence testing."""

import asyncio
import json
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, AsyncMock
import uuid

from src.fastapi_shield.threat_intelligence import (
    ThreatIndicator, ThreatAssessment, IPGeolocation, ThreatFeedConfig,
    ThreatLevel, ThreatType, ThreatSource, ResponseAction, IPReputation
)


class MockThreatDatabase:
    """Mock threat intelligence database for testing."""
    
    def __init__(self):
        self.indicators = {}  # value -> ThreatIndicator
        self.reputation_cache = {}  # ip -> (reputation, risk_score, confidence, geolocation)
        self.storage_calls = []
        self.retrieval_calls = []
        self.search_calls = []
    
    def store_indicator(self, indicator: ThreatIndicator) -> bool:
        """Mock store threat indicator."""
        self.storage_calls.append(indicator)
        self.indicators[indicator.value] = indicator
        return True
    
    def get_indicator(self, value: str) -> Optional[ThreatIndicator]:
        """Mock retrieve threat indicator."""
        self.retrieval_calls.append(value)
        return self.indicators.get(value)
    
    def search_indicators(self, 
                         threat_type: Optional[ThreatType] = None,
                         threat_level: Optional[ThreatLevel] = None,
                         source: Optional[ThreatSource] = None,
                         limit: int = 100) -> List[ThreatIndicator]:
        """Mock search threat indicators."""
        self.search_calls.append({
            'threat_type': threat_type,
            'threat_level': threat_level,
            'source': source,
            'limit': limit
        })
        
        results = []
        for indicator in self.indicators.values():
            if threat_type and indicator.threat_type != threat_type:
                continue
            if threat_level and indicator.threat_level != threat_level:
                continue
            if source and indicator.source != source:
                continue
            results.append(indicator)
            if len(results) >= limit:
                break
        
        return results
    
    def cache_ip_reputation(self, ip: str, reputation: IPReputation, 
                           risk_score: float, confidence: float,
                           geolocation: Optional[IPGeolocation] = None,
                           ttl: int = 3600):
        """Mock cache IP reputation."""
        self.reputation_cache[ip] = (reputation, risk_score, confidence, geolocation)
    
    def get_cached_reputation(self, ip: str) -> Optional[Tuple[IPReputation, float, float, Optional[IPGeolocation]]]:
        """Mock get cached reputation."""
        return self.reputation_cache.get(ip)


class MockGeolocationService:
    """Mock geolocation service for testing."""
    
    def __init__(self):
        self.lookup_calls = []
        self.mock_data = {
            '1.2.3.4': IPGeolocation(
                ip='1.2.3.4',
                country='United States',
                country_code='US',
                region='California',
                city='San Francisco',
                latitude=37.7749,
                longitude=-122.4194,
                asn=12345,
                asn_org='Mock ISP',
                is_proxy=False,
                is_tor=False
            ),
            '5.6.7.8': IPGeolocation(
                ip='5.6.7.8',
                country='Russia',
                country_code='RU',
                region='Moscow',
                city='Moscow',
                latitude=55.7558,
                longitude=37.6173,
                asn=67890,
                asn_org='Suspicious ISP',
                is_proxy=True,
                is_tor=False
            ),
            '9.10.11.12': IPGeolocation(
                ip='9.10.11.12',
                country='Unknown',
                country_code='XX',
                region=None,
                city=None,
                latitude=None,
                longitude=None,
                asn=None,
                asn_org=None,
                is_proxy=False,
                is_tor=True
            )
        }
    
    async def get_geolocation(self, ip: str) -> Optional[IPGeolocation]:
        """Mock get geolocation for IP."""
        self.lookup_calls.append(ip)
        return self.mock_data.get(ip)


class MockThreatFeedProvider:
    """Mock threat feed provider for testing."""
    
    def __init__(self, config: ThreatFeedConfig):
        self.config = config
        self.fetch_calls = []
        self.reputation_calls = []
        self.mock_indicators = []
        self.mock_assessments = {}
        self._last_update = None
        self._request_count = 0
        self._request_window_start = time.time()
    
    def set_mock_indicators(self, indicators: List[ThreatIndicator]):
        """Set mock indicators to return."""
        self.mock_indicators = indicators
    
    def set_mock_assessment(self, ip: str, assessment: ThreatAssessment):
        """Set mock assessment for specific IP."""
        self.mock_assessments[ip] = assessment
    
    async def fetch_indicators(self) -> List[ThreatIndicator]:
        """Mock fetch indicators."""
        self.fetch_calls.append(datetime.now(timezone.utc))
        self._last_update = time.time()
        return self.mock_indicators.copy()
    
    async def check_ip_reputation(self, ip: str) -> Optional[ThreatAssessment]:
        """Mock check IP reputation."""
        if not self._check_rate_limit():
            return None
            
        self.reputation_calls.append(ip)
        return self.mock_assessments.get(ip)
    
    def _check_rate_limit(self) -> bool:
        """Mock rate limit check."""
        current_time = time.time()
        
        # Reset counter if window expired
        if current_time - self._request_window_start > 60:
            self._request_count = 0
            self._request_window_start = current_time
        
        if self._request_count >= self.config.rate_limit:
            return False
        
        self._request_count += 1
        return True
    
    def _needs_update(self) -> bool:
        """Mock needs update check."""
        if not self._last_update:
            return True
        return (time.time() - self._last_update) > self.config.update_interval


class MockThreatSignatureEngine:
    """Mock threat signature engine for testing."""
    
    def __init__(self):
        self.signatures = {}
        self.scan_calls = []
        self.mock_indicators = []
    
    def add_signature(self, name: str, pattern: str, threat_level: ThreatLevel):
        """Mock add signature."""
        if name not in self.signatures:
            self.signatures[name] = []
        
        self.signatures[name].append({
            'pattern': pattern,
            'threat_level': threat_level
        })
    
    def scan_request(self, request_data: Dict[str, Any]) -> List[ThreatIndicator]:
        """Mock scan request."""
        self.scan_calls.append(request_data)
        return self.mock_indicators.copy()
    
    def set_mock_indicators(self, indicators: List[ThreatIndicator]):
        """Set mock indicators to return from scans."""
        self.mock_indicators = indicators


class MockThreatResponseManager:
    """Mock threat response manager for testing."""
    
    def __init__(self):
        self.response_policies = {}
        self.blocked_ips = set()
        self.rate_limited_ips = {}
        self.policy_calls = []
        self.response_calls = []
        self.block_checks = []
        self.rate_limit_checks = []
    
    def add_response_policy(self, threat_level: ThreatLevel, response):
        """Mock add response policy."""
        self.policy_calls.append((threat_level, response))
        self.response_policies[threat_level] = response
    
    def execute_response(self, assessment: ThreatAssessment) -> List[str]:
        """Mock execute response."""
        self.response_calls.append(assessment)
        
        policy = self.response_policies.get(assessment.threat_level)
        if not policy:
            return []
        
        actions = []
        ip = assessment.ip
        
        if policy.action == ResponseAction.PERMANENT_BLOCK:
            self.blocked_ips.add(ip)
            actions.append(f"Permanently blocked IP: {ip}")
        elif policy.action == ResponseAction.TEMPORARY_BLOCK:
            self.blocked_ips.add(ip)
            actions.append(f"Temporarily blocked IP: {ip}")
        elif policy.action == ResponseAction.RATE_LIMIT:
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
            self.rate_limited_ips[ip] = expires_at
            actions.append(f"Rate limited IP: {ip}")
        
        return actions
    
    def is_blocked(self, ip: str) -> bool:
        """Mock check if IP is blocked."""
        self.block_checks.append(ip)
        return ip in self.blocked_ips
    
    def is_rate_limited(self, ip: str) -> bool:
        """Mock check if IP is rate limited."""
        self.rate_limit_checks.append(ip)
        if ip in self.rate_limited_ips:
            expiry = self.rate_limited_ips[ip]
            if datetime.now(timezone.utc) < expiry:
                return True
            else:
                del self.rate_limited_ips[ip]
        return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Mock unblock IP."""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            return True
        if ip in self.rate_limited_ips:
            del self.rate_limited_ips[ip]
            return True
        return False


class MockIPReputationAnalyzer:
    """Mock IP reputation analyzer for testing."""
    
    def __init__(self, geolocation_service):
        self.geolocation_service = geolocation_service
        self.analysis_calls = []
        self.risk_score_calls = []
        self.mock_reputations = {}
        self.mock_risk_scores = {}
    
    def set_mock_reputation(self, ip: str, reputation: IPReputation):
        """Set mock reputation for IP."""
        self.mock_reputations[ip] = reputation
    
    def set_mock_risk_score(self, indicators_key: str, score: float):
        """Set mock risk score for indicators."""
        self.mock_risk_scores[indicators_key] = score
    
    async def analyze_ip(self, ip: str, indicators: List[ThreatIndicator]) -> IPReputation:
        """Mock analyze IP reputation."""
        self.analysis_calls.append((ip, len(indicators)))
        return self.mock_reputations.get(ip, IPReputation.UNKNOWN)
    
    def calculate_risk_score(self, indicators: List[ThreatIndicator], 
                           geolocation: Optional[IPGeolocation] = None) -> float:
        """Mock calculate risk score."""
        self.risk_score_calls.append((len(indicators), geolocation is not None))
        
        # Create a simple key based on indicators
        key = f"{len(indicators)}_indicators"
        return self.mock_risk_scores.get(key, 0.5)


class MockThreatIntelligenceEngine:
    """Mock threat intelligence engine for testing."""
    
    def __init__(self):
        self.database = MockThreatDatabase()
        self.geolocation_service = MockGeolocationService()
        self.reputation_analyzer = MockIPReputationAnalyzer(self.geolocation_service)
        self.signature_engine = MockThreatSignatureEngine()
        self.response_manager = MockThreatResponseManager()
        
        self.feed_providers = {}
        self.assessment_calls = []
        self.request_threat_calls = []
        self.mock_assessments = {}
        self._running = False
    
    def add_feed_provider(self, name: str, provider):
        """Mock add feed provider."""
        self.feed_providers[name] = provider
    
    def start_feed_updates(self):
        """Mock start feed updates."""
        self._running = True
    
    def stop_feed_updates(self):
        """Mock stop feed updates."""
        self._running = False
    
    def set_mock_assessment(self, ip: str, assessment: ThreatAssessment):
        """Set mock assessment for IP."""
        self.mock_assessments[ip] = assessment
    
    async def assess_ip_threat(self, ip: str, request_data: Optional[Dict[str, Any]] = None) -> ThreatAssessment:
        """Mock assess IP threat."""
        self.assessment_calls.append((ip, request_data is not None))
        
        if ip in self.mock_assessments:
            return self.mock_assessments[ip]
        
        # Check for invalid IP addresses
        try:
            from ipaddress import ip_address
            ip_address(ip)
        except:
            return ThreatAssessment(
                ip=ip,
                threat_level=ThreatLevel.UNKNOWN,
                reputation=IPReputation.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                indicators=[],
                reasons=["Invalid IP address format"]
            )
        
        # Return default assessment
        return ThreatAssessment(
            ip=ip,
            threat_level=ThreatLevel.LOW,
            reputation=IPReputation.CLEAN,
            risk_score=0.1,
            confidence=0.8,
            indicators=[],
            reasons=["Mock assessment"]
        )
    
    def check_request_threat(self, request) -> ThreatAssessment:
        """Mock check request threat."""
        self.request_threat_calls.append(request)
        
        # Extract IP from mock request
        ip = "127.0.0.1"  # Default for testing
        if hasattr(request, 'client') and request.client:
            ip = request.client.host
        
        if ip in self.mock_assessments:
            return self.mock_assessments[ip]
        
        return ThreatAssessment(
            ip=ip,
            threat_level=ThreatLevel.LOW,
            reputation=IPReputation.CLEAN,
            risk_score=0.1,
            confidence=0.8,
            indicators=[],
            reasons=["Mock request assessment"]
        )


class MockHTTPClient:
    """Mock HTTP client for external API calls."""
    
    def __init__(self):
        self.requests = []
        self.responses = {}
        self.default_response = Mock()
        self.default_response.status_code = 200
        self.default_response.json.return_value = {'status': 'success'}
        self.default_response.text = ""
    
    def set_response(self, url_pattern: str, response_data: Dict[str, Any], status_code: int = 200):
        """Set mock response for URL pattern."""
        mock_response = Mock()
        mock_response.status_code = status_code
        mock_response.json.return_value = response_data
        mock_response.text = json.dumps(response_data) if isinstance(response_data, dict) else str(response_data)
        self.responses[url_pattern] = mock_response
    
    async def get(self, url: str, headers: Optional[Dict] = None, params: Optional[Dict] = None, **kwargs):
        """Mock GET request."""
        self.requests.append({
            'method': 'GET',
            'url': url,
            'headers': headers,
            'params': params,
            'kwargs': kwargs
        })
        
        # Find matching response
        for pattern, response in self.responses.items():
            if pattern in url:
                return response
        
        return self.default_response
    
    async def post(self, url: str, headers: Optional[Dict] = None, data: Optional[Any] = None, **kwargs):
        """Mock POST request."""
        self.requests.append({
            'method': 'POST',
            'url': url,
            'headers': headers,
            'data': data,
            'kwargs': kwargs
        })
        
        # Find matching response
        for pattern, response in self.responses.items():
            if pattern in url:
                return response
        
        return self.default_response
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(self, client_ip: str = "127.0.0.1", headers: Optional[Dict[str, str]] = None):
        self.client = Mock()
        self.client.host = client_ip
        self.headers = headers or {}
        self.url = Mock()
        self.url.path = "/test"
        self.method = "GET"
        self.query_params = {}


class MockThreatIntelligenceTestEnvironment:
    """Comprehensive mock environment for threat intelligence testing."""
    
    def __init__(self):
        self.engine = MockThreatIntelligenceEngine()
        self.http_client = MockHTTPClient()
        self.test_indicators = self._generate_test_indicators()
        self.test_assessments = self._generate_test_assessments()
        self.performance_metrics = {
            'api_calls': [],
            'response_times': [],
            'cache_hits': 0,
            'cache_misses': 0
        }
    
    def _generate_test_indicators(self) -> Dict[str, ThreatIndicator]:
        """Generate test threat indicators."""
        indicators = {}
        
        # Malicious IP indicator
        malicious_indicator = ThreatIndicator(
            id=str(uuid.uuid4()),
            value="192.168.1.100",
            threat_type=ThreatType.MALICIOUS_IP,
            threat_level=ThreatLevel.HIGH,
            source=ThreatSource.ABUSE_IPDB,
            confidence=0.9,
            first_seen=datetime.now(timezone.utc) - timedelta(days=1),
            last_seen=datetime.now(timezone.utc),
            tags=['botnet', 'malware'],
            metadata={'abuse_confidence': 85, 'total_reports': 42}
        )
        indicators['192.168.1.100'] = malicious_indicator
        
        # Bot traffic indicator
        bot_indicator = ThreatIndicator(
            id=str(uuid.uuid4()),
            value="10.0.0.50",
            threat_type=ThreatType.BOT_TRAFFIC,
            threat_level=ThreatLevel.MEDIUM,
            source=ThreatSource.INTERNAL,
            confidence=0.7,
            first_seen=datetime.now(timezone.utc) - timedelta(hours=6),
            last_seen=datetime.now(timezone.utc),
            tags=['bot', 'scraping'],
            metadata={'request_rate': 1000, 'user_agent': 'suspicious-bot'}
        )
        indicators['10.0.0.50'] = bot_indicator
        
        # Clean IP (no indicator)
        indicators['1.2.3.4'] = None  # Clean IP
        
        return indicators
    
    def _generate_test_assessments(self) -> Dict[str, ThreatAssessment]:
        """Generate test threat assessments."""
        assessments = {}
        
        # High-risk assessment
        high_risk = ThreatAssessment(
            ip="192.168.1.100",
            threat_level=ThreatLevel.HIGH,
            reputation=IPReputation.MALICIOUS,
            risk_score=0.85,
            confidence=0.9,
            indicators=[self.test_indicators['192.168.1.100']],
            geolocation=IPGeolocation(
                ip="192.168.1.100",
                country="Unknown",
                country_code="XX",
                is_proxy=True
            ),
            recommended_action=ResponseAction.TEMPORARY_BLOCK,
            reasons=["High abuse confidence", "Known botnet member"]
        )
        assessments['192.168.1.100'] = high_risk
        
        # Medium-risk assessment
        medium_risk = ThreatAssessment(
            ip="10.0.0.50",
            threat_level=ThreatLevel.MEDIUM,
            reputation=IPReputation.SUSPICIOUS,
            risk_score=0.6,
            confidence=0.7,
            indicators=[self.test_indicators['10.0.0.50']],
            recommended_action=ResponseAction.RATE_LIMIT,
            reasons=["Suspicious bot activity", "High request rate"]
        )
        assessments['10.0.0.50'] = medium_risk
        
        # Low-risk assessment
        low_risk = ThreatAssessment(
            ip="1.2.3.4",
            threat_level=ThreatLevel.LOW,
            reputation=IPReputation.CLEAN,
            risk_score=0.1,
            confidence=0.8,
            indicators=[],
            geolocation=self.engine.geolocation_service.mock_data['1.2.3.4'],
            recommended_action=ResponseAction.MONITOR,
            reasons=["Clean reputation", "Legitimate traffic"]
        )
        assessments['1.2.3.4'] = low_risk
        
        return assessments
    
    def setup_mock_responses(self):
        """Setup mock HTTP responses for external services."""
        # VirusTotal responses
        self.http_client.set_response("virustotal.com", {
            'response_code': 1,
            'detected_urls': [{'url': 'http://example.com', 'positives': 5}],
            'detected_samples': []
        })
        
        # AbuseIPDB responses
        self.http_client.set_response("abuseipdb.com", {
            'data': {
                'ipAddress': '192.168.1.100',
                'abuseConfidencePercentage': 85,
                'countryCode': 'XX',
                'usageType': 'hosting',
                'totalReports': 42,
                'isWhitelisted': False
            }
        })
        
        # IP geolocation responses
        self.http_client.set_response("ip-api.com", {
            'status': 'success',
            'country': 'United States',
            'countryCode': 'US',
            'region': 'CA',
            'regionName': 'California',
            'city': 'San Francisco',
            'lat': 37.7749,
            'lon': -122.4194,
            'isp': 'Mock ISP',
            'as': 'AS12345 Mock ISP',
            'proxy': False
        })
    
    def track_performance(self, operation: str, duration: float):
        """Track performance metrics."""
        self.performance_metrics['api_calls'].append({
            'operation': operation,
            'timestamp': time.time(),
            'duration': duration
        })
        self.performance_metrics['response_times'].append(duration)
    
    def simulate_high_load(self, num_requests: int = 1000, duration_seconds: int = 10):
        """Simulate high-load testing scenario."""
        start_time = time.time()
        requests_processed = 0
        
        while time.time() - start_time < duration_seconds and requests_processed < num_requests:
            # Simulate threat assessment request
            ip = f"192.168.1.{(requests_processed % 254) + 1}"
            
            assessment_start = time.time()
            # Mock assessment processing
            time.sleep(0.001)  # 1ms processing time
            assessment_time = time.time() - assessment_start
            
            self.track_performance("assess_ip_threat", assessment_time)
            requests_processed += 1
        
        return {
            'requests_processed': requests_processed,
            'duration': time.time() - start_time,
            'avg_response_time': sum(self.performance_metrics['response_times'][-requests_processed:]) / requests_processed,
            'max_response_time': max(self.performance_metrics['response_times'][-requests_processed:]),
            'requests_per_second': requests_processed / (time.time() - start_time)
        }
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        if not self.performance_metrics['response_times']:
            return {'status': 'no_data'}
        
        response_times = self.performance_metrics['response_times']
        
        return {
            'total_requests': len(response_times),
            'avg_response_time': sum(response_times) / len(response_times),
            'max_response_time': max(response_times),
            'min_response_time': min(response_times),
            'cache_hit_rate': (
                self.performance_metrics['cache_hits'] / 
                (self.performance_metrics['cache_hits'] + self.performance_metrics['cache_misses'])
                if (self.performance_metrics['cache_hits'] + self.performance_metrics['cache_misses']) > 0 
                else 0
            ),
            'total_api_calls': len(self.performance_metrics['api_calls'])
        }
    
    def reset(self):
        """Reset all mock services and metrics."""
        self.engine = MockThreatIntelligenceEngine()
        self.http_client = MockHTTPClient()
        self.performance_metrics = {
            'api_calls': [],
            'response_times': [],
            'cache_hits': 0,
            'cache_misses': 0
        }
        self.setup_mock_responses()


# Export all mock classes
__all__ = [
    'MockThreatDatabase',
    'MockGeolocationService', 
    'MockThreatFeedProvider',
    'MockThreatSignatureEngine',
    'MockThreatResponseManager',
    'MockIPReputationAnalyzer',
    'MockThreatIntelligenceEngine',
    'MockHTTPClient',
    'MockRequest',
    'MockThreatIntelligenceTestEnvironment'
]