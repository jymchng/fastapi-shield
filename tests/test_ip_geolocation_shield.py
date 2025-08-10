"""Tests for IP geolocation shield functionality."""

import ipaddress
import sys
from typing import Dict, List, Optional
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield.ip_geolocation import (
    IPGeolocationShield,
    IPRule,
    IPAction,
    IPRuleType,
    GeoLocation,
    GeolocationProvider,
    MockGeolocationProvider,
    IPApiGeolocationProvider,
    MaxMindGeolocationProvider,
    ip_geolocation_shield,
    country_blocking_shield,
    ip_whitelist_shield,
    proxy_detection_shield,
)


class TestGeoLocation:
    """Test GeoLocation model."""
    
    def test_geolocation_creation(self):
        """Test creating GeoLocation instance."""
        geo = GeoLocation(
            ip="192.168.1.1",
            country="United States",
            country_code="US",
            region="California",
            city="San Francisco",
            latitude=37.7749,
            longitude=-122.4194,
            is_proxy=False
        )
        assert geo.ip == "192.168.1.1"
        assert geo.country == "United States"
        assert geo.country_code == "US"
        assert geo.latitude == 37.7749
        assert geo.is_proxy is False
    
    def test_geolocation_defaults(self):
        """Test GeoLocation with minimal data."""
        geo = GeoLocation(ip="10.0.0.1")
        assert geo.ip == "10.0.0.1"
        assert geo.country is None
        assert geo.is_proxy is False
        assert geo.is_vpn is False
        assert geo.is_tor is False


class TestIPRule:
    """Test IPRule configuration."""
    
    def test_ip_rule_creation(self):
        """Test creating IP rules."""
        rule = IPRule(
            name="block_country",
            rule_type=IPRuleType.COUNTRY,
            action=IPAction.BLOCK,
            value=["CN", "RU"],
            description="Block high-risk countries",
            priority=10
        )
        assert rule.name == "block_country"
        assert rule.rule_type == IPRuleType.COUNTRY
        assert rule.action == IPAction.BLOCK
        assert rule.value == ["CN", "RU"]
        assert rule.priority == 10
    
    def test_ip_rule_defaults(self):
        """Test IP rule default values."""
        rule = IPRule(
            name="simple_rule",
            rule_type=IPRuleType.SINGLE_IP,
            action=IPAction.ALLOW,
            value="192.168.1.1"
        )
        assert rule.description is None
        assert rule.priority == 100


class TestMockGeolocationProvider:
    """Test the mock geolocation provider."""
    
    @pytest.fixture
    def provider(self):
        return MockGeolocationProvider()
    
    @pytest.mark.asyncio
    async def test_get_location_known_ip(self, provider):
        """Test getting location for known IP."""
        geo = await provider.get_location("192.168.1.1")
        assert geo is not None
        assert geo.ip == "192.168.1.1"
        assert geo.country == "United States"
        assert geo.country_code == "US"
    
    @pytest.mark.asyncio
    async def test_get_location_unknown_ip(self, provider):
        """Test getting location for unknown IP."""
        geo = await provider.get_location("9.9.9.9")
        assert geo is None
    
    @pytest.mark.asyncio
    async def test_get_location_batch(self, provider):
        """Test batch location lookup."""
        ips = ["192.168.1.1", "10.0.0.1", "9.9.9.9"]
        results = await provider.get_location_batch(ips)
        
        assert len(results) == 3
        assert results["192.168.1.1"] is not None
        assert results["10.0.0.1"] is not None
        assert results["9.9.9.9"] is None


class TestIPApiGeolocationProvider:
    """Test the IP-API geolocation provider."""
    
    def test_initialization(self):
        """Test provider initialization."""
        provider = IPApiGeolocationProvider(api_key="test_key", timeout=10.0)
        assert provider.api_key == "test_key"
        assert provider.timeout == 10.0
    
    @pytest.mark.asyncio
    async def test_get_location_success(self):
        """Test successful geolocation lookup."""
        mock_response_data = {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "regionName": "California",
            "region": "CA",
            "city": "San Francisco",
            "timezone": "America/Los_Angeles",
            "lat": 37.7749,
            "lon": -122.4194,
            "as": "AS15169 Google LLC",
            "proxy": False,
            "hosting": False
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = Mock()
            mock_response.json.return_value = mock_response_data
            mock_response.raise_for_status.return_value = None
            
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            provider = IPApiGeolocationProvider()
            geo = await provider.get_location("8.8.8.8")
            
            assert geo is not None
            assert geo.country == "United States"
            assert geo.country_code == "US"
            assert geo.latitude == 37.7749
            assert geo.asn == 15169
            assert geo.asn_org == "Google LLC"
    
    @pytest.mark.asyncio
    async def test_get_location_failure(self):
        """Test failed geolocation lookup."""
        mock_response_data = {
            "status": "fail",
            "message": "private range"
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = Mock()
            mock_response.json.return_value = mock_response_data
            mock_response.raise_for_status.return_value = None
            
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            provider = IPApiGeolocationProvider()
            geo = await provider.get_location("192.168.1.1")
            
            assert geo is None
    
    @pytest.mark.asyncio
    async def test_get_location_exception(self):
        """Test exception handling in geolocation lookup."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(side_effect=Exception("Network error"))
            
            provider = IPApiGeolocationProvider()
            geo = await provider.get_location("8.8.8.8")
            
            assert geo is None


class TestMaxMindGeolocationProvider:
    """Test the MaxMind geolocation provider."""
    
    def test_initialization_without_db(self):
        """Test initialization without database."""
        provider = MaxMindGeolocationProvider()
        assert provider.database_path is None
        assert provider._geoip_reader is None
    
    def test_initialization_with_maxminddb_unavailable(self):
        """Test initialization when maxminddb is not available."""
        with patch.dict('sys.modules', {'maxminddb': None}):
            provider = MaxMindGeolocationProvider("/path/to/db")
            assert provider.maxminddb is None
    
    @pytest.mark.asyncio
    async def test_get_location_no_reader(self):
        """Test get_location without database reader."""
        provider = MaxMindGeolocationProvider()
        geo = await provider.get_location("8.8.8.8")
        assert geo is None


class TestIPGeolocationShield:
    """Test the IP geolocation shield class."""
    
    @pytest.fixture
    def mock_request(self):
        """Create a mock request for testing."""
        request = Mock()
        request.client = Mock()
        request.client.host = "192.168.1.1"
        request.headers = {}
        return request
    
    def test_initialization_defaults(self):
        """Test shield initialization with defaults."""
        shield = IPGeolocationShield()
        assert shield.rules == []
        assert isinstance(shield.geolocation_provider, MockGeolocationProvider)
        assert shield.default_action == IPAction.ALLOW
        assert shield.enable_caching is True
        assert shield.extract_real_ip is True
    
    def test_initialization_custom(self):
        """Test shield initialization with custom settings."""
        rules = [
            IPRule(
                name="test_rule",
                rule_type=IPRuleType.COUNTRY,
                action=IPAction.BLOCK,
                value=["CN"]
            )
        ]
        provider = MockGeolocationProvider()
        
        shield = IPGeolocationShield(
            rules=rules,
            geolocation_provider=provider,
            default_action=IPAction.BLOCK,
            enable_caching=False,
            trusted_proxies=["10.0.0.0/8"],
            extract_real_ip=False
        )
        
        assert len(shield.rules) == 1
        assert shield.geolocation_provider is provider
        assert shield.default_action == IPAction.BLOCK
        assert shield.enable_caching is False
        assert shield.extract_real_ip is False
        assert len(shield.trusted_proxies) == 1
    
    def test_parse_trusted_proxies(self):
        """Test parsing trusted proxy CIDR ranges."""
        shield = IPGeolocationShield(trusted_proxies=["10.0.0.0/8", "192.168.0.0/16", "invalid"])
        assert len(shield.trusted_proxies) == 2
        assert ipaddress.IPv4Network("10.0.0.0/8") in shield.trusted_proxies
        assert ipaddress.IPv4Network("192.168.0.0/16") in shield.trusted_proxies
    
    def test_extract_client_ip_direct(self, mock_request):
        """Test extracting IP from direct connection."""
        shield = IPGeolocationShield(extract_real_ip=False)
        ip = shield._extract_client_ip(mock_request)
        assert ip == "192.168.1.1"
    
    def test_extract_client_ip_x_forwarded_for(self, mock_request):
        """Test extracting IP from X-Forwarded-For header."""
        mock_request.headers = {"X-Forwarded-For": "8.8.8.8, 1.1.1.1, 192.168.1.1"}
        
        shield = IPGeolocationShield(extract_real_ip=True)
        ip = shield._extract_client_ip(mock_request)
        assert ip == "8.8.8.8"  # First public IP (leftmost)
    
    def test_extract_client_ip_x_real_ip(self, mock_request):
        """Test extracting IP from X-Real-IP header."""
        mock_request.headers = {"X-Real-IP": "8.8.8.8"}
        
        shield = IPGeolocationShield(extract_real_ip=True)
        ip = shield._extract_client_ip(mock_request)
        assert ip == "8.8.8.8"
    
    def test_extract_client_ip_cloudflare(self, mock_request):
        """Test extracting IP from Cloudflare header."""
        mock_request.headers = {"CF-Connecting-IP": "8.8.8.8"}
        
        shield = IPGeolocationShield(extract_real_ip=True)
        ip = shield._extract_client_ip(mock_request)
        assert ip == "8.8.8.8"
    
    def test_is_valid_ip(self):
        """Test IP address validation."""
        shield = IPGeolocationShield()
        
        assert shield._is_valid_ip("192.168.1.1") is True
        assert shield._is_valid_ip("2001:db8::1") is True
        assert shield._is_valid_ip("not.an.ip") is False
        assert shield._is_valid_ip("256.256.256.256") is False
    
    def test_is_private_ip(self):
        """Test private IP detection."""
        shield = IPGeolocationShield()
        
        assert shield._is_private_ip("192.168.1.1") is True
        assert shield._is_private_ip("10.0.0.1") is True
        assert shield._is_private_ip("172.16.0.1") is True
        assert shield._is_private_ip("127.0.0.1") is True
        assert shield._is_private_ip("8.8.8.8") is False
    
    def test_is_ip_in_trusted_proxies(self):
        """Test trusted proxy detection."""
        shield = IPGeolocationShield(trusted_proxies=["10.0.0.0/8", "8.8.8.0/24"])
        
        assert shield._is_ip_in_trusted_proxies("10.0.0.1") is True
        assert shield._is_ip_in_trusted_proxies("8.8.8.8") is True
        assert shield._is_ip_in_trusted_proxies("1.1.1.1") is False
    
    def test_match_ip_rule_single_ip(self):
        """Test matching single IP rule."""
        rule = IPRule(
            name="allow_ip",
            rule_type=IPRuleType.SINGLE_IP,
            action=IPAction.ALLOW,
            value="192.168.1.1"
        )
        shield = IPGeolocationShield()
        
        assert shield._match_ip_rule(rule, "192.168.1.1", None) is True
        assert shield._match_ip_rule(rule, "192.168.1.2", None) is False
    
    def test_match_ip_rule_cidr_range(self):
        """Test matching CIDR range rule."""
        rule = IPRule(
            name="allow_network",
            rule_type=IPRuleType.CIDR_RANGE,
            action=IPAction.ALLOW,
            value="192.168.1.0/24"
        )
        shield = IPGeolocationShield()
        
        assert shield._match_ip_rule(rule, "192.168.1.1", None) is True
        assert shield._match_ip_rule(rule, "192.168.1.255", None) is True
        assert shield._match_ip_rule(rule, "192.168.2.1", None) is False
    
    def test_match_ip_rule_cidr_range_list(self):
        """Test matching CIDR range rule with multiple ranges."""
        rule = IPRule(
            name="allow_networks",
            rule_type=IPRuleType.CIDR_RANGE,
            action=IPAction.ALLOW,
            value=["192.168.1.0/24", "10.0.0.0/8"]
        )
        shield = IPGeolocationShield()
        
        assert shield._match_ip_rule(rule, "192.168.1.1", None) is True
        assert shield._match_ip_rule(rule, "10.0.0.1", None) is True
        assert shield._match_ip_rule(rule, "172.16.0.1", None) is False
    
    def test_match_ip_rule_country(self):
        """Test matching country rule."""
        rule = IPRule(
            name="block_countries",
            rule_type=IPRuleType.COUNTRY,
            action=IPAction.BLOCK,
            value=["CN", "RU"]
        )
        shield = IPGeolocationShield()
        
        geo_cn = GeoLocation(ip="1.2.3.4", country_code="CN")
        geo_us = GeoLocation(ip="1.2.3.4", country_code="US")
        
        assert shield._match_ip_rule(rule, "1.2.3.4", geo_cn) is True
        assert shield._match_ip_rule(rule, "1.2.3.4", geo_us) is False
        assert shield._match_ip_rule(rule, "1.2.3.4", None) is False
    
    def test_match_ip_rule_proxy(self):
        """Test matching proxy rule."""
        rule = IPRule(
            name="block_proxies",
            rule_type=IPRuleType.PROXY,
            action=IPAction.BLOCK,
            value=True
        )
        shield = IPGeolocationShield()
        
        geo_proxy = GeoLocation(ip="1.2.3.4", is_proxy=True)
        geo_normal = GeoLocation(ip="1.2.3.4", is_proxy=False)
        
        assert shield._match_ip_rule(rule, "1.2.3.4", geo_proxy) is True
        assert shield._match_ip_rule(rule, "1.2.3.4", geo_normal) is False
    
    def test_match_ip_rule_vpn(self):
        """Test matching VPN rule."""
        rule = IPRule(
            name="block_vpns",
            rule_type=IPRuleType.VPN,
            action=IPAction.BLOCK,
            value=True
        )
        shield = IPGeolocationShield()
        
        geo_vpn = GeoLocation(ip="1.2.3.4", is_vpn=True)
        geo_normal = GeoLocation(ip="1.2.3.4", is_vpn=False)
        
        assert shield._match_ip_rule(rule, "1.2.3.4", geo_vpn) is True
        assert shield._match_ip_rule(rule, "1.2.3.4", geo_normal) is False
    
    def test_match_ip_rule_asn(self):
        """Test matching ASN rule."""
        rule = IPRule(
            name="block_asn",
            rule_type=IPRuleType.ASN,
            action=IPAction.BLOCK,
            value="15169"  # Google
        )
        shield = IPGeolocationShield()
        
        geo_google = GeoLocation(ip="8.8.8.8", asn=15169)
        geo_other = GeoLocation(ip="1.1.1.1", asn=13335)
        
        assert shield._match_ip_rule(rule, "8.8.8.8", geo_google) is True
        assert shield._match_ip_rule(rule, "1.1.1.1", geo_other) is False
    
    @pytest.mark.asyncio
    async def test_evaluate_ip_access_allow_default(self):
        """Test IP access evaluation with default allow."""
        shield = IPGeolocationShield(default_action=IPAction.ALLOW)
        
        action, reason, geo_data = await shield._evaluate_ip_access("8.8.8.8")
        assert action == IPAction.ALLOW
        assert "default action" in reason
    
    @pytest.mark.asyncio
    async def test_evaluate_ip_access_rule_match(self):
        """Test IP access evaluation with rule match."""
        rules = [
            IPRule(
                name="block_china",
                rule_type=IPRuleType.COUNTRY,
                action=IPAction.BLOCK,
                value=["CN"]
            )
        ]
        shield = IPGeolocationShield(rules=rules)
        
        action, reason, geo_data = await shield._evaluate_ip_access("1.2.3.4")  # Mock CN IP
        assert action == IPAction.BLOCK
        assert "block_china" in reason
    
    @pytest.mark.asyncio
    async def test_get_cached_geolocation(self):
        """Test geolocation caching."""
        shield = IPGeolocationShield(enable_caching=True, cache_ttl=3600)
        
        # First call should fetch from provider
        geo1 = await shield._get_cached_geolocation("192.168.1.1")
        assert geo1 is not None
        
        # Second call should use cache
        geo2 = await shield._get_cached_geolocation("192.168.1.1")
        assert geo2 is not None
        assert geo1.ip == geo2.ip
    
    @pytest.mark.asyncio
    async def test_get_cached_geolocation_expired(self):
        """Test expired cache handling."""
        shield = IPGeolocationShield(enable_caching=True, cache_ttl=0)  # Immediate expiry
        
        geo1 = await shield._get_cached_geolocation("192.168.1.1")
        assert geo1 is not None
        
        # Should fetch again due to immediate expiry
        geo2 = await shield._get_cached_geolocation("192.168.1.1")
        assert geo2 is not None


class TestIPGeolocationIntegration:
    """Integration tests with FastAPI."""
    
    def test_basic_ip_geolocation_shield(self):
        """Test basic IP geolocation shield integration."""
        app = FastAPI()
        
        @app.get("/api/data")
        @ip_geolocation_shield()
        def get_data():
            return {"data": "value"}
        
        client = TestClient(app)
        
        response = client.get("/api/data")
        assert response.status_code == 200
    
    def test_country_blocking_shield(self):
        """Test country blocking shield."""
        app = FastAPI()
        
        @app.get("/api/restricted")
        @country_blocking_shield(blocked_countries=["CN", "RU"])
        def restricted_endpoint():
            return {"data": "restricted"}
        
        client = TestClient(app)
        
        # Default testclient IP should not be blocked
        response = client.get("/api/restricted")
        assert response.status_code == 200
    
    def test_ip_whitelist_shield(self):
        """Test IP whitelist shield."""
        app = FastAPI()
        
        @app.get("/api/whitelist")
        @ip_whitelist_shield(allowed_ips=["testclient"], allowed_cidrs=["192.168.0.0/16"])
        def whitelist_endpoint():
            return {"data": "whitelisted"}
        
        client = TestClient(app)
        
        # TestClient uses "testclient" as the default client host
        response = client.get("/api/whitelist")
        assert response.status_code == 200
    
    def test_proxy_detection_shield(self):
        """Test proxy detection shield."""
        app = FastAPI()
        
        @app.get("/api/no-proxies")
        @proxy_detection_shield(block_proxies=True, block_vpns=True)
        def no_proxy_endpoint():
            return {"data": "no_proxies"}
        
        client = TestClient(app)
        
        # Default testclient should not be detected as proxy
        response = client.get("/api/no-proxies")
        assert response.status_code == 200
    
    def test_ip_geolocation_shield_with_rules(self):
        """Test IP geolocation shield with custom rules."""
        rules = [
            IPRule(
                name="allow_localhost",
                rule_type=IPRuleType.CIDR_RANGE,
                action=IPAction.ALLOW,
                value="127.0.0.0/8",
                priority=1
            ),
            IPRule(
                name="block_proxies",
                rule_type=IPRuleType.PROXY,
                action=IPAction.BLOCK,
                value=True,
                priority=10
            )
        ]
        
        app = FastAPI()
        
        @app.get("/api/custom")
        @ip_geolocation_shield(rules=rules)
        def custom_endpoint():
            return {"data": "custom"}
        
        client = TestClient(app)
        
        response = client.get("/api/custom")
        assert response.status_code == 200
    
    def test_shield_with_custom_provider(self):
        """Test shield with custom geolocation provider."""
        class TestProvider(GeolocationProvider):
            async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
                return GeoLocation(ip=ip_address, country_code="TEST", is_proxy=False)
            
            async def get_location_batch(self, ip_addresses: List[str]) -> Dict[str, Optional[GeoLocation]]:
                return {ip: await self.get_location(ip) for ip in ip_addresses}
        
        app = FastAPI()
        
        @app.get("/api/test-provider")
        @ip_geolocation_shield(geolocation_provider=TestProvider())
        def test_provider_endpoint():
            return {"data": "test_provider"}
        
        client = TestClient(app)
        
        response = client.get("/api/test-provider")
        assert response.status_code == 200


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_ip_geolocation_shield_factory(self):
        """Test IP geolocation shield factory function."""
        rules = [
            IPRule(
                name="test_rule",
                rule_type=IPRuleType.SINGLE_IP,
                action=IPAction.ALLOW,
                value="127.0.0.1"
            )
        ]
        
        shield = ip_geolocation_shield(
            rules=rules,
            default_action=IPAction.BLOCK,
            enable_caching=True
        )
        assert isinstance(shield, type(ip_geolocation_shield()))
    
    def test_country_blocking_shield_factory(self):
        """Test country blocking shield factory."""
        shield = country_blocking_shield(
            blocked_countries=["CN", "RU"],
            allowed_countries=["US", "GB"]
        )
        assert isinstance(shield, type(ip_geolocation_shield()))
    
    def test_ip_whitelist_shield_factory(self):
        """Test IP whitelist shield factory."""
        shield = ip_whitelist_shield(
            allowed_ips=["127.0.0.1", "192.168.1.1"],
            allowed_cidrs=["10.0.0.0/8"]
        )
        assert isinstance(shield, type(ip_geolocation_shield()))
    
    def test_proxy_detection_shield_factory(self):
        """Test proxy detection shield factory."""
        shield = proxy_detection_shield(
            block_proxies=True,
            block_vpns=True,
            block_tor=False
        )
        assert isinstance(shield, type(ip_geolocation_shield()))


class TestIPRuleMatching:
    """Test IP rule matching edge cases."""
    
    def test_invalid_cidr_range(self):
        """Test handling of invalid CIDR ranges."""
        rule = IPRule(
            name="invalid_cidr",
            rule_type=IPRuleType.CIDR_RANGE,
            action=IPAction.BLOCK,
            value="invalid/cidr"
        )
        shield = IPGeolocationShield()
        
        # Should not match due to invalid CIDR
        assert shield._match_ip_rule(rule, "192.168.1.1", None) is False
    
    def test_invalid_ip_address(self):
        """Test handling of invalid IP addresses."""
        rule = IPRule(
            name="valid_cidr",
            rule_type=IPRuleType.CIDR_RANGE,
            action=IPAction.BLOCK,
            value="192.168.1.0/24"
        )
        shield = IPGeolocationShield()
        
        # Should not match due to invalid IP
        assert shield._match_ip_rule(rule, "invalid.ip", None) is False
    
    def test_rule_priority_ordering(self):
        """Test that rules are sorted by priority."""
        rules = [
            IPRule(name="rule_high", rule_type=IPRuleType.SINGLE_IP, action=IPAction.ALLOW, value="1.1.1.1", priority=100),
            IPRule(name="rule_low", rule_type=IPRuleType.SINGLE_IP, action=IPAction.BLOCK, value="1.1.1.1", priority=1),
            IPRule(name="rule_medium", rule_type=IPRuleType.SINGLE_IP, action=IPAction.LOG_ONLY, value="1.1.1.1", priority=50),
        ]
        
        shield = IPGeolocationShield(rules=rules)
        
        # Rules should be sorted by priority (lower number = higher priority)
        assert shield.rules[0].name == "rule_low"
        assert shield.rules[1].name == "rule_medium"
        assert shield.rules[2].name == "rule_high"
    
    def test_rule_matching_without_geo_data(self):
        """Test rule matching when geolocation data is not available."""
        rule = IPRule(
            name="country_rule",
            rule_type=IPRuleType.COUNTRY,
            action=IPAction.BLOCK,
            value=["CN"]
        )
        shield = IPGeolocationShield()
        
        # Should not match without geo data
        assert shield._match_ip_rule(rule, "1.2.3.4", None) is False


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_shield_error_handling(self):
        """Test shield error handling."""
        app = FastAPI()
        
        # Create a shield that will cause an error
        class FailingProvider(GeolocationProvider):
            async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
                raise Exception("Provider error")
            
            async def get_location_batch(self, ip_addresses: List[str]) -> Dict[str, Optional[GeoLocation]]:
                raise Exception("Provider error")
        
        @app.get("/api/error-test")
        @ip_geolocation_shield(geolocation_provider=FailingProvider())
        def error_test():
            return {"status": "ok"}
        
        client = TestClient(app)
        
        # Should handle error gracefully and allow request
        response = client.get("/api/error-test")
        assert response.status_code == 200
    
    def test_extract_ip_no_client(self):
        """Test IP extraction when no client info is available."""
        mock_request = Mock()
        mock_request.client = None
        mock_request.headers = {}
        
        shield = IPGeolocationShield()
        ip = shield._extract_client_ip(mock_request)
        assert ip == "127.0.0.1"  # Fallback
    
    def test_extract_ip_invalid_header_values(self):
        """Test IP extraction with invalid header values."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {
            "X-Forwarded-For": "invalid, malformed,, 8.8.8.8",
            "X-Real-IP": "not.an.ip"
        }
        
        shield = IPGeolocationShield(extract_real_ip=True)
        ip = shield._extract_client_ip(mock_request)
        assert ip == "8.8.8.8"  # First valid IP in X-Forwarded-For


class TestIPv6Support:
    """Test IPv6 support."""
    
    def test_ipv6_address_validation(self):
        """Test IPv6 address validation."""
        shield = IPGeolocationShield()
        
        assert shield._is_valid_ip("2001:db8::1") is True
        assert shield._is_valid_ip("::1") is True
        assert shield._is_valid_ip("2001:db8::invalid") is False
    
    def test_ipv6_cidr_matching(self):
        """Test IPv6 CIDR range matching."""
        rule = IPRule(
            name="ipv6_network",
            rule_type=IPRuleType.CIDR_RANGE,
            action=IPAction.ALLOW,
            value="2001:db8::/32"
        )
        shield = IPGeolocationShield()
        
        assert shield._match_ip_rule(rule, "2001:db8::1", None) is True
        assert shield._match_ip_rule(rule, "2001:db9::1", None) is False
    
    def test_ipv6_private_detection(self):
        """Test IPv6 private address detection."""
        shield = IPGeolocationShield()
        
        assert shield._is_private_ip("::1") is True  # Loopback
        assert shield._is_private_ip("fe80::1") is True  # Link-local
        assert shield._is_private_ip("2001:db8::1") is True  # Documentation range (marked private by Python)


if __name__ == "__main__":
    pytest.main([__file__])