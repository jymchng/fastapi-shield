"""IP geolocation shield for FastAPI Shield.

This module provides IP-based access control, geolocation restrictions,
and IP reputation filtering for FastAPI applications. Supports CIDR ranges,
country-based blocking, and proxy detection.
"""

import asyncio
import ipaddress
import json
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request, status
from pydantic import BaseModel

from fastapi_shield.shield import Shield, shield


class IPAction(str, Enum):
    """IP access control actions."""
    ALLOW = "allow"
    BLOCK = "block"
    LOG_ONLY = "log_only"


class IPRuleType(str, Enum):
    """IP rule types."""
    SINGLE_IP = "single_ip"
    CIDR_RANGE = "cidr_range"
    COUNTRY = "country"
    REGION = "region"
    ASN = "asn"
    PROXY = "proxy"
    VPN = "vpn"
    TOR = "tor"


class IPRule(BaseModel):
    """IP access control rule configuration."""
    name: str
    rule_type: IPRuleType
    action: IPAction
    value: Union[str, List[str], bool]  # IP, CIDR, country codes, boolean for proxy/vpn/tor
    description: Optional[str] = None
    priority: int = 100  # Lower number = higher priority


class GeoLocation(BaseModel):
    """Geolocation information for an IP address."""
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    region_code: Optional[str] = None
    city: Optional[str] = None
    timezone: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    threat_level: Optional[str] = None


class GeolocationProvider(ABC):
    """Abstract base class for geolocation service providers."""
    
    @abstractmethod
    async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get geolocation information for an IP address."""
        pass
    
    @abstractmethod
    async def get_location_batch(self, ip_addresses: List[str]) -> Dict[str, Optional[GeoLocation]]:
        """Get geolocation information for multiple IP addresses."""
        pass


class MockGeolocationProvider(GeolocationProvider):
    """Mock geolocation provider for testing."""
    
    def __init__(self):
        # Mock data for testing
        self.mock_data = {
            "192.168.1.1": GeoLocation(
                ip="192.168.1.1",
                country="United States",
                country_code="US",
                region="California",
                city="San Francisco",
                is_proxy=False
            ),
            "10.0.0.1": GeoLocation(
                ip="10.0.0.1",
                country="Private Network",
                country_code="XX",
                is_proxy=False
            ),
            "1.2.3.4": GeoLocation(
                ip="1.2.3.4",
                country="China",
                country_code="CN",
                region="Beijing",
                city="Beijing",
                is_proxy=True
            ),
            "5.6.7.8": GeoLocation(
                ip="5.6.7.8",
                country="Russia",
                country_code="RU",
                region="Moscow",
                city="Moscow",
                is_vpn=True
            ),
        }
    
    async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get mock geolocation data."""
        return self.mock_data.get(ip_address)
    
    async def get_location_batch(self, ip_addresses: List[str]) -> Dict[str, Optional[GeoLocation]]:
        """Get mock geolocation data for multiple IPs."""
        return {ip: self.mock_data.get(ip) for ip in ip_addresses}


class IPApiGeolocationProvider(GeolocationProvider):
    """Geolocation provider using ip-api.com service."""
    
    def __init__(self, api_key: Optional[str] = None, timeout: float = 5.0):
        self.api_key = api_key
        self.timeout = timeout
        self.base_url = "http://ip-api.com/json"
        # Free tier has rate limits, pro tier requires API key
        
    async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get geolocation from ip-api.com."""
        try:
            params = {
                "fields": "status,message,country,countryCode,region,regionName,city,timezone,lat,lon,as,proxy,hosting"
            }
            
            url = f"{self.base_url}/{ip_address}"
            if self.api_key:
                params["key"] = self.api_key
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()
                data = response.json()
                
                if data.get("status") != "success":
                    return None
                
                return GeoLocation(
                    ip=ip_address,
                    country=data.get("country"),
                    country_code=data.get("countryCode"),
                    region=data.get("regionName"),
                    region_code=data.get("region"),
                    city=data.get("city"),
                    timezone=data.get("timezone"),
                    latitude=data.get("lat"),
                    longitude=data.get("lon"),
                    asn=int(data.get("as", "").split(" ")[0].replace("AS", "")) if data.get("as") and data.get("as").split(" ")[0].replace("AS", "").isdigit() else None,
                    asn_org=" ".join(data.get("as", "").split(" ")[1:]) if data.get("as") else None,
                    is_proxy=data.get("proxy", False),
                    is_hosting=data.get("hosting", False),
                )
        except Exception:
            # Return None on any error to avoid breaking the request
            return None
    
    async def get_location_batch(self, ip_addresses: List[str]) -> Dict[str, Optional[GeoLocation]]:
        """Get geolocation for multiple IPs (sequential for free tier)."""
        results = {}
        for ip in ip_addresses:
            results[ip] = await self.get_location(ip)
            # Add small delay to respect rate limits
            await asyncio.sleep(0.1)
        return results


class MaxMindGeolocationProvider(GeolocationProvider):
    """Geolocation provider using MaxMind GeoLite2/GeoIP2 databases."""
    
    def __init__(self, database_path: Optional[str] = None):
        self.database_path = database_path
        self._geoip_reader = None
        
        # Try to import maxminddb (optional dependency)
        try:
            import maxminddb
            self.maxminddb = maxminddb
            if database_path:
                self._geoip_reader = maxminddb.open_database(database_path)
        except ImportError:
            self.maxminddb = None
    
    async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get geolocation from MaxMind database."""
        if not self._geoip_reader:
            return None
        
        try:
            data = self._geoip_reader.get(ip_address)
            if not data:
                return None
            
            country = data.get("country", {})
            subdivisions = data.get("subdivisions", [{}])
            city_data = data.get("city", {})
            location = data.get("location", {})
            
            return GeoLocation(
                ip=ip_address,
                country=country.get("names", {}).get("en"),
                country_code=country.get("iso_code"),
                region=subdivisions[0].get("names", {}).get("en") if subdivisions else None,
                region_code=subdivisions[0].get("iso_code") if subdivisions else None,
                city=city_data.get("names", {}).get("en"),
                timezone=location.get("time_zone"),
                latitude=location.get("latitude"),
                longitude=location.get("longitude"),
            )
        except Exception:
            return None
    
    async def get_location_batch(self, ip_addresses: List[str]) -> Dict[str, Optional[GeoLocation]]:
        """Get geolocation for multiple IPs from MaxMind database."""
        results = {}
        for ip in ip_addresses:
            results[ip] = await self.get_location(ip)
        return results


class IPGeolocationShield:
    """IP geolocation and access control shield."""
    
    def __init__(
        self,
        rules: List[IPRule] = None,
        geolocation_provider: Optional[GeolocationProvider] = None,
        default_action: IPAction = IPAction.ALLOW,
        enable_caching: bool = True,
        cache_ttl: int = 3600,  # 1 hour
        trusted_proxies: Optional[List[str]] = None,
        extract_real_ip: bool = True,
        log_decisions: bool = True,
    ):
        """Initialize IP geolocation shield.
        
        Args:
            rules: List of IP access control rules
            geolocation_provider: Service provider for IP geolocation
            default_action: Default action when no rules match
            enable_caching: Enable caching of geolocation lookups
            cache_ttl: Cache time-to-live in seconds
            trusted_proxies: List of trusted proxy IP ranges
            extract_real_ip: Extract real IP from proxy headers
            log_decisions: Log access control decisions
        """
        self.rules = sorted(rules or [], key=lambda r: r.priority)
        self.geolocation_provider = geolocation_provider or MockGeolocationProvider()
        self.default_action = default_action
        self.enable_caching = enable_caching
        self.cache_ttl = cache_ttl
        self.trusted_proxies = self._parse_trusted_proxies(trusted_proxies or [])
        self.extract_real_ip = extract_real_ip
        self.log_decisions = log_decisions
        
        # Simple in-memory cache
        self._geo_cache: Dict[str, tuple[GeoLocation, float]] = {}
        
    def _parse_trusted_proxies(self, proxy_list: List[str]) -> List[ipaddress.IPv4Network]:
        """Parse trusted proxy CIDR ranges."""
        networks = []
        for proxy in proxy_list:
            try:
                networks.append(ipaddress.ip_network(proxy, strict=False))
            except ValueError:
                continue
        return networks
    
    def _extract_client_ip(self, request: Request) -> str:
        """Extract the real client IP address from the request."""
        if not self.extract_real_ip:
            return request.client.host if request.client else "127.0.0.1"
        
        # Common headers used by proxies and load balancers
        headers_to_check = [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",  # Cloudflare
            "X-Client-IP",
            "X-Forwarded",
            "Forwarded-For",
            "Forwarded",
        ]
        
        # Check headers in order of preference
        for header in headers_to_check:
            value = request.headers.get(header)
            if value:
                # X-Forwarded-For can contain multiple IPs
                if header == "X-Forwarded-For":
                    # Take the first non-private IP (leftmost public IP = original client)
                    ips = [ip.strip() for ip in value.split(",")]
                    for ip in ips:
                        if self._is_valid_ip(ip) and not self._is_true_private_ip(ip):
                            return ip
                else:
                    if self._is_valid_ip(value):
                        return value
        
        # Fallback to direct connection IP
        return request.client.host if request.client else "127.0.0.1"
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is in private ranges (including reserved/documentation ranges)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.version == 4:
                return (
                    ip.is_private or 
                    ip.is_loopback or 
                    ip.is_link_local or
                    ip.is_reserved
                )
            else:  # IPv6
                return (
                    ip.is_private or 
                    ip.is_loopback or 
                    ip.is_link_local or
                    ip.is_reserved or
                    str(ip).startswith('2001:db8:')  # Documentation range
                )
        except ValueError:
            return False
    
    def _is_true_private_ip(self, ip_str: str) -> bool:
        """Check if IP is in true private ranges (RFC 1918, not documentation ranges)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.version == 4:
                return (
                    ip.is_private or 
                    ip.is_loopback or 
                    ip.is_link_local
                )
            else:  # IPv6
                return (
                    ip.is_private or 
                    ip.is_loopback or 
                    ip.is_link_local
                )
        except ValueError:
            return False
    
    def _is_ip_in_trusted_proxies(self, ip_str: str) -> bool:
        """Check if IP is in trusted proxy ranges."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.trusted_proxies:
                if ip in network:
                    return True
        except ValueError:
            pass
        return False
    
    async def _get_cached_geolocation(self, ip_address: str) -> Optional[GeoLocation]:
        """Get geolocation from cache or provider."""
        if self.enable_caching and ip_address in self._geo_cache:
            geo_data, timestamp = self._geo_cache[ip_address]
            import time
            if time.time() - timestamp < self.cache_ttl:
                return geo_data
            else:
                # Remove expired entry
                del self._geo_cache[ip_address]
        
        # Get from provider
        try:
            geo_data = await self.geolocation_provider.get_location(ip_address)
            
            # Cache the result
            if self.enable_caching and geo_data:
                import time
                self._geo_cache[ip_address] = (geo_data, time.time())
            
            return geo_data
        except Exception:
            # Return None on provider error to avoid breaking requests
            return None
    
    def _match_ip_rule(self, rule: IPRule, ip_address: str, geo_data: Optional[GeoLocation]) -> bool:
        """Check if an IP rule matches the given IP and geolocation data."""
        try:
            if rule.rule_type == IPRuleType.SINGLE_IP:
                return ip_address == rule.value
            
            elif rule.rule_type == IPRuleType.CIDR_RANGE:
                try:
                    ip = ipaddress.ip_address(ip_address)
                    if isinstance(rule.value, list):
                        return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in rule.value)
                    else:
                        return ip in ipaddress.ip_network(rule.value, strict=False)
                except (ValueError, ipaddress.AddressValueError):
                    return False
            
            elif rule.rule_type == IPRuleType.COUNTRY and geo_data:
                if isinstance(rule.value, list):
                    return geo_data.country_code in rule.value
                else:
                    return geo_data.country_code == rule.value
            
            elif rule.rule_type == IPRuleType.REGION and geo_data:
                if isinstance(rule.value, list):
                    return geo_data.region_code in rule.value or geo_data.region in rule.value
                else:
                    return geo_data.region_code == rule.value or geo_data.region == rule.value
            
            elif rule.rule_type == IPRuleType.ASN and geo_data:
                if isinstance(rule.value, list):
                    return str(geo_data.asn) in rule.value
                else:
                    return str(geo_data.asn) == rule.value
            
            elif rule.rule_type == IPRuleType.PROXY and geo_data:
                return geo_data.is_proxy and rule.value is True
            
            elif rule.rule_type == IPRuleType.VPN and geo_data:
                return geo_data.is_vpn and rule.value is True
            
            elif rule.rule_type == IPRuleType.TOR and geo_data:
                return geo_data.is_tor and rule.value is True
            
        except Exception:
            # On any error, rule doesn't match
            pass
        
        return False
    
    async def _evaluate_ip_access(self, ip_address: str) -> tuple[IPAction, str, Optional[GeoLocation]]:
        """Evaluate IP access based on rules and return action, reason, and geo data."""
        # Get geolocation data
        geo_data = await self._get_cached_geolocation(ip_address)
        
        # Check rules in priority order
        for rule in self.rules:
            if self._match_ip_rule(rule, ip_address, geo_data):
                reason = f"Matched rule: {rule.name} ({rule.description or rule.rule_type.value})"
                return rule.action, reason, geo_data
        
        # No rules matched, use default action
        reason = f"No rules matched, using default action: {self.default_action.value}"
        return self.default_action, reason, geo_data
    
    def create_shield(self, name: str = "IPGeolocation") -> Shield:
        """Create a shield instance for IP geolocation access control."""
        
        async def ip_geolocation_shield(request: Request) -> Optional[Dict[str, Any]]:
            """IP geolocation shield function."""
            try:
                # Extract client IP
                client_ip = self._extract_client_ip(request)
                
                # Evaluate IP access
                action, reason, geo_data = await self._evaluate_ip_access(client_ip)
                
                # Log decision if enabled
                if self.log_decisions:
                    # In a real implementation, use proper logging
                    pass
                
                # Handle action
                if action == IPAction.BLOCK:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Access denied from IP {client_ip}: {reason}",
                        headers={"X-Blocked-IP": client_ip}
                    )
                
                # For ALLOW and LOG_ONLY, let request proceed
                return {
                    "client_ip": client_ip,
                    "action": action.value,
                    "reason": reason,
                    "geolocation": geo_data.model_dump() if geo_data else None,
                }
                
            except HTTPException:
                raise
            except Exception as e:
                # On any error, log and allow by default for safety
                return {
                    "error": str(e),
                    "action": "allow_on_error",
                    "client_ip": getattr(request, 'client', {}).get('host', 'unknown')
                }
        
        return shield(
            ip_geolocation_shield,
            name=name,
            auto_error=True,
        )


# Convenience functions for common IP geolocation scenarios
def ip_geolocation_shield(
    rules: Optional[List[IPRule]] = None,
    geolocation_provider: Optional[GeolocationProvider] = None,
    default_action: IPAction = IPAction.ALLOW,
    enable_caching: bool = True,
    trusted_proxies: Optional[List[str]] = None,
    name: str = "IPGeolocation",
) -> Shield:
    """Create an IP geolocation shield with specified configuration.
    
    Args:
        rules: List of IP access control rules
        geolocation_provider: Geolocation service provider
        default_action: Default action when no rules match
        enable_caching: Enable geolocation caching
        trusted_proxies: Trusted proxy CIDR ranges
        name: Shield name
        
    Returns:
        Shield: Configured IP geolocation shield
        
    Examples:
        ```python
        # Block specific countries
        rules = [
            IPRule(
                name="block_malicious_countries",
                rule_type=IPRuleType.COUNTRY,
                action=IPAction.BLOCK,
                value=["CN", "RU", "KP"],
                description="Block high-risk countries"
            )
        ]
        
        @app.get("/api/secure")
        @ip_geolocation_shield(rules=rules)
        def secure_endpoint():
            return {"status": "accessible"}
        
        # Block proxy/VPN traffic
        proxy_rules = [
            IPRule(
                name="block_proxies",
                rule_type=IPRuleType.PROXY,
                action=IPAction.BLOCK,
                value=True,
                description="Block proxy traffic"
            ),
            IPRule(
                name="block_vpns",
                rule_type=IPRuleType.VPN,
                action=IPAction.BLOCK,
                value=True,
                description="Block VPN traffic"
            )
        ]
        
        @app.post("/api/payment")
        @ip_geolocation_shield(rules=proxy_rules)
        def payment_endpoint():
            return {"status": "payment_processed"}
        ```
    """
    geo_shield = IPGeolocationShield(
        rules=rules,
        geolocation_provider=geolocation_provider,
        default_action=default_action,
        enable_caching=enable_caching,
        trusted_proxies=trusted_proxies,
    )
    return geo_shield.create_shield(name=name)


def country_blocking_shield(
    blocked_countries: List[str],
    allowed_countries: Optional[List[str]] = None,
    geolocation_provider: Optional[GeolocationProvider] = None,
    name: str = "CountryBlocking",
) -> Shield:
    """Create a shield that blocks specific countries.
    
    Args:
        blocked_countries: List of country codes to block (e.g., ["CN", "RU"])
        allowed_countries: List of country codes to explicitly allow (overrides blocks)
        geolocation_provider: Geolocation service provider
        name: Shield name
        
    Returns:
        Shield: Country blocking shield
    """
    rules = []
    
    # Add allow rules first (higher priority)
    if allowed_countries:
        rules.append(IPRule(
            name="allow_countries",
            rule_type=IPRuleType.COUNTRY,
            action=IPAction.ALLOW,
            value=allowed_countries,
            priority=10,
            description=f"Allow countries: {', '.join(allowed_countries)}"
        ))
    
    # Add block rules
    if blocked_countries:
        rules.append(IPRule(
            name="block_countries",
            rule_type=IPRuleType.COUNTRY,
            action=IPAction.BLOCK,
            value=blocked_countries,
            priority=20,
            description=f"Block countries: {', '.join(blocked_countries)}"
        ))
    
    return ip_geolocation_shield(
        rules=rules,
        geolocation_provider=geolocation_provider,
        name=name,
    )


def ip_whitelist_shield(
    allowed_ips: List[str],
    allowed_cidrs: Optional[List[str]] = None,
    name: str = "IPWhitelist",
) -> Shield:
    """Create a shield that only allows specific IPs/ranges.
    
    Args:
        allowed_ips: List of specific IP addresses to allow
        allowed_cidrs: List of CIDR ranges to allow
        name: Shield name
        
    Returns:
        Shield: IP whitelist shield
    """
    rules = []
    
    # Add allow rules for specific IPs
    if allowed_ips:
        for ip in allowed_ips:
            rules.append(IPRule(
                name=f"allow_ip_{ip}",
                rule_type=IPRuleType.SINGLE_IP,
                action=IPAction.ALLOW,
                value=ip,
                priority=10,
                description=f"Allow IP: {ip}"
            ))
    
    # Add allow rules for CIDR ranges
    if allowed_cidrs:
        rules.append(IPRule(
            name="allow_cidr_ranges",
            rule_type=IPRuleType.CIDR_RANGE,
            action=IPAction.ALLOW,
            value=allowed_cidrs,
            priority=10,
            description=f"Allow CIDR ranges: {', '.join(allowed_cidrs)}"
        ))
    
    return ip_geolocation_shield(
        rules=rules,
        default_action=IPAction.BLOCK,  # Block everything not explicitly allowed
        name=name,
    )


def proxy_detection_shield(
    block_proxies: bool = True,
    block_vpns: bool = True,
    block_tor: bool = True,
    geolocation_provider: Optional[GeolocationProvider] = None,
    name: str = "ProxyDetection",
) -> Shield:
    """Create a shield that detects and blocks proxy traffic.
    
    Args:
        block_proxies: Block HTTP/HTTPS proxies
        block_vpns: Block VPN traffic
        block_tor: Block Tor exit nodes
        geolocation_provider: Geolocation service provider
        name: Shield name
        
    Returns:
        Shield: Proxy detection shield
    """
    rules = []
    
    if block_proxies:
        rules.append(IPRule(
            name="block_proxies",
            rule_type=IPRuleType.PROXY,
            action=IPAction.BLOCK,
            value=True,
            description="Block HTTP/HTTPS proxy traffic"
        ))
    
    if block_vpns:
        rules.append(IPRule(
            name="block_vpns",
            rule_type=IPRuleType.VPN,
            action=IPAction.BLOCK,
            value=True,
            description="Block VPN traffic"
        ))
    
    if block_tor:
        rules.append(IPRule(
            name="block_tor",
            rule_type=IPRuleType.TOR,
            action=IPAction.BLOCK,
            value=True,
            description="Block Tor exit node traffic"
        ))
    
    return ip_geolocation_shield(
        rules=rules,
        geolocation_provider=geolocation_provider,
        name=name,
    )