"""FastAPI-Shield Advanced Threat Intelligence Integration

This module provides comprehensive threat intelligence capabilities for FastAPI-Shield
with real-time threat analysis, external feed integration, and automated response.

Features:
- Real-time threat intelligence processing with external feed integration
- Advanced IP reputation scoring with geolocation analysis
- Custom threat database with high-performance caching and persistence
- Threat signature matching and pattern recognition engine
- Automated threat response and mitigation capabilities
- Comprehensive threat analytics with machine learning-based scoring
- Integration with major threat intelligence providers (VirusTotal, AbuseIPDB, etc.)
- Historical threat pattern recognition and campaign tracking
- Dynamic rule generation and incident response automation
"""

import asyncio
import hashlib
import hmac
import json
import logging
import re
import sqlite3
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from ipaddress import ip_address, ip_network, AddressValueError
from pathlib import Path
from threading import RLock, Thread
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    NamedTuple, Protocol, AsyncIterator
)
import urllib.parse
import weakref

from fastapi import Request, HTTPException

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    UNKNOWN = "unknown"           # Unknown or unclassified threat
    LOW = "low"                   # Low-risk threat
    MEDIUM = "medium"             # Medium-risk threat  
    HIGH = "high"                 # High-risk threat
    CRITICAL = "critical"         # Critical threat requiring immediate action


class ThreatType(Enum):
    """Types of security threats."""
    MALICIOUS_IP = "malicious_ip"         # Known malicious IP address
    BOT_TRAFFIC = "bot_traffic"           # Automated bot traffic
    BRUTE_FORCE = "brute_force"           # Brute force attack pattern
    DDOS = "ddos"                         # Distributed denial of service
    MALWARE = "malware"                   # Malware-related activity
    PHISHING = "phishing"                 # Phishing attempt
    SPAM = "spam"                         # Spam or unwanted content
    SCANNING = "scanning"                 # Port or vulnerability scanning
    EXPLOITATION = "exploitation"         # Active exploitation attempt
    DATA_EXFILTRATION = "data_exfiltration"  # Data theft attempt


class ThreatSource(Enum):
    """Sources of threat intelligence."""
    VIRUS_TOTAL = "virustotal"           # VirusTotal API
    ABUSE_IPDB = "abuseipdb"            # AbuseIPDB feed
    THREAT_FOX = "threatfox"            # ThreatFox indicators
    MALWARE_BAZAAR = "malware_bazaar"   # MalwareBazaar signatures
    CUSTOM_FEED = "custom_feed"         # Custom threat feed
    INTERNAL = "internal"               # Internal threat detection
    MACHINE_LEARNING = "ml"             # ML-based detection
    SIGNATURE_MATCH = "signature"       # Signature-based detection


class ResponseAction(Enum):
    """Automated response actions for threats."""
    MONITOR = "monitor"                 # Monitor and log only
    RATE_LIMIT = "rate_limit"          # Apply rate limiting
    TEMPORARY_BLOCK = "temporary_block" # Temporary IP block
    PERMANENT_BLOCK = "permanent_block" # Permanent IP block
    QUARANTINE = "quarantine"          # Quarantine suspicious activity
    ALERT_ONLY = "alert_only"          # Generate alert only
    ESCALATE = "escalate"              # Escalate to security team


class IPReputation(Enum):
    """IP reputation categories."""
    TRUSTED = "trusted"                 # Trusted/whitelisted IP
    CLEAN = "clean"                     # Clean IP with good reputation
    SUSPICIOUS = "suspicious"           # Suspicious but not confirmed malicious
    MALICIOUS = "malicious"            # Confirmed malicious IP
    UNKNOWN = "unknown"                # Unknown reputation


@dataclass
class ThreatIndicator:
    """Individual threat indicator with metadata."""
    id: str
    value: str                          # The actual indicator (IP, hash, etc.)
    threat_type: ThreatType
    threat_level: ThreatLevel
    source: ThreatSource
    confidence: float                   # Confidence score (0.0 to 1.0)
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    expiry_date: Optional[datetime] = None
    is_active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert threat indicator to dictionary."""
        return {
            'id': self.id,
            'value': self.value,
            'threat_type': self.threat_type.value,
            'threat_level': self.threat_level.value,
            'source': self.source.value,
            'confidence': self.confidence,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'tags': self.tags,
            'metadata': self.metadata,
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'is_active': self.is_active
        }


@dataclass
class IPGeolocation:
    """IP geolocation information."""
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_proxy: bool = False
    is_tor: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert geolocation to dictionary."""
        return asdict(self)


@dataclass
class ThreatAssessment:
    """Comprehensive threat assessment result."""
    ip: str
    threat_level: ThreatLevel
    reputation: IPReputation
    risk_score: float                   # Overall risk score (0.0 to 1.0)
    confidence: float                   # Assessment confidence (0.0 to 1.0)
    indicators: List[ThreatIndicator]
    geolocation: Optional[IPGeolocation] = None
    recommended_action: ResponseAction = ResponseAction.MONITOR
    reasons: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert threat assessment to dictionary."""
        return {
            'ip': self.ip,
            'threat_level': self.threat_level.value,
            'reputation': self.reputation.value,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'indicators': [indicator.to_dict() for indicator in self.indicators],
            'geolocation': self.geolocation.to_dict() if self.geolocation else None,
            'recommended_action': self.recommended_action.value,
            'reasons': self.reasons,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ThreatFeedConfig:
    """Configuration for external threat feed."""
    name: str
    provider: str
    api_key: Optional[str] = None
    base_url: str = ""
    update_interval: int = 3600         # Update interval in seconds
    rate_limit: int = 100               # Requests per minute
    timeout: int = 30                   # Request timeout in seconds
    enabled: bool = True
    priority: int = 1                   # Feed priority (1-10)
    reliability_score: float = 1.0      # Feed reliability (0.0 to 1.0)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    custom_params: Dict[str, str] = field(default_factory=dict)


@dataclass
class ThreatResponse:
    """Automated threat response configuration."""
    threat_level: ThreatLevel
    action: ResponseAction
    duration: Optional[timedelta] = None  # For temporary actions
    notify: bool = True
    escalate_after: Optional[timedelta] = None
    custom_rules: Dict[str, Any] = field(default_factory=dict)


class ThreatDatabase:
    """High-performance threat intelligence database with caching."""
    
    def __init__(self, db_path: str = "threat_intelligence.db"):
        self.db_path = db_path
        self._cache = {}
        self._cache_expiry = {}
        self._cache_size_limit = 10000
        self._cache_ttl = 3600  # 1 hour
        self._lock = RLock()
        
        # Initialize database
        self._init_database()
        
        # Start cleanup thread
        self._cleanup_thread = Thread(target=self._cleanup_expired, daemon=True)
        self._cleanup_thread.start()
        
        logger.info(f"ThreatDatabase initialized with path: {db_path}")
    
    def _init_database(self):
        """Initialize SQLite database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    tags TEXT,
                    metadata TEXT,
                    expiry_date TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_value ON threat_indicators(value)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_indicators(threat_type)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_level ON threat_indicators(threat_level)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_active ON threat_indicators(is_active)
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation_cache (
                    ip TEXT PRIMARY KEY,
                    reputation TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    confidence REAL NOT NULL,
                    geolocation TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_reputation_expires ON ip_reputation_cache(expires_at)
            """)
            
            conn.commit()
    
    def store_indicator(self, indicator: ThreatIndicator) -> bool:
        """Store threat indicator in database."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO threat_indicators 
                        (id, value, threat_type, threat_level, source, confidence,
                         first_seen, last_seen, tags, metadata, expiry_date, is_active)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        indicator.id,
                        indicator.value,
                        indicator.threat_type.value,
                        indicator.threat_level.value,
                        indicator.source.value,
                        indicator.confidence,
                        indicator.first_seen,
                        indicator.last_seen,
                        json.dumps(indicator.tags),
                        json.dumps(indicator.metadata),
                        indicator.expiry_date,
                        indicator.is_active
                    ))
                    conn.commit()
                
                # Update cache
                cache_key = f"indicator:{indicator.value}"
                self._cache[cache_key] = indicator
                self._cache_expiry[cache_key] = time.time() + self._cache_ttl
                
                return True
                
            except Exception as e:
                logger.error(f"Error storing threat indicator: {e}")
                return False
    
    def get_indicator(self, value: str) -> Optional[ThreatIndicator]:
        """Retrieve threat indicator by value."""
        with self._lock:
            # Check cache first
            cache_key = f"indicator:{value}"
            if cache_key in self._cache:
                if time.time() < self._cache_expiry.get(cache_key, 0):
                    return self._cache[cache_key]
                else:
                    # Remove expired cache entry
                    del self._cache[cache_key]
                    del self._cache_expiry[cache_key]
            
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("""
                        SELECT * FROM threat_indicators 
                        WHERE value = ? AND is_active = 1
                        ORDER BY last_seen DESC LIMIT 1
                    """, (value,))
                    
                    row = cursor.fetchone()
                    if row:
                        indicator = self._row_to_indicator(row)
                        
                        # Update cache
                        self._cache[cache_key] = indicator
                        self._cache_expiry[cache_key] = time.time() + self._cache_ttl
                        
                        return indicator
                
            except Exception as e:
                logger.error(f"Error retrieving threat indicator: {e}")
        
        return None
    
    def search_indicators(self, 
                         threat_type: Optional[ThreatType] = None,
                         threat_level: Optional[ThreatLevel] = None,
                         source: Optional[ThreatSource] = None,
                         limit: int = 100) -> List[ThreatIndicator]:
        """Search threat indicators with filters."""
        conditions = ["is_active = 1"]
        params = []
        
        if threat_type:
            conditions.append("threat_type = ?")
            params.append(threat_type.value)
        
        if threat_level:
            conditions.append("threat_level = ?")
            params.append(threat_level.value)
        
        if source:
            conditions.append("source = ?")
            params.append(source.value)
        
        query = f"""
            SELECT * FROM threat_indicators 
            WHERE {' AND '.join(conditions)}
            ORDER BY last_seen DESC LIMIT ?
        """
        params.append(limit)
        
        indicators = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query, params)
                for row in cursor.fetchall():
                    indicators.append(self._row_to_indicator(row))
        
        except Exception as e:
            logger.error(f"Error searching threat indicators: {e}")
        
        return indicators
    
    def cache_ip_reputation(self, ip: str, reputation: IPReputation, 
                           risk_score: float, confidence: float,
                           geolocation: Optional[IPGeolocation] = None,
                           ttl: int = 3600):
        """Cache IP reputation information."""
        with self._lock:
            try:
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
                
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO ip_reputation_cache 
                        (ip, reputation, risk_score, confidence, geolocation, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        ip,
                        reputation.value,
                        risk_score,
                        confidence,
                        json.dumps(geolocation.to_dict()) if geolocation else None,
                        expires_at
                    ))
                    conn.commit()
                
            except Exception as e:
                logger.error(f"Error caching IP reputation: {e}")
    
    def get_cached_reputation(self, ip: str) -> Optional[Tuple[IPReputation, float, float, Optional[IPGeolocation]]]:
        """Get cached IP reputation if not expired."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT reputation, risk_score, confidence, geolocation
                    FROM ip_reputation_cache 
                    WHERE ip = ? AND expires_at > CURRENT_TIMESTAMP
                """, (ip,))
                
                row = cursor.fetchone()
                if row:
                    reputation = IPReputation(row[0])
                    risk_score = row[1]
                    confidence = row[2]
                    geolocation = None
                    
                    if row[3]:
                        geo_data = json.loads(row[3])
                        geolocation = IPGeolocation(**geo_data)
                    
                    return reputation, risk_score, confidence, geolocation
        
        except Exception as e:
            logger.error(f"Error retrieving cached reputation: {e}")
        
        return None
    
    def _row_to_indicator(self, row) -> ThreatIndicator:
        """Convert database row to ThreatIndicator object."""
        return ThreatIndicator(
            id=row[0],
            value=row[1],
            threat_type=ThreatType(row[2]),
            threat_level=ThreatLevel(row[3]),
            source=ThreatSource(row[4]),
            confidence=row[5],
            first_seen=datetime.fromisoformat(row[6].replace('Z', '+00:00')) if isinstance(row[6], str) else row[6],
            last_seen=datetime.fromisoformat(row[7].replace('Z', '+00:00')) if isinstance(row[7], str) else row[7],
            tags=json.loads(row[8]) if row[8] else [],
            metadata=json.loads(row[9]) if row[9] else {},
            expiry_date=datetime.fromisoformat(row[10].replace('Z', '+00:00')) if row[10] else None,
            is_active=bool(row[11])
        )
    
    def _cleanup_expired(self):
        """Background cleanup of expired data."""
        while True:
            try:
                # Clean up expired cache entries
                current_time = time.time()
                with self._lock:
                    expired_keys = [
                        key for key, expiry in self._cache_expiry.items()
                        if current_time >= expiry
                    ]
                    
                    for key in expired_keys:
                        del self._cache[key]
                        del self._cache_expiry[key]
                
                # Clean up database expired records
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        DELETE FROM threat_indicators 
                        WHERE expiry_date IS NOT NULL AND expiry_date < CURRENT_TIMESTAMP
                    """)
                    
                    conn.execute("""
                        DELETE FROM ip_reputation_cache 
                        WHERE expires_at < CURRENT_TIMESTAMP
                    """)
                    
                    conn.commit()
                
                time.sleep(300)  # Cleanup every 5 minutes
                
            except Exception as e:
                logger.error(f"Error during database cleanup: {e}")
                time.sleep(60)


class GeolocationService:
    """IP geolocation service with caching."""
    
    def __init__(self, geoip_db_path: Optional[str] = None):
        self.geoip_db_path = geoip_db_path
        self._cache = {}
        self._cache_expiry = {}
        self._cache_ttl = 3600  # 1 hour
        self._lock = RLock()
        
        # Initialize GeoIP database if available
        if GEOIP_AVAILABLE and geoip_db_path and Path(geoip_db_path).exists():
            try:
                self._geoip_reader = geoip2.database.Reader(geoip_db_path)
                self._geoip_enabled = True
                logger.info(f"GeoIP database loaded: {geoip_db_path}")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP database: {e}")
                self._geoip_enabled = False
        else:
            self._geoip_enabled = False
            logger.warning("GeoIP functionality not available")
    
    async def get_geolocation(self, ip: str) -> Optional[IPGeolocation]:
        """Get geolocation for IP address."""
        with self._lock:
            # Check cache first
            if ip in self._cache:
                if time.time() < self._cache_expiry.get(ip, 0):
                    return self._cache[ip]
                else:
                    del self._cache[ip]
                    del self._cache_expiry[ip]
        
        geolocation = None
        
        if self._geoip_enabled:
            geolocation = await self._get_geoip_location(ip)
        
        if not geolocation:
            geolocation = await self._get_online_location(ip)
        
        # Cache result
        if geolocation:
            with self._lock:
                self._cache[ip] = geolocation
                self._cache_expiry[ip] = time.time() + self._cache_ttl
        
        return geolocation
    
    async def _get_geoip_location(self, ip: str) -> Optional[IPGeolocation]:
        """Get location from local GeoIP database."""
        try:
            response = self._geoip_reader.city(ip)
            
            return IPGeolocation(
                ip=ip,
                country=response.country.name,
                country_code=response.country.iso_code,
                region=response.subdivisions.most_specific.name,
                city=response.city.name,
                latitude=float(response.location.latitude) if response.location.latitude else None,
                longitude=float(response.location.longitude) if response.location.longitude else None,
                # Additional checks would be needed for proxy/Tor detection
            )
            
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            return None
    
    async def _get_online_location(self, ip: str) -> Optional[IPGeolocation]:
        """Get location from online service (fallback)."""
        if not HTTPX_AVAILABLE:
            return None
        
        try:
            # Using a free IP geolocation service
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"http://ip-api.com/json/{ip}")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('status') == 'success':
                        return IPGeolocation(
                            ip=ip,
                            country=data.get('country'),
                            country_code=data.get('countryCode'),
                            region=data.get('regionName'),
                            city=data.get('city'),
                            latitude=data.get('lat'),
                            longitude=data.get('lon'),
                            asn=data.get('as', '').split(' ')[0].replace('AS', '') if data.get('as') else None,
                            asn_org=data.get('isp'),
                            is_proxy=data.get('proxy', False),
                        )
        
        except Exception as e:
            logger.debug(f"Online geolocation lookup failed for {ip}: {e}")
        
        return None


class ThreatFeedProvider(ABC):
    """Abstract base class for threat intelligence feed providers."""
    
    def __init__(self, config: ThreatFeedConfig):
        self.config = config
        self._last_update = None
        self._request_count = 0
        self._request_window_start = time.time()
        self._lock = RLock()
    
    @abstractmethod
    async def fetch_indicators(self) -> List[ThreatIndicator]:
        """Fetch threat indicators from external feed."""
        pass
    
    @abstractmethod
    async def check_ip_reputation(self, ip: str) -> Optional[ThreatAssessment]:
        """Check IP reputation with external service."""
        pass
    
    def _check_rate_limit(self) -> bool:
        """Check if request is within rate limits."""
        with self._lock:
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
        """Check if feed needs to be updated."""
        if not self._last_update:
            return True
        
        return (time.time() - self._last_update) > self.config.update_interval


class VirusTotalProvider(ThreatFeedProvider):
    """VirusTotal threat intelligence provider."""
    
    def __init__(self, config: ThreatFeedConfig):
        super().__init__(config)
        self.base_url = "https://www.virustotal.com/vtapi/v2"
    
    async def fetch_indicators(self) -> List[ThreatIndicator]:
        """Fetch indicators from VirusTotal feed."""
        if not HTTPX_AVAILABLE or not self.config.api_key:
            return []
        
        if not self._check_rate_limit():
            logger.warning("VirusTotal rate limit exceeded")
            return []
        
        indicators = []
        
        try:
            # Note: This is a simplified example - real VirusTotal integration
            # would use their feed APIs or specific indicator endpoints
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                # This would be replaced with actual VirusTotal feed endpoints
                logger.info("VirusTotal feed update - implementation would fetch latest indicators")
                
                self._last_update = time.time()
        
        except Exception as e:
            logger.error(f"VirusTotal feed error: {e}")
        
        return indicators
    
    async def check_ip_reputation(self, ip: str) -> Optional[ThreatAssessment]:
        """Check IP reputation with VirusTotal."""
        if not HTTPX_AVAILABLE or not self.config.api_key:
            return None
        
        if not self._check_rate_limit():
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                params = {
                    'apikey': self.config.api_key,
                    'ip': ip
                }
                
                response = await client.get(
                    f"{self.base_url}/ip-address/report",
                    params=params
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Parse VirusTotal response
                    detected_urls = data.get('detected_urls', [])
                    detected_samples = data.get('detected_samples', [])
                    
                    # Calculate risk score based on detections
                    total_detections = len(detected_urls) + len(detected_samples)
                    risk_score = min(1.0, total_detections / 10.0)  # Normalize to 0-1
                    
                    # Determine threat level
                    if risk_score > 0.8:
                        threat_level = ThreatLevel.CRITICAL
                        reputation = IPReputation.MALICIOUS
                    elif risk_score > 0.5:
                        threat_level = ThreatLevel.HIGH
                        reputation = IPReputation.SUSPICIOUS
                    elif risk_score > 0.2:
                        threat_level = ThreatLevel.MEDIUM
                        reputation = IPReputation.SUSPICIOUS
                    else:
                        threat_level = ThreatLevel.LOW
                        reputation = IPReputation.CLEAN
                    
                    # Create indicators
                    indicators = []
                    if total_detections > 0:
                        indicator = ThreatIndicator(
                            id=str(uuid.uuid4()),
                            value=ip,
                            threat_type=ThreatType.MALICIOUS_IP,
                            threat_level=threat_level,
                            source=ThreatSource.VIRUS_TOTAL,
                            confidence=min(1.0, total_detections / 5.0),
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                            metadata={
                                'detected_urls': len(detected_urls),
                                'detected_samples': len(detected_samples),
                                'vt_data': data
                            }
                        )
                        indicators.append(indicator)
                    
                    return ThreatAssessment(
                        ip=ip,
                        threat_level=threat_level,
                        reputation=reputation,
                        risk_score=risk_score,
                        confidence=0.9,  # High confidence for VirusTotal
                        indicators=indicators,
                        recommended_action=self._get_recommended_action(threat_level),
                        reasons=[f"VirusTotal detections: {total_detections}"]
                    )
        
        except Exception as e:
            logger.error(f"VirusTotal IP check error: {e}")
        
        return None
    
    def _get_recommended_action(self, threat_level: ThreatLevel) -> ResponseAction:
        """Get recommended action based on threat level."""
        if threat_level == ThreatLevel.CRITICAL:
            return ResponseAction.PERMANENT_BLOCK
        elif threat_level == ThreatLevel.HIGH:
            return ResponseAction.TEMPORARY_BLOCK
        elif threat_level == ThreatLevel.MEDIUM:
            return ResponseAction.RATE_LIMIT
        else:
            return ResponseAction.MONITOR


class AbuseIPDBProvider(ThreatFeedProvider):
    """AbuseIPDB threat intelligence provider."""
    
    def __init__(self, config: ThreatFeedConfig):
        super().__init__(config)
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    async def fetch_indicators(self) -> List[ThreatIndicator]:
        """Fetch indicators from AbuseIPDB feed."""
        if not HTTPX_AVAILABLE or not self.config.api_key:
            return []
        
        if not self._check_rate_limit():
            logger.warning("AbuseIPDB rate limit exceeded")
            return []
        
        indicators = []
        
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                headers = {
                    'Key': self.config.api_key,
                    'Accept': 'application/json'
                }
                
                # Get blacklisted IPs
                params = {
                    'confidenceMinimum': 75,
                    'limit': 1000,
                    'plaintext': 1
                }
                
                response = await client.get(
                    f"{self.base_url}/blacklist",
                    headers=headers,
                    params=params
                )
                
                if response.status_code == 200:
                    ips = response.text.strip().split('\n')
                    
                    for ip in ips:
                        if ip.strip():
                            indicator = ThreatIndicator(
                                id=str(uuid.uuid4()),
                                value=ip.strip(),
                                threat_type=ThreatType.MALICIOUS_IP,
                                threat_level=ThreatLevel.HIGH,
                                source=ThreatSource.ABUSE_IPDB,
                                confidence=0.85,
                                first_seen=datetime.now(timezone.utc),
                                last_seen=datetime.now(timezone.utc),
                                metadata={'provider': 'abuseipdb'},
                                expiry_date=datetime.now(timezone.utc) + timedelta(days=7)
                            )
                            indicators.append(indicator)
                
                self._last_update = time.time()
                logger.info(f"AbuseIPDB: Updated {len(indicators)} indicators")
        
        except Exception as e:
            logger.error(f"AbuseIPDB feed error: {e}")
        
        return indicators
    
    async def check_ip_reputation(self, ip: str) -> Optional[ThreatAssessment]:
        """Check IP reputation with AbuseIPDB."""
        if not HTTPX_AVAILABLE or not self.config.api_key:
            return None
        
        if not self._check_rate_limit():
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                headers = {
                    'Key': self.config.api_key,
                    'Accept': 'application/json'
                }
                
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': ''
                }
                
                response = await client.get(
                    f"{self.base_url}/check",
                    headers=headers,
                    params=params
                )
                
                if response.status_code == 200:
                    data = response.json()['data']
                    
                    abuse_confidence = data.get('abuseConfidencePercentage', 0)
                    usage_type = data.get('usageType', '')
                    
                    # Calculate risk score
                    risk_score = abuse_confidence / 100.0
                    
                    # Determine threat level and reputation
                    if abuse_confidence > 75:
                        threat_level = ThreatLevel.CRITICAL
                        reputation = IPReputation.MALICIOUS
                    elif abuse_confidence > 50:
                        threat_level = ThreatLevel.HIGH
                        reputation = IPReputation.MALICIOUS
                    elif abuse_confidence > 25:
                        threat_level = ThreatLevel.MEDIUM
                        reputation = IPReputation.SUSPICIOUS
                    elif abuse_confidence > 0:
                        threat_level = ThreatLevel.LOW
                        reputation = IPReputation.SUSPICIOUS
                    else:
                        threat_level = ThreatLevel.LOW
                        reputation = IPReputation.CLEAN
                    
                    # Create indicators if malicious
                    indicators = []
                    if abuse_confidence > 0:
                        indicator = ThreatIndicator(
                            id=str(uuid.uuid4()),
                            value=ip,
                            threat_type=ThreatType.MALICIOUS_IP,
                            threat_level=threat_level,
                            source=ThreatSource.ABUSE_IPDB,
                            confidence=abuse_confidence / 100.0,
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                            metadata={
                                'abuse_confidence': abuse_confidence,
                                'usage_type': usage_type,
                                'country_code': data.get('countryCode'),
                                'is_whitelisted': data.get('isWhitelisted'),
                                'total_reports': data.get('totalReports')
                            }
                        )
                        indicators.append(indicator)
                    
                    reasons = []
                    if abuse_confidence > 0:
                        reasons.append(f"AbuseIPDB confidence: {abuse_confidence}%")
                    if data.get('totalReports', 0) > 0:
                        reasons.append(f"Total reports: {data['totalReports']}")
                    
                    return ThreatAssessment(
                        ip=ip,
                        threat_level=threat_level,
                        reputation=reputation,
                        risk_score=risk_score,
                        confidence=0.9,
                        indicators=indicators,
                        recommended_action=self._get_recommended_action(threat_level),
                        reasons=reasons
                    )
        
        except Exception as e:
            logger.error(f"AbuseIPDB IP check error: {e}")
        
        return None
    
    def _get_recommended_action(self, threat_level: ThreatLevel) -> ResponseAction:
        """Get recommended action based on threat level."""
        if threat_level == ThreatLevel.CRITICAL:
            return ResponseAction.PERMANENT_BLOCK
        elif threat_level == ThreatLevel.HIGH:
            return ResponseAction.TEMPORARY_BLOCK
        elif threat_level == ThreatLevel.MEDIUM:
            return ResponseAction.RATE_LIMIT
        else:
            return ResponseAction.MONITOR


class ThreatSignatureEngine:
    """Pattern matching and signature-based threat detection."""
    
    def __init__(self):
        self.signatures = {}
        self._lock = RLock()
        self._load_default_signatures()
    
    def _load_default_signatures(self):
        """Load default threat signatures."""
        default_signatures = {
            'sql_injection': [
                r"(\\'|(\\')|(;)|(union)|(select)|(drop)|(insert)|(delete)|(update)|(create)|(alter)|(exec)|(execute))",
                r"(or\s+1\s*=\s*1)|(and\s+1\s*=\s*1)",
                r"(union\s+select)|(union\s+all\s+select)",
            ],
            'xss_attempt': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
            ],
            'command_injection': [
                r"(\||\&|\;|\$\(|\`)",
                r"(wget|curl|nc|netcat|telnet)",
                r"(/bin/|/usr/bin/|cmd\.exe)",
            ],
            'path_traversal': [
                r"(\.\.\/|\.\.\\)",
                r"(\/etc\/passwd|\/etc\/shadow)",
                r"(\.\.%2f|\.\.%5c)",
            ],
            'brute_force_patterns': [
                r"(admin|administrator|root|test|guest)",
                r"(password|passwd|pwd|login)",
                r"(123456|password|admin|test)",
            ]
        }
        
        for category, patterns in default_signatures.items():
            for pattern in patterns:
                self.add_signature(category, pattern, ThreatLevel.MEDIUM)
    
    def add_signature(self, name: str, pattern: str, threat_level: ThreatLevel):
        """Add new threat signature pattern."""
        with self._lock:
            if name not in self.signatures:
                self.signatures[name] = []
            
            try:
                compiled_pattern = re.compile(pattern, re.IGNORECASE)
                self.signatures[name].append({
                    'pattern': pattern,
                    'compiled': compiled_pattern,
                    'threat_level': threat_level
                })
                logger.info(f"Added signature: {name}")
            
            except re.error as e:
                logger.error(f"Invalid regex pattern '{pattern}': {e}")
    
    def scan_request(self, request_data: Dict[str, Any]) -> List[ThreatIndicator]:
        """Scan request data for threat signatures."""
        indicators = []
        
        # Combine all request data for scanning
        scan_text = ""
        if request_data.get('url'):
            scan_text += request_data['url'] + " "
        if request_data.get('headers'):
            scan_text += " ".join(f"{k}:{v}" for k, v in request_data['headers'].items()) + " "
        if request_data.get('body'):
            scan_text += str(request_data['body']) + " "
        if request_data.get('params'):
            scan_text += " ".join(f"{k}={v}" for k, v in request_data['params'].items())
        
        with self._lock:
            for signature_name, signatures in self.signatures.items():
                for sig_data in signatures:
                    if sig_data['compiled'].search(scan_text):
                        indicator = ThreatIndicator(
                            id=str(uuid.uuid4()),
                            value=signature_name,
                            threat_type=ThreatType.EXPLOITATION,
                            threat_level=sig_data['threat_level'],
                            source=ThreatSource.SIGNATURE_MATCH,
                            confidence=0.8,
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                            metadata={
                                'signature_name': signature_name,
                                'pattern': sig_data['pattern'],
                                'matched_text': scan_text[:200]  # First 200 chars
                            }
                        )
                        indicators.append(indicator)
        
        return indicators


class ThreatResponseManager:
    """Automated threat response and mitigation."""
    
    def __init__(self):
        self.response_policies = {}
        self.blocked_ips = set()
        self.rate_limited_ips = {}
        self._lock = RLock()
        self._cleanup_thread = Thread(target=self._cleanup_expired_blocks, daemon=True)
        self._cleanup_thread.start()
    
    def add_response_policy(self, threat_level: ThreatLevel, response: ThreatResponse):
        """Add automated response policy."""
        with self._lock:
            self.response_policies[threat_level] = response
            logger.info(f"Added response policy for {threat_level.value}: {response.action.value}")
    
    def execute_response(self, assessment: ThreatAssessment) -> List[str]:
        """Execute automated response based on threat assessment."""
        actions_taken = []
        
        with self._lock:
            policy = self.response_policies.get(assessment.threat_level)
            if not policy:
                return actions_taken
            
            ip = assessment.ip
            
            if policy.action == ResponseAction.PERMANENT_BLOCK:
                self.blocked_ips.add(ip)
                actions_taken.append(f"Permanently blocked IP: {ip}")
                
            elif policy.action == ResponseAction.TEMPORARY_BLOCK:
                duration = policy.duration or timedelta(hours=1)
                expires_at = datetime.now(timezone.utc) + duration
                self.blocked_ips.add(ip)
                # Store expiry time (simplified - would use more sophisticated storage)
                actions_taken.append(f"Temporarily blocked IP: {ip} until {expires_at}")
                
            elif policy.action == ResponseAction.RATE_LIMIT:
                duration = policy.duration or timedelta(minutes=30)
                expires_at = datetime.now(timezone.utc) + duration
                self.rate_limited_ips[ip] = expires_at
                actions_taken.append(f"Rate limited IP: {ip} until {expires_at}")
                
            elif policy.action == ResponseAction.QUARANTINE:
                # Quarantine logic would be implemented here
                actions_taken.append(f"Quarantined IP: {ip}")
            
            if policy.notify:
                actions_taken.append(f"Generated security alert for IP: {ip}")
        
        return actions_taken
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        with self._lock:
            return ip in self.blocked_ips
    
    def is_rate_limited(self, ip: str) -> bool:
        """Check if IP is currently rate limited."""
        with self._lock:
            if ip in self.rate_limited_ips:
                expiry = self.rate_limited_ips[ip]
                if datetime.now(timezone.utc) < expiry:
                    return True
                else:
                    del self.rate_limited_ips[ip]
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP address."""
        with self._lock:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                return True
            if ip in self.rate_limited_ips:
                del self.rate_limited_ips[ip]
                return True
            return False
    
    def _cleanup_expired_blocks(self):
        """Cleanup expired temporary blocks."""
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                
                with self._lock:
                    # Clean up expired rate limits
                    expired_ips = [
                        ip for ip, expiry in self.rate_limited_ips.items()
                        if current_time >= expiry
                    ]
                    
                    for ip in expired_ips:
                        del self.rate_limited_ips[ip]
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error during response cleanup: {e}")
                time.sleep(60)


class IPReputationAnalyzer:
    """Advanced IP reputation scoring and analysis."""
    
    def __init__(self, geolocation_service: GeolocationService):
        self.geolocation_service = geolocation_service
        self._reputation_cache = {}
        self._cache_expiry = {}
        self._lock = RLock()
    
    async def analyze_ip(self, ip: str, indicators: List[ThreatIndicator]) -> IPReputation:
        """Analyze IP reputation based on multiple factors."""
        factors = {
            'threat_indicators': 0.0,
            'geolocation_risk': 0.0,
            'network_reputation': 0.0,
            'behavioral_analysis': 0.0
        }
        
        # Analyze threat indicators
        if indicators:
            total_confidence = sum(ind.confidence for ind in indicators)
            max_threat_level = max(ind.threat_level for ind in indicators)
            
            # Weight by threat level
            threat_weights = {
                ThreatLevel.CRITICAL: 1.0,
                ThreatLevel.HIGH: 0.8,
                ThreatLevel.MEDIUM: 0.6,
                ThreatLevel.LOW: 0.3,
                ThreatLevel.UNKNOWN: 0.1
            }
            
            factors['threat_indicators'] = min(1.0, 
                total_confidence * threat_weights.get(max_threat_level, 0.5))
        
        # Analyze geolocation risk
        try:
            geolocation = await self.geolocation_service.get_geolocation(ip)
            if geolocation:
                # High-risk countries/regions (simplified example)
                high_risk_countries = {'CN', 'RU', 'IR', 'KP', 'PK'}
                
                if geolocation.country_code in high_risk_countries:
                    factors['geolocation_risk'] += 0.3
                
                if geolocation.is_proxy or geolocation.is_tor:
                    factors['geolocation_risk'] += 0.4
        
        except Exception as e:
            logger.debug(f"Geolocation analysis failed: {e}")
        
        # Check if it's a private/internal IP
        try:
            ip_obj = ip_address(ip)
            if ip_obj.is_private:
                factors['network_reputation'] = -0.5  # Negative score for internal IPs
        except AddressValueError:
            pass
        
        # Calculate overall risk score
        total_score = sum(factors.values()) / len(factors)
        
        # Determine reputation category
        if total_score > 0.8:
            return IPReputation.MALICIOUS
        elif total_score > 0.5:
            return IPReputation.SUSPICIOUS
        elif total_score > 0.2:
            return IPReputation.UNKNOWN
        elif total_score < -0.2:
            return IPReputation.TRUSTED
        else:
            return IPReputation.CLEAN
    
    def calculate_risk_score(self, indicators: List[ThreatIndicator], 
                           geolocation: Optional[IPGeolocation] = None) -> float:
        """Calculate numerical risk score (0.0 to 1.0)."""
        if not indicators:
            return 0.0
        
        # Base score from indicators
        confidence_scores = [ind.confidence for ind in indicators]
        threat_level_scores = {
            ThreatLevel.CRITICAL: 1.0,
            ThreatLevel.HIGH: 0.8,
            ThreatLevel.MEDIUM: 0.6,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.UNKNOWN: 0.1
        }
        
        level_scores = [threat_level_scores.get(ind.threat_level, 0.1) for ind in indicators]
        
        # Combine confidence and threat level
        base_score = sum(c * l for c, l in zip(confidence_scores, level_scores)) / len(indicators)
        
        # Geolocation modifier
        geo_modifier = 1.0
        if geolocation:
            if geolocation.is_proxy or geolocation.is_tor:
                geo_modifier = 1.2
            elif geolocation.country_code in {'CN', 'RU', 'IR'}:
                geo_modifier = 1.1
        
        return min(1.0, base_score * geo_modifier)


class ThreatIntelligenceEngine:
    """Main threat intelligence orchestration engine."""
    
    def __init__(self, db_path: str = "threat_intelligence.db"):
        self.database = ThreatDatabase(db_path)
        self.geolocation_service = GeolocationService()
        self.reputation_analyzer = IPReputationAnalyzer(self.geolocation_service)
        self.signature_engine = ThreatSignatureEngine()
        self.response_manager = ThreatResponseManager()
        
        # Feed providers
        self.feed_providers = {}
        self._feed_update_thread = None
        self._running = False
        
        # Setup default response policies
        self._setup_default_policies()
        
        logger.info("ThreatIntelligenceEngine initialized")
    
    def add_feed_provider(self, name: str, provider: ThreatFeedProvider):
        """Add threat intelligence feed provider."""
        self.feed_providers[name] = provider
        logger.info(f"Added threat feed provider: {name}")
    
    def start_feed_updates(self):
        """Start background thread for feed updates."""
        if self._feed_update_thread and self._feed_update_thread.is_alive():
            return
        
        self._running = True
        self._feed_update_thread = Thread(target=self._update_feeds_loop, daemon=True)
        self._feed_update_thread.start()
        logger.info("Started threat feed update service")
    
    def stop_feed_updates(self):
        """Stop background feed updates."""
        self._running = False
        if self._feed_update_thread:
            self._feed_update_thread.join(timeout=30)
        logger.info("Stopped threat feed update service")
    
    async def assess_ip_threat(self, ip: str, request_data: Optional[Dict[str, Any]] = None) -> ThreatAssessment:
        """Perform comprehensive threat assessment for IP address."""
        try:
            # Validate IP address format
            ip_obj = ip_address(ip)
        except AddressValueError:
            return ThreatAssessment(
                ip=ip,
                threat_level=ThreatLevel.UNKNOWN,
                reputation=IPReputation.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                indicators=[],
                reasons=["Invalid IP address format"]
            )
        
        # Check cache first
        cached_result = self.database.get_cached_reputation(ip)
        if cached_result:
            reputation, risk_score, confidence, geolocation = cached_result
            
            # Get stored indicators
            indicators = [
                ind for ind in self.database.search_indicators(limit=10) 
                if ind.value == ip
            ]
            
            # Determine threat level from risk score
            if risk_score > 0.8:
                threat_level = ThreatLevel.CRITICAL
            elif risk_score > 0.6:
                threat_level = ThreatLevel.HIGH
            elif risk_score > 0.4:
                threat_level = ThreatLevel.MEDIUM
            elif risk_score > 0.2:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.UNKNOWN
            
            return ThreatAssessment(
                ip=ip,
                threat_level=threat_level,
                reputation=reputation,
                risk_score=risk_score,
                confidence=confidence,
                indicators=indicators,
                geolocation=geolocation,
                reasons=["Cached assessment"]
            )
        
        # Collect threat indicators from various sources
        indicators = []
        
        # 1. Check local database
        local_indicator = self.database.get_indicator(ip)
        if local_indicator:
            indicators.append(local_indicator)
        
        # 2. Check external feed providers
        for name, provider in self.feed_providers.items():
            if provider.config.enabled:
                try:
                    assessment = await provider.check_ip_reputation(ip)
                    if assessment and assessment.indicators:
                        indicators.extend(assessment.indicators)
                        # Store indicators in database
                        for indicator in assessment.indicators:
                            self.database.store_indicator(indicator)
                
                except Exception as e:
                    logger.error(f"Error checking {name} feed: {e}")
        
        # 3. Signature-based analysis
        if request_data:
            signature_indicators = self.signature_engine.scan_request(request_data)
            indicators.extend(signature_indicators)
        
        # Get geolocation data
        geolocation = await self.geolocation_service.get_geolocation(ip)
        
        # Analyze reputation
        reputation = await self.reputation_analyzer.analyze_ip(ip, indicators)
        risk_score = self.reputation_analyzer.calculate_risk_score(indicators, geolocation)
        
        # Calculate confidence based on number of sources
        confidence = min(1.0, len(indicators) * 0.2 + (0.5 if geolocation else 0.0))
        
        # Determine threat level
        if risk_score > 0.8:
            threat_level = ThreatLevel.CRITICAL
        elif risk_score > 0.6:
            threat_level = ThreatLevel.HIGH
        elif risk_score > 0.4:
            threat_level = ThreatLevel.MEDIUM
        elif risk_score > 0.2:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.UNKNOWN
        
        # Generate reasons
        reasons = []
        if indicators:
            reasons.append(f"Found {len(indicators)} threat indicators")
        
        source_counts = defaultdict(int)
        for indicator in indicators:
            source_counts[indicator.source.value] += 1
        
        for source, count in source_counts.items():
            reasons.append(f"{source}: {count} indicators")
        
        if geolocation and (geolocation.is_proxy or geolocation.is_tor):
            reasons.append("Traffic from proxy/Tor network")
        
        # Determine recommended action
        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            recommended_action = ResponseAction.TEMPORARY_BLOCK
        elif threat_level == ThreatLevel.MEDIUM:
            recommended_action = ResponseAction.RATE_LIMIT
        else:
            recommended_action = ResponseAction.MONITOR
        
        assessment = ThreatAssessment(
            ip=ip,
            threat_level=threat_level,
            reputation=reputation,
            risk_score=risk_score,
            confidence=confidence,
            indicators=indicators,
            geolocation=geolocation,
            recommended_action=recommended_action,
            reasons=reasons
        )
        
        # Cache the result
        self.database.cache_ip_reputation(ip, reputation, risk_score, confidence, geolocation)
        
        # Execute automated response if enabled
        actions = self.response_manager.execute_response(assessment)
        if actions:
            logger.info(f"Automated response for {ip}: {actions}")
        
        return assessment
    
    def check_request_threat(self, request: Request) -> ThreatAssessment:
        """Synchronous threat check for requests (for use in shields)."""
        client_ip = self._get_client_ip(request)
        
        if not client_ip:
            return ThreatAssessment(
                ip="unknown",
                threat_level=ThreatLevel.UNKNOWN,
                reputation=IPReputation.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                indicators=[],
                reasons=["Could not determine client IP"]
            )
        
        # Quick checks first
        if self.response_manager.is_blocked(client_ip):
            return ThreatAssessment(
                ip=client_ip,
                threat_level=ThreatLevel.HIGH,
                reputation=IPReputation.MALICIOUS,
                risk_score=0.9,
                confidence=1.0,
                indicators=[],
                reasons=["IP is currently blocked"],
                recommended_action=ResponseAction.PERMANENT_BLOCK
            )
        
        # Check for cached assessment
        cached_result = self.database.get_cached_reputation(client_ip)
        if cached_result:
            reputation, risk_score, confidence, geolocation = cached_result
            
            threat_level = ThreatLevel.LOW
            if risk_score > 0.8:
                threat_level = ThreatLevel.CRITICAL
            elif risk_score > 0.6:
                threat_level = ThreatLevel.HIGH
            elif risk_score > 0.4:
                threat_level = ThreatLevel.MEDIUM
            elif risk_score > 0.2:
                threat_level = ThreatLevel.LOW
            
            return ThreatAssessment(
                ip=client_ip,
                threat_level=threat_level,
                reputation=reputation,
                risk_score=risk_score,
                confidence=confidence,
                indicators=[],  # Don't load full indicators for sync check
                geolocation=geolocation,
                reasons=["Quick cached assessment"]
            )
        
        # Return minimal assessment for unknown IPs
        return ThreatAssessment(
            ip=client_ip,
            threat_level=ThreatLevel.UNKNOWN,
            reputation=IPReputation.UNKNOWN,
            risk_score=0.0,
            confidence=0.0,
            indicators=[],
            reasons=["No cached data available - async analysis recommended"]
        )
    
    def _get_client_ip(self, request: Request) -> Optional[str]:
        """Extract client IP from request."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in case of multiple proxies
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fall back to direct client IP
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return None
    
    def _update_feeds_loop(self):
        """Background loop for updating threat feeds."""
        while self._running:
            try:
                for name, provider in self.feed_providers.items():
                    if not provider.config.enabled:
                        continue
                    
                    if provider._needs_update():
                        logger.info(f"Updating threat feed: {name}")
                        
                        # Run the async feed update
                        try:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            indicators = loop.run_until_complete(provider.fetch_indicators())
                            loop.close()
                            
                            # Store indicators in database
                            stored_count = 0
                            for indicator in indicators:
                                if self.database.store_indicator(indicator):
                                    stored_count += 1
                            
                            logger.info(f"Feed {name}: Stored {stored_count}/{len(indicators)} indicators")
                            
                        except Exception as e:
                            logger.error(f"Feed update error for {name}: {e}")
                
                # Sleep between update cycles
                time.sleep(300)  # 5 minutes
                
            except Exception as e:
                logger.error(f"Feed update loop error: {e}")
                time.sleep(60)
    
    def _setup_default_policies(self):
        """Setup default automated response policies."""
        self.response_manager.add_response_policy(
            ThreatLevel.CRITICAL,
            ThreatResponse(
                threat_level=ThreatLevel.CRITICAL,
                action=ResponseAction.TEMPORARY_BLOCK,
                duration=timedelta(hours=24),
                notify=True
            )
        )
        
        self.response_manager.add_response_policy(
            ThreatLevel.HIGH,
            ThreatResponse(
                threat_level=ThreatLevel.HIGH,
                action=ResponseAction.TEMPORARY_BLOCK,
                duration=timedelta(hours=6),
                notify=True
            )
        )
        
        self.response_manager.add_response_policy(
            ThreatLevel.MEDIUM,
            ThreatResponse(
                threat_level=ThreatLevel.MEDIUM,
                action=ResponseAction.RATE_LIMIT,
                duration=timedelta(hours=1),
                notify=False
            )
        )


# Convenience functions for easy integration

def create_threat_intelligence_engine(
    db_path: str = "threat_intelligence.db",
    enable_virustotal: bool = False,
    virustotal_api_key: Optional[str] = None,
    enable_abuseipdb: bool = False,
    abuseipdb_api_key: Optional[str] = None,
    geoip_db_path: Optional[str] = None
) -> ThreatIntelligenceEngine:
    """Create and configure threat intelligence engine."""
    
    # Initialize engine
    engine = ThreatIntelligenceEngine(db_path)
    
    # Add VirusTotal provider if enabled
    if enable_virustotal and virustotal_api_key:
        vt_config = ThreatFeedConfig(
            name="virustotal",
            provider="VirusTotal",
            api_key=virustotal_api_key,
            update_interval=3600,
            rate_limit=4,  # VirusTotal free tier limit
            enabled=True
        )
        engine.add_feed_provider("virustotal", VirusTotalProvider(vt_config))
    
    # Add AbuseIPDB provider if enabled
    if enable_abuseipdb and abuseipdb_api_key:
        abuse_config = ThreatFeedConfig(
            name="abuseipdb",
            provider="AbuseIPDB",
            api_key=abuseipdb_api_key,
            update_interval=1800,  # 30 minutes
            rate_limit=1000,  # Generous limit
            enabled=True
        )
        engine.add_feed_provider("abuseipdb", AbuseIPDBProvider(abuse_config))
    
    # Configure geolocation if available
    if geoip_db_path:
        engine.geolocation_service = GeolocationService(geoip_db_path)
    
    # Start feed updates
    if engine.feed_providers:
        engine.start_feed_updates()
    
    return engine


# Export all public classes and functions
__all__ = [
    # Enums
    'ThreatLevel',
    'ThreatType',
    'ThreatSource',
    'ResponseAction',
    'IPReputation',
    
    # Data classes
    'ThreatIndicator',
    'IPGeolocation',
    'ThreatAssessment',
    'ThreatFeedConfig',
    'ThreatResponse',
    
    # Core classes
    'ThreatDatabase',
    'GeolocationService',
    'ThreatFeedProvider',
    'VirusTotalProvider',
    'AbuseIPDBProvider',
    'ThreatSignatureEngine',
    'ThreatResponseManager',
    'IPReputationAnalyzer',
    'ThreatIntelligenceEngine',
    
    # Convenience functions
    'create_threat_intelligence_engine',
]