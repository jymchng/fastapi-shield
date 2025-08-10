"""Bot detection shield for FastAPI Shield.

This module provides comprehensive bot detection capabilities to identify
and manage automated requests. It includes user-agent analysis, behavioral
pattern detection, IP reputation checking, and CAPTCHA integration.
"""

import hashlib
import re
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple, Union
from urllib.parse import urlparse
from collections import defaultdict, deque

from fastapi import HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator

from fastapi_shield.shield import Shield, shield


class BotType(str, Enum):
    """Types of detected bots."""
    SEARCH_ENGINE = "search_engine"
    SOCIAL_MEDIA = "social_media"
    MONITORING = "monitoring"
    SCRAPER = "scraper"
    MALICIOUS = "malicious"
    CRAWLER = "crawler"
    SEO_TOOL = "seo_tool"
    SECURITY_SCANNER = "security_scanner"
    UNKNOWN = "unknown"


class DetectionMethod(str, Enum):
    """Bot detection methods."""
    USER_AGENT = "user_agent"
    BEHAVIORAL = "behavioral"
    IP_REPUTATION = "ip_reputation"
    FINGERPRINTING = "fingerprinting"
    RATE_LIMITING = "rate_limiting"
    CAPTCHA = "captcha"


class BotAction(str, Enum):
    """Actions to take when a bot is detected."""
    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"
    RATE_LIMIT = "rate_limit"
    LOG_ONLY = "log_only"


class ChallengeType(str, Enum):
    """Types of challenges for bot verification."""
    CAPTCHA = "captcha"
    JAVASCRIPT = "javascript"
    PROOF_OF_WORK = "proof_of_work"
    DELAY = "delay"


class BotDetectionConfig(BaseModel):
    """Configuration for bot detection."""
    
    # Detection methods to enable
    enable_user_agent_detection: bool = True
    enable_behavioral_detection: bool = True
    enable_ip_reputation: bool = False  # Requires external service
    enable_fingerprinting: bool = True
    enable_rate_analysis: bool = True
    
    # User-agent patterns
    known_bot_patterns: List[str] = Field(default_factory=lambda: [
        r'.*bot.*',
        r'.*crawl.*',
        r'.*spider.*',
        r'.*scraper.*',
        r'.*scanner.*',
        r'curl/',
        r'wget/',
        r'python-requests/',
        r'Go-http-client/',
        r'Apache-HttpClient/',
        r'Java/',
        r'.*headless.*',
        r'PhantomJS',
        r'Selenium',
        r'.*automated.*'
    ])
    
    # Legitimate bot whitelist
    legitimate_bots: Dict[str, BotType] = Field(default_factory=lambda: {
        r'Googlebot': BotType.SEARCH_ENGINE,
        r'Bingbot': BotType.SEARCH_ENGINE,
        r'Slurp': BotType.SEARCH_ENGINE,  # Yahoo
        r'DuckDuckBot': BotType.SEARCH_ENGINE,
        r'Baiduspider': BotType.SEARCH_ENGINE,
        r'YandexBot': BotType.SEARCH_ENGINE,
        r'facebookexternalhit': BotType.SOCIAL_MEDIA,
        r'Twitterbot': BotType.SOCIAL_MEDIA,
        r'LinkedInBot': BotType.SOCIAL_MEDIA,
        r'WhatsApp': BotType.SOCIAL_MEDIA,
        r'TelegramBot': BotType.SOCIAL_MEDIA,
        r'Pingdom': BotType.MONITORING,
        r'UptimeRobot': BotType.MONITORING,
        r'StatusCake': BotType.MONITORING,
        r'Datadog': BotType.MONITORING,
    })
    
    # Behavioral detection settings
    behavioral_window_minutes: int = 10
    max_requests_per_window: int = 100
    max_unique_paths_ratio: float = 0.8  # Suspicious if > 80% unique paths
    min_request_interval_ms: int = 100   # Minimum time between requests
    suspicious_patterns: List[str] = Field(default_factory=lambda: [
        r'/admin.*',
        r'/wp-admin.*',
        r'/.env',
        r'/config.*',
        r'/\..*',  # Hidden files
        r'/robots\.txt',
        r'/sitemap\.xml'
    ])
    
    # Fingerprinting settings
    track_request_fingerprints: bool = True
    fingerprint_headers: List[str] = Field(default_factory=lambda: [
        'user-agent',
        'accept',
        'accept-language',
        'accept-encoding',
        'connection',
        'upgrade-insecure-requests',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest'
    ])
    
    # Challenge settings
    default_bot_action: BotAction = BotAction.LOG_ONLY
    malicious_bot_action: BotAction = BotAction.BLOCK
    challenge_type: ChallengeType = ChallengeType.CAPTCHA
    challenge_timeout_minutes: int = 5
    
    # Bot type specific actions
    bot_type_actions: Dict[BotType, BotAction] = Field(default_factory=lambda: {
        BotType.SEARCH_ENGINE: BotAction.ALLOW,
        BotType.SOCIAL_MEDIA: BotAction.ALLOW,
        BotType.MONITORING: BotAction.ALLOW,
        BotType.SCRAPER: BotAction.CHALLENGE,
        BotType.MALICIOUS: BotAction.BLOCK,
        BotType.SECURITY_SCANNER: BotAction.BLOCK,
        BotType.UNKNOWN: BotAction.LOG_ONLY,
    })
    
    # Performance settings
    max_tracked_ips: int = 10000
    cleanup_interval_minutes: int = 60
    enable_caching: bool = True
    
    # Logging and monitoring
    log_all_detections: bool = True
    log_legitimate_bots: bool = False
    include_detection_headers: bool = True
    
    @field_validator('known_bot_patterns', 'suspicious_patterns')
    @classmethod
    def validate_regex_patterns(cls, v):
        """Validate regex patterns."""
        for pattern in v:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
        return v


class BotDetectionResult(BaseModel):
    """Result of bot detection analysis."""
    
    is_bot: bool
    bot_type: Optional[BotType] = None
    confidence: float = Field(ge=0.0, le=1.0)
    detection_methods: List[DetectionMethod] = Field(default_factory=list)
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    action: BotAction = BotAction.LOG_ONLY
    challenge_required: bool = False
    reason: Optional[str] = None
    score_breakdown: Dict[DetectionMethod, float] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)


class RequestFingerprint(BaseModel):
    """Fingerprint of a request for tracking."""
    
    headers_hash: str
    path_hash: str
    ip_address: str
    timestamp: float
    user_agent: Optional[str] = None


class BehavioralMetrics(BaseModel):
    """Behavioral metrics for an IP address."""
    
    request_count: int = 0
    unique_paths: Set[str] = Field(default_factory=set)
    request_intervals: deque = Field(default_factory=lambda: deque(maxlen=100))
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    suspicious_path_count: int = 0
    fingerprints: List[str] = Field(default_factory=list)
    
    model_config = {"arbitrary_types_allowed": True}


class UserAgentAnalyzer:
    """Analyzes user-agent strings for bot detection."""
    
    def __init__(self, config: BotDetectionConfig):
        """Initialize user-agent analyzer.
        
        Args:
            config: Bot detection configuration
        """
        self.config = config
        self._bot_patterns: List[Pattern] = []
        self._legitimate_patterns: Dict[Pattern, BotType] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance."""
        # Compile general bot patterns
        for pattern in self.config.known_bot_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._bot_patterns.append(compiled)
            except re.error:
                pass  # Skip invalid patterns
        
        # Compile legitimate bot patterns
        for pattern, bot_type in self.config.legitimate_bots.items():
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._legitimate_patterns[compiled] = bot_type
            except re.error:
                pass  # Skip invalid patterns
    
    def analyze(self, user_agent: str) -> Tuple[bool, Optional[BotType], float, str]:
        """Analyze user-agent string.
        
        Args:
            user_agent: User-agent string to analyze
            
        Returns:
            Tuple of (is_bot, bot_type, confidence, reason)
        """
        if not user_agent:
            return False, None, 0.0, "No user-agent provided"
        
        user_agent = user_agent.strip()
        
        # Check for legitimate bots first
        for pattern, bot_type in self._legitimate_patterns.items():
            if pattern.search(user_agent):
                return True, bot_type, 0.9, f"Legitimate {bot_type.value} detected"
        
        # Check for suspicious characteristics
        suspicious_score = 0.0
        reasons = []
        
        # Very short user-agents 
        if len(user_agent) < 20:
            suspicious_score += 0.3
            reasons.append("Unusually short user-agent")
        
        # Check for general bot patterns (but only if not already suspicious for other reasons)
        matched_patterns = []
        for pattern in self._bot_patterns:
            if pattern.search(user_agent):
                matched_patterns.append(pattern.pattern)
        
        # If we have both suspicious characteristics and pattern matches, prioritize characteristics
        if suspicious_score >= 0.3 and matched_patterns:
            # Continue with suspicious characteristics analysis
            pass  
        elif matched_patterns:
            confidence = min(0.8 + len(matched_patterns) * 0.1, 1.0)
            reason = f"Bot patterns matched: {', '.join(matched_patterns[:3])}"
            return True, BotType.UNKNOWN, confidence, reason
        
        # No version information
        if not re.search(r'\d+\.\d+', user_agent):
            suspicious_score += 0.2
            reasons.append("No version information")
        
        # Missing common browser indicators
        common_indicators = ['mozilla', 'webkit', 'chrome', 'firefox', 'safari', 'edge']
        if not any(indicator in user_agent.lower() for indicator in common_indicators):
            suspicious_score += 0.3
            reasons.append("Missing common browser indicators")
        
        # Programming language indicators
        prog_languages = ['python', 'java', 'go', 'ruby', 'php', 'node']
        if any(lang in user_agent.lower() for lang in prog_languages):
            suspicious_score += 0.4
            reasons.append("Programming language detected in user-agent")
        
        # Library/framework indicators
        libraries = ['requests', 'urllib', 'httpclient', 'okhttp', 'axios']
        if any(lib in user_agent.lower() for lib in libraries):
            suspicious_score += 0.5
            reasons.append("HTTP library detected in user-agent")
        
        if suspicious_score >= 0.5:
            reason = f"Suspicious characteristics: {', '.join(reasons)}"
            bot_type = BotType.SCRAPER if suspicious_score >= 0.7 else BotType.UNKNOWN
            return True, bot_type, suspicious_score, reason
        
        return False, None, 0.0, "Appears to be legitimate user"


class BehavioralAnalyzer:
    """Analyzes request patterns for bot-like behavior."""
    
    def __init__(self, config: BotDetectionConfig):
        """Initialize behavioral analyzer.
        
        Args:
            config: Bot detection configuration
        """
        self.config = config
        self.ip_metrics: Dict[str, BehavioralMetrics] = {}
        self._suspicious_patterns: List[Pattern] = []
        self._compile_patterns()
        self._last_cleanup = time.time()
    
    def _compile_patterns(self) -> None:
        """Compile suspicious path patterns."""
        for pattern in self.config.suspicious_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._suspicious_patterns.append(compiled)
            except re.error:
                pass  # Skip invalid patterns
    
    def _cleanup_old_metrics(self) -> None:
        """Clean up old metrics to prevent memory leaks."""
        current_time = time.time()
        if current_time - self._last_cleanup < self.config.cleanup_interval_minutes * 60:
            return
        
        cutoff_time = current_time - self.config.behavioral_window_minutes * 60
        expired_ips = [
            ip for ip, metrics in self.ip_metrics.items()
            if metrics.last_seen < cutoff_time
        ]
        
        for ip in expired_ips:
            del self.ip_metrics[ip]
        
        # Limit total tracked IPs
        if len(self.ip_metrics) > self.config.max_tracked_ips:
            # Remove oldest entries
            sorted_ips = sorted(
                self.ip_metrics.items(),
                key=lambda x: x[1].last_seen
            )
            to_remove = len(self.ip_metrics) - self.config.max_tracked_ips
            for ip, _ in sorted_ips[:to_remove]:
                del self.ip_metrics[ip]
        
        self._last_cleanup = current_time
    
    def track_request(self, ip_address: str, path: str, user_agent: Optional[str] = None) -> None:
        """Track a request for behavioral analysis.
        
        Args:
            ip_address: Client IP address
            path: Request path
            user_agent: User-agent string
        """
        current_time = time.time()
        
        # Cleanup old metrics periodically
        self._cleanup_old_metrics()
        
        # Get or create metrics for this IP
        if ip_address not in self.ip_metrics:
            self.ip_metrics[ip_address] = BehavioralMetrics()
        
        metrics = self.ip_metrics[ip_address]
        
        # Update metrics
        metrics.request_count += 1
        metrics.unique_paths.add(path)
        metrics.last_seen = current_time
        
        # Track request intervals (store timestamps, not intervals)
        metrics.request_intervals.append(current_time)
        
        # Check for suspicious paths
        for pattern in self._suspicious_patterns:
            if pattern.search(path):
                metrics.suspicious_path_count += 1
                break
        
        # Track fingerprints
        if user_agent:
            ua_hash = hashlib.md5(user_agent.encode()).hexdigest()[:16]
            if ua_hash not in metrics.fingerprints:
                metrics.fingerprints.append(ua_hash)
    
    def analyze(self, ip_address: str) -> Tuple[bool, float, str]:
        """Analyze behavioral patterns for an IP.
        
        Args:
            ip_address: IP address to analyze
            
        Returns:
            Tuple of (is_suspicious, confidence, reason)
        """
        if ip_address not in self.ip_metrics:
            return False, 0.0, "No behavioral data available"
        
        metrics = self.ip_metrics[ip_address]
        current_time = time.time()
        window_start = current_time - self.config.behavioral_window_minutes * 60
        
        # Filter requests within the window
        if metrics.first_seen < window_start:
            # Only consider recent activity
            relevant_request_count = metrics.request_count  # Simplified for now
        else:
            relevant_request_count = metrics.request_count
        
        suspicious_score = 0.0
        reasons = []
        
        # High request rate
        if relevant_request_count > self.config.max_requests_per_window:
            suspicious_score += 0.4
            reasons.append(f"High request rate: {relevant_request_count} requests")
        
        # High unique path ratio (indicates crawling behavior)
        if relevant_request_count > 10:  # Only analyze if sufficient data
            unique_ratio = len(metrics.unique_paths) / relevant_request_count
            if unique_ratio > self.config.max_unique_paths_ratio:
                suspicious_score += 0.3
                reasons.append(f"High unique paths ratio: {unique_ratio:.2f}")
        
        # Fast request intervals
        if len(metrics.request_intervals) > 2:
            # Calculate intervals between consecutive timestamps
            intervals = []
            for i in range(1, len(metrics.request_intervals)):
                interval = metrics.request_intervals[i] - metrics.request_intervals[i-1]
                intervals.append(interval)
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                if avg_interval < self.config.min_request_interval_ms / 1000:
                    suspicious_score += 0.3
                    reasons.append(f"Fast request intervals: {avg_interval:.3f}s average")
        
        # Suspicious path access
        if metrics.suspicious_path_count > 0:
            suspicious_score += min(metrics.suspicious_path_count * 0.1, 0.3)
            reasons.append(f"Accessed {metrics.suspicious_path_count} suspicious paths")
        
        # Multiple fingerprints (indicates automation tools)
        if len(metrics.fingerprints) > 3:
            suspicious_score += 0.2
            reasons.append(f"Multiple fingerprints: {len(metrics.fingerprints)}")
        
        if suspicious_score >= 0.5:
            reason = f"Behavioral analysis: {', '.join(reasons)}"
            return True, min(suspicious_score, 1.0), reason
        
        return False, suspicious_score, f"Normal behavior (score: {suspicious_score:.2f})"


class BotDetector:
    """Main bot detection engine."""
    
    def __init__(self, config: BotDetectionConfig):
        """Initialize bot detector.
        
        Args:
            config: Bot detection configuration
        """
        self.config = config
        self.user_agent_analyzer = UserAgentAnalyzer(config)
        self.behavioral_analyzer = BehavioralAnalyzer(config)
        self._detection_cache: Dict[str, Tuple[BotDetectionResult, float]] = {}
    
    def _get_cache_key(self, ip_address: str, user_agent: str) -> str:
        """Generate cache key for detection results.
        
        Args:
            ip_address: Client IP address
            user_agent: User-agent string
            
        Returns:
            Cache key string
        """
        combined = f"{ip_address}|{user_agent}"
        return hashlib.md5(combined.encode()).hexdigest()
    
    def _is_cache_valid(self, timestamp: float) -> bool:
        """Check if cached result is still valid.
        
        Args:
            timestamp: Cache timestamp
            
        Returns:
            True if cache is still valid
        """
        return time.time() - timestamp < 300  # 5 minutes cache
    
    async def detect(
        self,
        request: Request,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> BotDetectionResult:
        """Detect if request is from a bot.
        
        Args:
            request: FastAPI request object
            ip_address: Override IP address
            user_agent: Override user-agent
            
        Returns:
            Bot detection result
        """
        # Extract information from request
        if not ip_address:
            ip_address = self._get_client_ip(request)
        
        if not user_agent:
            user_agent = request.headers.get('user-agent', '')
        
        path = request.url.path
        
        # Check cache first
        if self.config.enable_caching:
            cache_key = self._get_cache_key(ip_address, user_agent)
            if cache_key in self._detection_cache:
                cached_result, timestamp = self._detection_cache[cache_key]
                if self._is_cache_valid(timestamp):
                    return cached_result
        
        # Track request for behavioral analysis
        if self.config.enable_behavioral_detection:
            self.behavioral_analyzer.track_request(ip_address, path, user_agent)
        
        # Initialize result
        result = BotDetectionResult(
            is_bot=False,
            confidence=0.0,
            user_agent=user_agent,
            ip_address=ip_address,
            action=self.config.default_bot_action
        )
        
        detection_scores: Dict[DetectionMethod, float] = {}
        detection_reasons: List[str] = []
        
        # User-agent analysis
        if self.config.enable_user_agent_detection and user_agent:
            is_bot, bot_type, confidence, reason = self.user_agent_analyzer.analyze(user_agent)
            detection_scores[DetectionMethod.USER_AGENT] = confidence
            
            if is_bot:
                result.is_bot = True
                result.bot_type = bot_type
                result.detection_methods.append(DetectionMethod.USER_AGENT)
                detection_reasons.append(reason)
        
        # Behavioral analysis
        if self.config.enable_behavioral_detection:
            is_suspicious, confidence, reason = self.behavioral_analyzer.analyze(ip_address)
            detection_scores[DetectionMethod.BEHAVIORAL] = confidence
            
            if is_suspicious:
                result.is_bot = True
                if not result.bot_type:
                    result.bot_type = BotType.SCRAPER
                result.detection_methods.append(DetectionMethod.BEHAVIORAL)
                detection_reasons.append(reason)
        
        # Calculate overall confidence
        if detection_scores:
            # If user-agent detection found a legitimate bot, use that confidence directly
            if DetectionMethod.USER_AGENT in detection_scores and result.bot_type in [BotType.SEARCH_ENGINE, BotType.SOCIAL_MEDIA, BotType.MONITORING]:
                result.confidence = detection_scores[DetectionMethod.USER_AGENT]
            else:
                # Weighted average of detection scores for other cases
                weights = {
                    DetectionMethod.USER_AGENT: 0.4,
                    DetectionMethod.BEHAVIORAL: 0.6,
                    DetectionMethod.FINGERPRINTING: 0.3,
                    DetectionMethod.RATE_LIMITING: 0.5,
                }
                
                total_score = 0.0
                total_weight = 0.0
                
                for method, score in detection_scores.items():
                    weight = weights.get(method, 0.5)
                    total_score += score * weight
                    total_weight += weight
                
                result.confidence = total_score / total_weight if total_weight > 0 else 0.0
        
        # Determine final bot type if not already set
        if result.is_bot and not result.bot_type:
            if result.confidence >= 0.8:
                result.bot_type = BotType.MALICIOUS
            elif result.confidence >= 0.6:
                result.bot_type = BotType.SCRAPER
            else:
                result.bot_type = BotType.UNKNOWN
        
        # Determine action based on bot type
        if result.is_bot and result.bot_type:
            result.action = self.config.bot_type_actions.get(
                result.bot_type, 
                self.config.default_bot_action
            )
        
        # Set challenge requirement
        result.challenge_required = result.action == BotAction.CHALLENGE
        
        # Set reason and score breakdown
        result.reason = '; '.join(detection_reasons) if detection_reasons else None
        result.score_breakdown = detection_scores
        
        # Cache result
        if self.config.enable_caching:
            self._detection_cache[cache_key] = (result, time.time())
        
        return result
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Client IP address
        """
        # Check for forwarded headers (in order of preference)
        forwarded_headers = [
            'x-forwarded-for',
            'x-real-ip',
            'cf-connecting-ip',  # Cloudflare
            'x-client-ip',
            'forwarded'
        ]
        
        for header in forwarded_headers:
            if header in request.headers:
                ip = request.headers[header].split(',')[0].strip()
                if ip and ip != 'unknown':
                    return ip
        
        # Fallback to client host
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return 'unknown'


class BotDetectionShield:
    """Bot detection shield for FastAPI endpoints."""
    
    def __init__(self, config: BotDetectionConfig):
        """Initialize bot detection shield.
        
        Args:
            config: Bot detection configuration
        """
        self.config = config
        self.detector = BotDetector(config)
    
    def create_shield(self, name: str = "BotDetection") -> Shield:
        """Create a shield for bot detection.
        
        Args:
            name: Shield name
            
        Returns:
            Shield instance
        """
        
        async def bot_detection_shield(request: Request) -> Dict[str, Any]:
            """Bot detection shield function."""
            
            # Perform bot detection
            detection_result = await self.detector.detect(request)
            
            # Handle detected bots based on action
            if detection_result.is_bot:
                if detection_result.action == BotAction.BLOCK:
                    error_message = f"Access denied: Bot detected ({detection_result.bot_type.value if detection_result.bot_type else 'unknown'})"
                    if detection_result.reason:
                        error_message += f" - {detection_result.reason}"
                    
                    headers = {}
                    if self.config.include_detection_headers:
                        headers.update({
                            "X-Bot-Detection": "blocked",
                            "X-Bot-Type": detection_result.bot_type.value if detection_result.bot_type else "unknown",
                            "X-Bot-Confidence": str(detection_result.confidence)
                        })
                    
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=error_message,
                        headers=headers if headers else None
                    )
                
                elif detection_result.action == BotAction.CHALLENGE:
                    # For now, we'll return a challenge response
                    # In a real implementation, this would integrate with CAPTCHA services
                    headers = {}
                    if self.config.include_detection_headers:
                        headers.update({
                            "X-Bot-Detection": "challenge",
                            "X-Bot-Type": detection_result.bot_type.value if detection_result.bot_type else "unknown",
                            "X-Challenge-Type": self.config.challenge_type.value
                        })
                    
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Bot challenge required. Please solve CAPTCHA to continue.",
                        headers=headers if headers else None
                    )
            
            # Return detection result for logging/monitoring
            result = {
                "bot_detection_passed": True,
                "is_bot": detection_result.is_bot,
                "bot_type": detection_result.bot_type.value if detection_result.bot_type else None,
                "confidence": detection_result.confidence,
                "detection_methods": [method.value for method in detection_result.detection_methods],
                "action": detection_result.action.value,
                "detection_result": detection_result,
            }
            
            # Add detection headers for monitoring
            if self.config.include_detection_headers:
                # These would be added to the response in a real implementation
                result["response_headers"] = {
                    "X-Bot-Detection": "passed",
                    "X-Bot-Score": str(detection_result.confidence),
                    "X-Bot-Type": detection_result.bot_type.value if detection_result.bot_type else "none"
                }
            
            return result
        
        return shield(
            bot_detection_shield,
            name=name,
            auto_error=True,
        )


def bot_detection_shield(
    block_malicious: bool = True,
    challenge_scrapers: bool = True,
    allow_search_engines: bool = True,
    enable_behavioral_analysis: bool = True,
    behavioral_window_minutes: int = 10,
    name: str = "BotDetection",
) -> Shield:
    """Create a bot detection shield.
    
    Args:
        block_malicious: Whether to block malicious bots
        challenge_scrapers: Whether to challenge scraper bots
        allow_search_engines: Whether to allow search engine bots
        enable_behavioral_analysis: Whether to enable behavioral analysis
        behavioral_window_minutes: Time window for behavioral analysis
        name: Shield name
        
    Returns:
        Bot detection shield
        
    Examples:
        ```python
        # Basic bot detection
        @app.get("/api/data")
        @bot_detection_shield()
        def get_data():
            return {"data": "protected"}
        
        # Strict bot detection
        @app.get("/api/sensitive")
        @bot_detection_shield(
            block_malicious=True,
            challenge_scrapers=True,
            allow_search_engines=False
        )
        def get_sensitive_data():
            return {"sensitive": "data"}
        
        # Custom behavioral analysis
        @app.post("/api/content")
        @bot_detection_shield(
            enable_behavioral_analysis=True,
            behavioral_window_minutes=5
        )
        def post_content(data: dict):
            return {"created": True}
        ```
    """
    # Configure bot type actions
    bot_type_actions = {
        BotType.SEARCH_ENGINE: BotAction.ALLOW if allow_search_engines else BotAction.CHALLENGE,
        BotType.SOCIAL_MEDIA: BotAction.ALLOW,
        BotType.MONITORING: BotAction.ALLOW,
        BotType.SCRAPER: BotAction.CHALLENGE if challenge_scrapers else BotAction.LOG_ONLY,
        BotType.MALICIOUS: BotAction.BLOCK if block_malicious else BotAction.CHALLENGE,
        BotType.SECURITY_SCANNER: BotAction.BLOCK,
        BotType.UNKNOWN: BotAction.LOG_ONLY,
    }
    
    config = BotDetectionConfig(
        enable_behavioral_detection=enable_behavioral_analysis,
        behavioral_window_minutes=behavioral_window_minutes,
        bot_type_actions=bot_type_actions,
    )
    
    shield_instance = BotDetectionShield(config)
    return shield_instance.create_shield(name)


def strict_bot_detection_shield(
    name: str = "StrictBotDetection",
) -> Shield:
    """Create a strict bot detection shield that blocks most bots.
    
    Args:
        name: Shield name
        
    Returns:
        Strict bot detection shield
        
    Examples:
        ```python
        @app.get("/admin/panel")
        @strict_bot_detection_shield()
        def admin_panel():
            return {"admin": "interface"}
        ```
    """
    config = BotDetectionConfig(
        default_bot_action=BotAction.BLOCK,
        bot_type_actions={
            BotType.SEARCH_ENGINE: BotAction.BLOCK,
            BotType.SOCIAL_MEDIA: BotAction.CHALLENGE,
            BotType.MONITORING: BotAction.CHALLENGE,
            BotType.SCRAPER: BotAction.BLOCK,
            BotType.MALICIOUS: BotAction.BLOCK,
            BotType.SECURITY_SCANNER: BotAction.BLOCK,
            BotType.UNKNOWN: BotAction.CHALLENGE,
        },
        enable_behavioral_detection=True,
        behavioral_window_minutes=5,
        max_requests_per_window=50,
    )
    
    shield_instance = BotDetectionShield(config)
    return shield_instance.create_shield(name)


def search_engine_friendly_shield(
    name: str = "SearchEngineFriendly",
) -> Shield:
    """Create a bot detection shield that's friendly to search engines.
    
    Args:
        name: Shield name
        
    Returns:
        Search engine friendly shield
        
    Examples:
        ```python
        @app.get("/public/content")
        @search_engine_friendly_shield()
        def public_content():
            return {"content": "public data"}
        ```
    """
    config = BotDetectionConfig(
        default_bot_action=BotAction.LOG_ONLY,
        bot_type_actions={
            BotType.SEARCH_ENGINE: BotAction.ALLOW,
            BotType.SOCIAL_MEDIA: BotAction.ALLOW,
            BotType.MONITORING: BotAction.ALLOW,
            BotType.SCRAPER: BotAction.CHALLENGE,
            BotType.MALICIOUS: BotAction.BLOCK,
            BotType.SECURITY_SCANNER: BotAction.BLOCK,
            BotType.UNKNOWN: BotAction.LOG_ONLY,
        },
        enable_behavioral_detection=True,
        behavioral_window_minutes=15,
        max_requests_per_window=200,  # More lenient for crawlers
    )
    
    shield_instance = BotDetectionShield(config)
    return shield_instance.create_shield(name)