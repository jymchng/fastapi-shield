"""API Versioning Shield for FastAPI Shield.

This module provides comprehensive API versioning functionality including
version validation, routing, deprecation warnings, and feature toggles.
"""

import re
import warnings
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import parse_qs, urlparse

from fastapi import HTTPException, Request, Response, status
from pydantic import BaseModel, Field, validator

from fastapi_shield.shield import Shield, shield


class VersioningStrategy(str, Enum):
    """API versioning strategies."""
    HEADER = "header"
    QUERY_PARAM = "query_param"
    PATH = "path"
    ACCEPT_HEADER = "accept_header"
    URI_PARAM = "uri_param"


class VersionFormat(str, Enum):
    """Version format types."""
    SEMANTIC = "semantic"  # e.g., 1.2.3
    MAJOR_MINOR = "major_minor"  # e.g., 1.2
    MAJOR_ONLY = "major_only"  # e.g., 1
    DATE_BASED = "date_based"  # e.g., 2023-01-01
    CUSTOM = "custom"  # Custom format with regex


class DeprecationLevel(str, Enum):
    """Deprecation warning levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    SUNSET = "sunset"


class VersionValidationResult(BaseModel):
    """Version validation result."""
    version: str
    normalized_version: str
    is_valid: bool
    is_supported: bool
    is_deprecated: bool
    deprecation_level: Optional[DeprecationLevel] = None
    deprecation_message: Optional[str] = None
    sunset_date: Optional[datetime] = None
    feature_flags: Dict[str, bool] = Field(default_factory=dict)


class VersionInfo(BaseModel):
    """Version information model."""
    version: str = Field(description="Version string")
    normalized_version: str = Field(description="Normalized version string")
    is_supported: bool = Field(default=True, description="Whether version is supported")
    is_deprecated: bool = Field(default=False, description="Whether version is deprecated")
    deprecation_level: Optional[DeprecationLevel] = Field(default=None, description="Deprecation level")
    deprecation_message: Optional[str] = Field(default=None, description="Deprecation message")
    deprecation_date: Optional[datetime] = Field(default=None, description="When version was deprecated")
    sunset_date: Optional[datetime] = Field(default=None, description="When version will be removed")
    feature_flags: Dict[str, bool] = Field(default_factory=dict, description="Feature flags for this version")
    release_date: Optional[datetime] = Field(default=None, description="Version release date")
    changelog_url: Optional[str] = Field(default=None, description="URL to changelog")


class APIVersioningConfig(BaseModel):
    """API versioning configuration."""
    strategy: VersioningStrategy = Field(default=VersioningStrategy.HEADER, description="Versioning strategy")
    version_format: VersionFormat = Field(default=VersionFormat.SEMANTIC, description="Version format")
    custom_version_regex: Optional[str] = Field(default=None, description="Custom version regex pattern")
    header_name: str = Field(default="API-Version", description="Header name for version")
    query_param_name: str = Field(default="version", description="Query parameter name")
    path_param_name: str = Field(default="version", description="Path parameter name")
    accept_header_pattern: str = Field(default=r"application/vnd\.api\+json;version=(.+)", 
                                     description="Accept header pattern")
    default_version: str = Field(description="Default version when none specified")
    supported_versions: List[str] = Field(description="List of supported versions")
    deprecated_versions: Dict[str, VersionInfo] = Field(default_factory=dict, 
                                                       description="Deprecated version info")
    require_version: bool = Field(default=True, description="Whether version is required")
    strict_validation: bool = Field(default=True, description="Whether to use strict validation")
    enable_deprecation_warnings: bool = Field(default=True, description="Enable deprecation warnings")
    enable_usage_tracking: bool = Field(default=False, description="Enable usage tracking")
    version_header_response: bool = Field(default=True, description="Include version in response headers")


class VersionExtractor(ABC):
    """Abstract base class for version extractors."""
    
    @abstractmethod
    def extract_version(self, request: Request) -> Optional[str]:
        """Extract version from request."""
        pass


class HeaderVersionExtractor(VersionExtractor):
    """Extract version from request headers."""
    
    def __init__(self, header_name: str = "API-Version"):
        self.header_name = header_name
    
    def extract_version(self, request: Request) -> Optional[str]:
        """Extract version from request headers."""
        return request.headers.get(self.header_name)


class QueryParamVersionExtractor(VersionExtractor):
    """Extract version from query parameters."""
    
    def __init__(self, param_name: str = "version"):
        self.param_name = param_name
    
    def extract_version(self, request: Request) -> Optional[str]:
        """Extract version from query parameters."""
        return request.query_params.get(self.param_name)


class PathVersionExtractor(VersionExtractor):
    """Extract version from path parameters."""
    
    def __init__(self, param_name: str = "version"):
        self.param_name = param_name
    
    def extract_version(self, request: Request) -> Optional[str]:
        """Extract version from path parameters."""
        return request.path_params.get(self.param_name)


class AcceptHeaderVersionExtractor(VersionExtractor):
    """Extract version from Accept header."""
    
    def __init__(self, pattern: str = r"application/vnd\.api\+json;version=(.+)"):
        self.pattern = re.compile(pattern)
    
    def extract_version(self, request: Request) -> Optional[str]:
        """Extract version from Accept header."""
        accept_header = request.headers.get("Accept", "")
        match = self.pattern.search(accept_header)
        return match.group(1) if match else None


class URIVersionExtractor(VersionExtractor):
    """Extract version from URI path."""
    
    def __init__(self, pattern: str = r"/v(\d+(?:\.\d+)*)/"):
        self.pattern = re.compile(pattern)
    
    def extract_version(self, request: Request) -> Optional[str]:
        """Extract version from URI path."""
        match = self.pattern.search(request.url.path)
        return match.group(1) if match else None


class VersionValidator:
    """Version validator for different formats."""
    
    def __init__(self, version_format: VersionFormat, custom_regex: Optional[str] = None):
        self.version_format = version_format
        self.custom_regex = re.compile(custom_regex) if custom_regex else None
        
        # Predefined patterns
        self._patterns = {
            VersionFormat.SEMANTIC: re.compile(r"^\d+\.\d+\.\d+(?:-[\w\.-]+)?(?:\+[\w\.-]+)?$"),
            VersionFormat.MAJOR_MINOR: re.compile(r"^\d+\.\d+$"),
            VersionFormat.MAJOR_ONLY: re.compile(r"^\d+$"),
            VersionFormat.DATE_BASED: re.compile(r"^\d{4}-\d{2}-\d{2}$"),
        }
    
    def is_valid(self, version: str) -> bool:
        """Check if version format is valid."""
        if self.version_format == VersionFormat.CUSTOM and self.custom_regex:
            return bool(self.custom_regex.match(version))
        
        pattern = self._patterns.get(self.version_format)
        return bool(pattern and pattern.match(version))
    
    def normalize_version(self, version: str) -> str:
        """Normalize version string."""
        if not version:
            return version
            
        if self.version_format == VersionFormat.SEMANTIC:
            # Ensure semantic version has all parts
            parts = version.split('.')
            if len(parts) == 1:
                return f"{parts[0]}.0.0"
            elif len(parts) == 2:
                return f"{parts[0]}.{parts[1]}.0"
        elif self.version_format == VersionFormat.MAJOR_MINOR:
            # Ensure major.minor format
            parts = version.split('.')
            if len(parts) == 1:
                return f"{parts[0]}.0"
        
        return version
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """Compare two versions. Returns -1, 0, or 1."""
        v1_parts = self._parse_version(version1)
        v2_parts = self._parse_version(version2)
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1_part = v1_parts[i] if i < len(v1_parts) else 0
            v2_part = v2_parts[i] if i < len(v2_parts) else 0
            
            if v1_part < v2_part:
                return -1
            elif v1_part > v2_part:
                return 1
        
        return 0
    
    def _parse_version(self, version: str) -> List[int]:
        """Parse version into numeric parts."""
        if self.version_format == VersionFormat.DATE_BASED:
            # Convert date to comparable format
            date_str = version.replace('-', '')
            return [int(date_str)]
        
        # Extract numeric parts
        parts = re.findall(r'\d+', version)
        return [int(part) for part in parts]


class UsageTracker:
    """Track API version usage."""
    
    def __init__(self):
        self.usage_stats: Dict[str, Dict[str, Any]] = {}
    
    def track_usage(self, version: str, endpoint: str, user_agent: Optional[str] = None):
        """Track version usage."""
        if version not in self.usage_stats:
            self.usage_stats[version] = {
                'count': 0,
                'first_seen': datetime.now(timezone.utc),
                'last_seen': datetime.now(timezone.utc),
                'endpoints': {},
                'user_agents': set()
            }
        
        stats = self.usage_stats[version]
        stats['count'] += 1
        stats['last_seen'] = datetime.now(timezone.utc)
        
        if endpoint not in stats['endpoints']:
            stats['endpoints'][endpoint] = 0
        stats['endpoints'][endpoint] += 1
        
        if user_agent:
            stats['user_agents'].add(user_agent)
    
    def get_usage_stats(self, version: Optional[str] = None) -> Dict[str, Any]:
        """Get usage statistics."""
        if version:
            return self.usage_stats.get(version, {})
        return self.usage_stats
    
    def get_top_versions(self, limit: int = 10) -> List[tuple[str, int]]:
        """Get top versions by usage."""
        version_counts = [(v, stats['count']) for v, stats in self.usage_stats.items()]
        return sorted(version_counts, key=lambda x: x[1], reverse=True)[:limit]


class APIVersionManager:
    """Manage API versions and their lifecycle."""
    
    def __init__(self, config: APIVersioningConfig):
        self.config = config
        self.validator = VersionValidator(config.version_format, config.custom_version_regex)
        self.usage_tracker = UsageTracker() if config.enable_usage_tracking else None
        
        # Setup version extractors
        self.extractors = {
            VersioningStrategy.HEADER: HeaderVersionExtractor(config.header_name),
            VersioningStrategy.QUERY_PARAM: QueryParamVersionExtractor(config.query_param_name),
            VersioningStrategy.PATH: PathVersionExtractor(config.path_param_name),
            VersioningStrategy.ACCEPT_HEADER: AcceptHeaderVersionExtractor(config.accept_header_pattern),
            VersioningStrategy.URI_PARAM: URIVersionExtractor(),
        }
    
    def extract_version(self, request: Request) -> Optional[str]:
        """Extract version from request using configured strategy."""
        extractor = self.extractors[self.config.strategy]
        return extractor.extract_version(request)
    
    def validate_version(self, request: Request) -> VersionValidationResult:
        """Validate and process version from request."""
        # Extract version
        version = self.extract_version(request)
        
        # Use default if not provided
        if not version:
            if self.config.require_version:
                return VersionValidationResult(
                    version="",
                    normalized_version="",
                    is_valid=False,
                    is_supported=False,
                    is_deprecated=False
                )
            version = self.config.default_version
        
        # Validate format
        if self.config.strict_validation and not self.validator.is_valid(version):
            return VersionValidationResult(
                version=version,
                normalized_version=version,
                is_valid=False,
                is_supported=False,
                is_deprecated=False
            )
        
        # Normalize version
        normalized_version = self.validator.normalize_version(version)
        
        # Check if supported
        is_supported = normalized_version in self.config.supported_versions
        
        # Check deprecation status
        is_deprecated = normalized_version in self.config.deprecated_versions
        deprecated_info = self.config.deprecated_versions.get(normalized_version)
        
        # Get feature flags
        feature_flags = {}
        if deprecated_info:
            feature_flags = deprecated_info.feature_flags.copy()
        
        # Track usage if enabled
        if self.usage_tracker:
            endpoint = request.url.path
            user_agent = request.headers.get("User-Agent")
            self.usage_tracker.track_usage(normalized_version, endpoint, user_agent)
        
        return VersionValidationResult(
            version=version,
            normalized_version=normalized_version,
            is_valid=True,
            is_supported=is_supported,
            is_deprecated=is_deprecated,
            deprecation_level=deprecated_info.deprecation_level if deprecated_info else None,
            deprecation_message=deprecated_info.deprecation_message if deprecated_info else None,
            sunset_date=deprecated_info.sunset_date if deprecated_info else None,
            feature_flags=feature_flags
        )
    
    def add_deprecation_warning(self, response: Response, validation_result: VersionValidationResult):
        """Add deprecation warnings to response."""
        if not validation_result.is_deprecated or not self.config.enable_deprecation_warnings:
            return
        
        # Add deprecation headers
        response.headers["API-Deprecation"] = "true"
        response.headers["API-Deprecation-Level"] = validation_result.deprecation_level.value
        
        if validation_result.deprecation_message:
            response.headers["API-Deprecation-Message"] = validation_result.deprecation_message
        
        if validation_result.sunset_date:
            response.headers["API-Sunset-Date"] = validation_result.sunset_date.isoformat()
        
        # Issue Python warning
        if validation_result.deprecation_level == DeprecationLevel.CRITICAL:
            warnings.warn(
                f"API version {validation_result.normalized_version} is critically deprecated",
                DeprecationWarning,
                stacklevel=3
            )
    
    def add_version_headers(self, response: Response, validation_result: VersionValidationResult):
        """Add version information to response headers."""
        if self.config.version_header_response:
            response.headers["API-Version"] = validation_result.normalized_version
            response.headers["API-Supported-Versions"] = ",".join(self.config.supported_versions)


class APIVersioningShield(Shield):
    """API versioning shield for FastAPI endpoints."""
    
    def __init__(self, config: APIVersioningConfig, **kwargs):
        self.config = config
        self.version_manager = APIVersionManager(config)
        
        super().__init__(
            self._version_guard,
            name=kwargs.get('name', 'API Versioning'),
            auto_error=kwargs.get('auto_error', True),
            exception_to_raise_if_fail=kwargs.get('exception_to_raise_if_fail'),
            default_response_to_return_if_fail=kwargs.get('default_response_to_return_if_fail')
        )
    
    async def _version_guard(self, request: Request, response: Response) -> Optional[Dict[str, Any]]:
        """Version validation guard function."""
        validation_result = self.version_manager.validate_version(request)
        
        # Check if version is valid and supported
        if not validation_result.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid API version format: {validation_result.version}"
            )
        
        if not validation_result.is_supported:
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                detail=f"API version {validation_result.normalized_version} is not supported. "
                       f"Supported versions: {', '.join(self.config.supported_versions)}"
            )
        
        # Check if version is sunset (completely deprecated)
        if (validation_result.is_deprecated and 
            validation_result.sunset_date and 
            validation_result.sunset_date <= datetime.now(timezone.utc)):
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=f"API version {validation_result.normalized_version} has been sunset"
            )
        
        # Add deprecation warnings
        self.version_manager.add_deprecation_warning(response, validation_result)
        
        # Add version headers
        self.version_manager.add_version_headers(response, validation_result)
        
        return {
            'api_version': validation_result.normalized_version,
            'version_info': validation_result,
            'feature_flags': validation_result.feature_flags
        }


# Convenience functions for creating common versioning shields

def api_versioning_shield(
    strategy: VersioningStrategy = VersioningStrategy.HEADER,
    supported_versions: Optional[List[str]] = None,
    default_version: str = "1.0.0",
    **kwargs
) -> APIVersioningShield:
    """Create a basic API versioning shield."""
    if supported_versions is None:
        supported_versions = ["1.0.0"]
    
    config = APIVersioningConfig(
        strategy=strategy,
        supported_versions=supported_versions,
        default_version=default_version
    )
    
    return APIVersioningShield(config=config, **kwargs)


def semantic_versioning_shield(
    supported_versions: Optional[List[str]] = None,
    deprecated_versions: Optional[Dict[str, VersionInfo]] = None,
    **kwargs
) -> APIVersioningShield:
    """Create a semantic versioning shield."""
    if supported_versions is None:
        supported_versions = ["1.0.0", "1.1.0", "2.0.0"]
    
    config = APIVersioningConfig(
        strategy=VersioningStrategy.HEADER,
        version_format=VersionFormat.SEMANTIC,
        supported_versions=supported_versions,
        deprecated_versions=deprecated_versions or {},
        default_version=supported_versions[-1],
        enable_deprecation_warnings=True,
        enable_usage_tracking=True
    )
    
    return APIVersioningShield(config=config, **kwargs)


def url_path_versioning_shield(
    supported_versions: Optional[List[str]] = None,
    **kwargs
) -> APIVersioningShield:
    """Create a URL path versioning shield (e.g., /v1/users)."""
    if supported_versions is None:
        supported_versions = ["1", "2", "3"]
    
    config = APIVersioningConfig(
        strategy=VersioningStrategy.URI_PARAM,
        version_format=VersionFormat.MAJOR_ONLY,
        supported_versions=supported_versions,
        default_version=supported_versions[-1],
        require_version=True
    )
    
    return APIVersioningShield(config=config, **kwargs)


def accept_header_versioning_shield(
    accept_pattern: str = r"application/vnd\.api\+json;version=(.+)",
    supported_versions: Optional[List[str]] = None,
    **kwargs
) -> APIVersioningShield:
    """Create an Accept header versioning shield."""
    if supported_versions is None:
        supported_versions = ["1.0", "1.1", "2.0"]
    
    config = APIVersioningConfig(
        strategy=VersioningStrategy.ACCEPT_HEADER,
        accept_header_pattern=accept_pattern,
        version_format=VersionFormat.MAJOR_MINOR,
        supported_versions=supported_versions,
        default_version=supported_versions[0]
    )
    
    return APIVersioningShield(config=config, **kwargs)