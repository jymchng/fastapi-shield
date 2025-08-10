"""Tests for API Versioning Shield functionality."""

import warnings
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield.api_versioning import (
    APIVersioningShield,
    APIVersioningConfig,
    VersioningStrategy,
    VersionFormat,
    DeprecationLevel,
    VersionValidationResult,
    VersionInfo,
    HeaderVersionExtractor,
    QueryParamVersionExtractor,
    PathVersionExtractor,
    AcceptHeaderVersionExtractor,
    URIVersionExtractor,
    VersionValidator,
    UsageTracker,
    APIVersionManager,
    api_versioning_shield,
    semantic_versioning_shield,
    url_path_versioning_shield,
    accept_header_versioning_shield,
)
from tests.mocks.api_versioning_mocks import (
    MockVersionExtractor,
    MockUsageTracker,
    create_mock_request,
    create_mock_response,
)


class TestVersionExtractors:
    """Test version extractor functionality."""
    
    def test_header_version_extractor(self):
        """Test extracting version from headers."""
        extractor = HeaderVersionExtractor("API-Version")
        request = create_mock_request(headers={"API-Version": "1.2.3"})
        
        version = extractor.extract_version(request)
        assert version == "1.2.3"
    
    def test_header_version_extractor_missing(self):
        """Test header extractor with missing header."""
        extractor = HeaderVersionExtractor("API-Version")
        request = create_mock_request(headers={})
        
        version = extractor.extract_version(request)
        assert version is None
    
    def test_header_version_extractor_custom_name(self):
        """Test header extractor with custom header name."""
        extractor = HeaderVersionExtractor("X-API-Version")
        request = create_mock_request(headers={"X-API-Version": "2.0.0"})
        
        version = extractor.extract_version(request)
        assert version == "2.0.0"
    
    def test_query_param_version_extractor(self):
        """Test extracting version from query parameters."""
        extractor = QueryParamVersionExtractor("version")
        request = create_mock_request(query_params={"version": "1.1.0"})
        
        version = extractor.extract_version(request)
        assert version == "1.1.0"
    
    def test_query_param_version_extractor_missing(self):
        """Test query param extractor with missing parameter."""
        extractor = QueryParamVersionExtractor("version")
        request = create_mock_request(query_params={})
        
        version = extractor.extract_version(request)
        assert version is None
    
    def test_path_version_extractor(self):
        """Test extracting version from path parameters."""
        extractor = PathVersionExtractor("version")
        request = create_mock_request(path_params={"version": "3"})
        
        version = extractor.extract_version(request)
        assert version == "3"
    
    def test_accept_header_version_extractor(self):
        """Test extracting version from Accept header."""
        extractor = AcceptHeaderVersionExtractor()
        request = create_mock_request(
            headers={"Accept": "application/vnd.api+json;version=1.5"}
        )
        
        version = extractor.extract_version(request)
        assert version == "1.5"
    
    def test_accept_header_version_extractor_no_match(self):
        """Test Accept header extractor with no matching pattern."""
        extractor = AcceptHeaderVersionExtractor()
        request = create_mock_request(
            headers={"Accept": "application/json"}
        )
        
        version = extractor.extract_version(request)
        assert version is None
    
    def test_uri_version_extractor(self):
        """Test extracting version from URI path."""
        extractor = URIVersionExtractor()
        request = create_mock_request(url_path="/v2/users")
        
        version = extractor.extract_version(request)
        assert version == "2"
    
    def test_uri_version_extractor_complex_path(self):
        """Test URI extractor with complex version path."""
        extractor = URIVersionExtractor()
        request = create_mock_request(url_path="/api/v1.2/users/123")
        
        version = extractor.extract_version(request)
        assert version == "1.2"


class TestVersionValidator:
    """Test version validator functionality."""
    
    def test_semantic_version_validation(self):
        """Test semantic version validation."""
        validator = VersionValidator(VersionFormat.SEMANTIC)
        
        assert validator.is_valid("1.0.0")
        assert validator.is_valid("1.2.3")
        assert validator.is_valid("2.0.0-alpha")
        assert validator.is_valid("1.0.0+build.1")
        assert not validator.is_valid("1.0")
        assert not validator.is_valid("v1.0.0")
        assert not validator.is_valid("invalid")
    
    def test_major_minor_validation(self):
        """Test major.minor version validation."""
        validator = VersionValidator(VersionFormat.MAJOR_MINOR)
        
        assert validator.is_valid("1.0")
        assert validator.is_valid("2.5")
        assert not validator.is_valid("1.0.0")
        assert not validator.is_valid("1")
        assert not validator.is_valid("invalid")
    
    def test_major_only_validation(self):
        """Test major-only version validation."""
        validator = VersionValidator(VersionFormat.MAJOR_ONLY)
        
        assert validator.is_valid("1")
        assert validator.is_valid("10")
        assert not validator.is_valid("1.0")
        assert not validator.is_valid("v1")
        assert not validator.is_valid("invalid")
    
    def test_date_based_validation(self):
        """Test date-based version validation."""
        validator = VersionValidator(VersionFormat.DATE_BASED)
        
        assert validator.is_valid("2023-01-01")
        assert validator.is_valid("2024-12-31")
        assert not validator.is_valid("2023-1-1")
        assert not validator.is_valid("23-01-01")
        assert not validator.is_valid("invalid")
    
    def test_custom_validation(self):
        """Test custom regex validation."""
        validator = VersionValidator(VersionFormat.CUSTOM, r"^v\d+$")
        
        assert validator.is_valid("v1")
        assert validator.is_valid("v123")
        assert not validator.is_valid("1")
        assert not validator.is_valid("version1")
    
    def test_version_normalization(self):
        """Test version normalization."""
        semantic_validator = VersionValidator(VersionFormat.SEMANTIC)
        assert semantic_validator.normalize_version("1") == "1.0.0"
        assert semantic_validator.normalize_version("1.2") == "1.2.0"
        assert semantic_validator.normalize_version("1.2.3") == "1.2.3"
        
        major_minor_validator = VersionValidator(VersionFormat.MAJOR_MINOR)
        assert major_minor_validator.normalize_version("1") == "1.0"
        assert major_minor_validator.normalize_version("1.2") == "1.2"
    
    def test_version_comparison(self):
        """Test version comparison."""
        validator = VersionValidator(VersionFormat.SEMANTIC)
        
        assert validator.compare_versions("1.0.0", "1.0.1") == -1
        assert validator.compare_versions("1.0.1", "1.0.0") == 1
        assert validator.compare_versions("1.0.0", "1.0.0") == 0
        assert validator.compare_versions("2.0.0", "1.9.9") == 1
        assert validator.compare_versions("1.0.0", "2.0.0") == -1


class TestUsageTracker:
    """Test usage tracker functionality."""
    
    def test_track_usage(self):
        """Test basic usage tracking."""
        tracker = UsageTracker()
        
        tracker.track_usage("1.0.0", "/api/users", "Mozilla/5.0")
        
        stats = tracker.get_usage_stats("1.0.0")
        assert stats["count"] == 1
        assert "/api/users" in stats["endpoints"]
        assert stats["endpoints"]["/api/users"] == 1
        assert "Mozilla/5.0" in stats["user_agents"]
    
    def test_track_multiple_usage(self):
        """Test tracking multiple requests."""
        tracker = UsageTracker()
        
        tracker.track_usage("1.0.0", "/api/users", "Mozilla/5.0")
        tracker.track_usage("1.0.0", "/api/posts", "Chrome/90.0")
        tracker.track_usage("2.0.0", "/api/users", "Safari/14.0")
        
        v1_stats = tracker.get_usage_stats("1.0.0")
        assert v1_stats["count"] == 2
        assert len(v1_stats["endpoints"]) == 2
        assert len(v1_stats["user_agents"]) == 2
        
        v2_stats = tracker.get_usage_stats("2.0.0")
        assert v2_stats["count"] == 1
    
    def test_get_top_versions(self):
        """Test getting top versions by usage."""
        tracker = UsageTracker()
        
        # Track different amounts for different versions
        for _ in range(5):
            tracker.track_usage("1.0.0", "/api/test")
        
        for _ in range(3):
            tracker.track_usage("2.0.0", "/api/test")
        
        for _ in range(7):
            tracker.track_usage("1.5.0", "/api/test")
        
        top_versions = tracker.get_top_versions(2)
        assert len(top_versions) == 2
        assert top_versions[0] == ("1.5.0", 7)
        assert top_versions[1] == ("1.0.0", 5)


class TestAPIVersionManager:
    """Test API version manager functionality."""
    
    def test_manager_creation(self):
        """Test creating API version manager."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0", "2.0.0"],
            default_version="1.0.0"
        )
        manager = APIVersionManager(config)
        
        assert manager.config == config
        assert manager.validator is not None
        assert manager.usage_tracker is None  # Disabled by default
    
    def test_manager_with_usage_tracking(self):
        """Test manager with usage tracking enabled."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0",
            enable_usage_tracking=True
        )
        manager = APIVersionManager(config)
        
        assert manager.usage_tracker is not None
    
    def test_extract_version_header_strategy(self):
        """Test version extraction with header strategy."""
        config = APIVersioningConfig(
            strategy=VersioningStrategy.HEADER,
            supported_versions=["1.0.0"],
            default_version="1.0.0"
        )
        manager = APIVersionManager(config)
        
        request = create_mock_request(headers={"API-Version": "1.0.0"})
        version = manager.extract_version(request)
        
        assert version == "1.0.0"
    
    def test_validate_version_success(self):
        """Test successful version validation."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0", "2.0.0"],
            default_version="1.0.0"
        )
        manager = APIVersionManager(config)
        
        request = create_mock_request(headers={"API-Version": "1.0.0"})
        result = manager.validate_version(request)
        
        assert result.is_valid
        assert result.is_supported
        assert not result.is_deprecated
        assert result.normalized_version == "1.0.0"
    
    def test_validate_version_missing_required(self):
        """Test validation with missing required version."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0",
            require_version=True
        )
        manager = APIVersionManager(config)
        
        request = create_mock_request(headers={})
        result = manager.validate_version(request)
        
        assert not result.is_valid
        assert not result.is_supported
    
    def test_validate_version_use_default(self):
        """Test validation using default version."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0",
            require_version=False
        )
        manager = APIVersionManager(config)
        
        request = create_mock_request(headers={})
        result = manager.validate_version(request)
        
        assert result.is_valid
        assert result.is_supported
        assert result.normalized_version == "1.0.0"
    
    def test_validate_version_unsupported(self):
        """Test validation with unsupported version."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0"
        )
        manager = APIVersionManager(config)
        
        request = create_mock_request(headers={"API-Version": "3.0.0"})
        result = manager.validate_version(request)
        
        assert result.is_valid  # Format is valid
        assert not result.is_supported  # But not supported
    
    def test_validate_version_deprecated(self):
        """Test validation with deprecated version."""
        deprecated_info = VersionInfo(
            version="1.0.0",
            normalized_version="1.0.0",
            is_deprecated=True,
            deprecation_level=DeprecationLevel.WARNING,
            deprecation_message="Version 1.0.0 is deprecated"
        )
        
        config = APIVersioningConfig(
            supported_versions=["1.0.0", "2.0.0"],
            default_version="2.0.0",
            deprecated_versions={"1.0.0": deprecated_info}
        )
        manager = APIVersionManager(config)
        
        request = create_mock_request(headers={"API-Version": "1.0.0"})
        result = manager.validate_version(request)
        
        assert result.is_valid
        assert result.is_supported
        assert result.is_deprecated
        assert result.deprecation_level == DeprecationLevel.WARNING
        assert result.deprecation_message == "Version 1.0.0 is deprecated"
    
    def test_add_deprecation_warning_headers(self):
        """Test adding deprecation warnings to response."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0",
            enable_deprecation_warnings=True
        )
        manager = APIVersionManager(config)
        
        response = create_mock_response()
        validation_result = VersionValidationResult(
            version="1.0.0",
            normalized_version="1.0.0",
            is_valid=True,
            is_supported=True,
            is_deprecated=True,
            deprecation_level=DeprecationLevel.CRITICAL,
            deprecation_message="Critical deprecation",
            sunset_date=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        manager.add_deprecation_warning(response, validation_result)
        
        assert response.headers["API-Deprecation"] == "true"
        assert response.headers["API-Deprecation-Level"] == "critical"
        assert response.headers["API-Deprecation-Message"] == "Critical deprecation"
        assert "API-Sunset-Date" in response.headers
    
    def test_add_version_headers(self):
        """Test adding version headers to response."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0", "2.0.0"],
            default_version="1.0.0",
            version_header_response=True
        )
        manager = APIVersionManager(config)
        
        response = create_mock_response()
        validation_result = VersionValidationResult(
            version="1.0.0",
            normalized_version="1.0.0",
            is_valid=True,
            is_supported=True,
            is_deprecated=False
        )
        
        manager.add_version_headers(response, validation_result)
        
        assert response.headers["API-Version"] == "1.0.0"
        assert response.headers["API-Supported-Versions"] == "1.0.0,2.0.0"


class TestAPIVersioningShield:
    """Test API versioning shield functionality."""
    
    def test_shield_creation(self):
        """Test creating API versioning shield."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0"
        )
        shield = APIVersioningShield(config)
        
        assert shield.config == config
        assert shield.version_manager is not None
    
    @pytest.mark.asyncio
    async def test_version_guard_success(self):
        """Test successful version guard execution."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0"
        )
        shield = APIVersioningShield(config)
        
        request = create_mock_request(headers={"API-Version": "1.0.0"})
        response = create_mock_response()
        
        result = await shield._version_guard(request, response)
        
        assert result is not None
        assert result["api_version"] == "1.0.0"
        assert "version_info" in result
        assert "feature_flags" in result
    
    @pytest.mark.asyncio
    async def test_version_guard_invalid_format(self):
        """Test version guard with invalid format."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0",
            version_format=VersionFormat.SEMANTIC,
            strict_validation=True
        )
        shield = APIVersioningShield(config)
        
        request = create_mock_request(headers={"API-Version": "invalid"})
        response = create_mock_response()
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._version_guard(request, response)
        
        assert exc_info.value.status_code == 400
        assert "Invalid API version format" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_version_guard_unsupported(self):
        """Test version guard with unsupported version."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0"
        )
        shield = APIVersioningShield(config)
        
        request = create_mock_request(headers={"API-Version": "3.0.0"})
        response = create_mock_response()
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._version_guard(request, response)
        
        assert exc_info.value.status_code == 406
        assert "is not supported" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_version_guard_sunset(self):
        """Test version guard with sunset version."""
        deprecated_info = VersionInfo(
            version="1.0.0",
            normalized_version="1.0.0",
            is_deprecated=True,
            sunset_date=datetime.now(timezone.utc) - timedelta(days=1)  # Already sunset
        )
        
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0",
            deprecated_versions={"1.0.0": deprecated_info}
        )
        shield = APIVersioningShield(config)
        
        request = create_mock_request(headers={"API-Version": "1.0.0"})
        response = create_mock_response()
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._version_guard(request, response)
        
        assert exc_info.value.status_code == 410
        assert "has been sunset" in exc_info.value.detail


class TestConvenienceFunctions:
    """Test convenience shield creation functions."""
    
    def test_basic_api_versioning_shield(self):
        """Test basic API versioning shield creation."""
        shield = api_versioning_shield(
            strategy=VersioningStrategy.HEADER,
            supported_versions=["1.0.0", "2.0.0"],
            default_version="1.0.0"
        )
        
        assert isinstance(shield, APIVersioningShield)
        assert shield.config.strategy == VersioningStrategy.HEADER
        assert shield.config.supported_versions == ["1.0.0", "2.0.0"]
        assert shield.config.default_version == "1.0.0"
    
    def test_semantic_versioning_shield(self):
        """Test semantic versioning shield creation."""
        shield = semantic_versioning_shield(
            supported_versions=["1.0.0", "1.1.0", "2.0.0"]
        )
        
        assert isinstance(shield, APIVersioningShield)
        assert shield.config.version_format == VersionFormat.SEMANTIC
        assert shield.config.enable_deprecation_warnings is True
        assert shield.config.enable_usage_tracking is True
        assert shield.config.default_version == "2.0.0"  # Latest version
    
    def test_url_path_versioning_shield(self):
        """Test URL path versioning shield creation."""
        shield = url_path_versioning_shield(
            supported_versions=["1", "2", "3"]
        )
        
        assert isinstance(shield, APIVersioningShield)
        assert shield.config.strategy == VersioningStrategy.URI_PARAM
        assert shield.config.version_format == VersionFormat.MAJOR_ONLY
        assert shield.config.require_version is True
    
    def test_accept_header_versioning_shield(self):
        """Test Accept header versioning shield creation."""
        shield = accept_header_versioning_shield(
            supported_versions=["1.0", "2.0"]
        )
        
        assert isinstance(shield, APIVersioningShield)
        assert shield.config.strategy == VersioningStrategy.ACCEPT_HEADER
        assert shield.config.version_format == VersionFormat.MAJOR_MINOR


class TestIntegration:
    """Integration tests with FastAPI."""
    
    def test_versioning_shield_integration(self):
        """Test versioning shield integration with FastAPI."""
        app = FastAPI()
        
        shield = api_versioning_shield(
            supported_versions=["1.0.0", "2.0.0"],
            default_version="1.0.0"
        )
        
        @app.get("/api/test")
        @shield
        def test_endpoint():
            return {"message": "Test endpoint"}
        
        @app.get("/public")
        def public_endpoint():
            return {"message": "Public endpoint"}
        
        client = TestClient(app)
        
        # Test with valid version header
        response = client.get("/api/test", headers={"API-Version": "1.0.0"})
        assert response.status_code == 200
        assert "API-Version" in response.headers
        
        # Test with invalid version
        response = client.get("/api/test", headers={"API-Version": "9.0.0"})
        assert response.status_code == 406
        
        # Test public endpoint (unprotected)
        response = client.get("/public")
        assert response.status_code == 200
    
    def test_path_versioning_integration(self):
        """Test path-based versioning integration."""
        app = FastAPI()
        
        shield = url_path_versioning_shield(supported_versions=["1", "2"])
        
        @app.get("/api/v{version}/users")
        @shield
        def get_users():
            return {"users": []}
        
        client = TestClient(app)
        
        # Test valid version in path
        response = client.get("/api/v1/users")
        assert response.status_code == 200
        
        # Test invalid version in path
        response = client.get("/api/v9/users")
        assert response.status_code == 406


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_version_normalization_edge_cases(self):
        """Test version normalization with edge cases."""
        validator = VersionValidator(VersionFormat.SEMANTIC)
        
        assert validator.normalize_version("1") == "1.0.0"
        assert validator.normalize_version("1.2") == "1.2.0"
        assert validator.normalize_version("1.2.3-alpha") == "1.2.3-alpha"
        assert validator.normalize_version("") == ""
    
    def test_usage_tracker_with_none_values(self):
        """Test usage tracker with None values."""
        tracker = UsageTracker()
        
        tracker.track_usage("1.0.0", "/api/test", None)
        
        stats = tracker.get_usage_stats("1.0.0")
        assert stats["count"] == 1
        assert len(stats["user_agents"]) == 0  # None not added to set
    
    def test_version_comparison_with_different_lengths(self):
        """Test version comparison with different length versions."""
        validator = VersionValidator(VersionFormat.SEMANTIC)
        
        # Different length comparisons
        assert validator.compare_versions("1.0", "1.0.1") == -1
        assert validator.compare_versions("1.0.1", "1.0") == 1
        assert validator.compare_versions("2", "1.9.9") == 1
    
    def test_date_based_version_comparison(self):
        """Test date-based version comparison."""
        validator = VersionValidator(VersionFormat.DATE_BASED)
        
        assert validator.compare_versions("2023-01-01", "2023-12-31") == -1
        assert validator.compare_versions("2024-01-01", "2023-12-31") == 1
        assert validator.compare_versions("2023-01-01", "2023-01-01") == 0
    
    @pytest.mark.asyncio
    async def test_shield_with_disabled_features(self):
        """Test shield with various features disabled."""
        config = APIVersioningConfig(
            supported_versions=["1.0.0"],
            default_version="1.0.0",
            enable_deprecation_warnings=False,
            version_header_response=False,
            enable_usage_tracking=False
        )
        shield = APIVersioningShield(config)
        
        request = create_mock_request(headers={"API-Version": "1.0.0"})
        response = create_mock_response()
        
        result = await shield._version_guard(request, response)
        
        assert result is not None
        assert len(response.headers) == 0  # No headers added
    
    def test_custom_regex_validation_error(self):
        """Test custom regex validation with invalid pattern."""
        # This should not raise an error during initialization
        validator = VersionValidator(VersionFormat.CUSTOM, None)
        
        # Should return False for any version when no custom regex
        assert not validator.is_valid("anything")
    
    def test_extractor_with_malformed_accept_header(self):
        """Test Accept header extractor with malformed header."""
        extractor = AcceptHeaderVersionExtractor()
        request = create_mock_request(
            headers={"Accept": "malformed-header-without-version"}
        )
        
        version = extractor.extract_version(request)
        assert version is None