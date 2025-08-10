"""Mock objects for API Versioning testing."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from unittest.mock import Mock

from fastapi_shield.api_versioning import UsageTracker, VersionExtractor


class MockVersionExtractor(VersionExtractor):
    """Mock version extractor for testing."""
    
    def __init__(self, version_to_return: Optional[str] = None):
        self.version_to_return = version_to_return
        self.extract_calls = []
    
    def extract_version(self, request) -> Optional[str]:
        """Mock version extraction."""
        self.extract_calls.append(request)
        return self.version_to_return
    
    def set_version(self, version: Optional[str]):
        """Set the version to return."""
        self.version_to_return = version
    
    def get_call_count(self) -> int:
        """Get number of calls."""
        return len(self.extract_calls)


class MockUsageTracker(UsageTracker):
    """Mock usage tracker for testing."""
    
    def __init__(self):
        super().__init__()
        self.track_calls = []
    
    def track_usage(self, version: str, endpoint: str, user_agent: Optional[str] = None):
        """Mock usage tracking with call recording."""
        super().track_usage(version, endpoint, user_agent)
        self.track_calls.append({
            'version': version,
            'endpoint': endpoint,
            'user_agent': user_agent,
            'timestamp': datetime.now(timezone.utc)
        })
    
    def get_track_calls(self) -> List[Dict]:
        """Get all tracking calls."""
        return self.track_calls
    
    def clear_calls(self):
        """Clear tracking calls."""
        self.track_calls.clear()


def create_mock_request(
    headers: Optional[Dict[str, str]] = None,
    query_params: Optional[Dict[str, str]] = None,
    path_params: Optional[Dict[str, str]] = None,
    path: str = "/api/test",
    url_path: str = "/api/test"
) -> Mock:
    """Create a mock FastAPI Request object."""
    request = Mock()
    request.headers = headers or {}
    request.query_params = query_params or {}
    request.path_params = path_params or {}
    request.url = Mock()
    request.url.path = url_path
    
    # Mock the path attribute directly too
    request.path = path
    
    return request


def create_mock_response() -> Mock:
    """Create a mock FastAPI Response object."""
    response = Mock()
    response.headers = {}
    return response