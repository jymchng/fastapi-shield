"""Mock objects and utilities for GraphQL Query Depth Shield testing."""

from typing import Any, Dict, List, Optional, Union
from unittest.mock import Mock, AsyncMock

from fastapi_shield.graphql_query_depth import (
    QueryAnalysisResult,
    GraphQLQueryType,
    FieldComplexity,
)


class MockGraphQLDocument:
    """Mock GraphQL document for AST parser testing."""
    
    def __init__(self, operation_type: str = "query", selections: Optional[List] = None):
        self.definitions = [MockOperationDefinition(operation_type, selections or [])]


class MockOperationDefinition:
    """Mock GraphQL operation definition."""
    
    def __init__(self, operation_type: str = "query", selections: Optional[List] = None):
        self.operation = Mock()
        self.operation.value = operation_type
        self.selection_set = MockSelectionSet(selections or [])
        self.variable_definitions = []


class MockSelectionSet:
    """Mock GraphQL selection set."""
    
    def __init__(self, selections: Optional[List] = None):
        self.selections = selections or []


class MockFieldSelection:
    """Mock GraphQL field selection."""
    
    def __init__(self, field_name: str, nested_selections: Optional[List] = None):
        self.name = Mock()
        self.name.value = field_name
        if nested_selections:
            self.selection_set = MockSelectionSet(nested_selections)
        else:
            self.selection_set = None


class MockFragmentSpread:
    """Mock GraphQL fragment spread."""
    
    def __init__(self, fragment_name: str):
        self.name = Mock()
        self.name.value = fragment_name


class MockInlineFragment:
    """Mock GraphQL inline fragment."""
    
    def __init__(self, type_name: str, selections: Optional[List] = None):
        self.type_condition = Mock()
        self.type_condition.name = Mock()
        self.type_condition.name.value = type_name
        self.selection_set = MockSelectionSet(selections or [])


class MockGraphQLParser:
    """Mock GraphQL parser for testing."""
    
    def __init__(self, should_fail: bool = False, fail_on_parse: bool = False):
        self.should_fail = should_fail
        self.fail_on_parse = fail_on_parse
        self.parse_calls = []
    
    def parse(self, query: str) -> MockGraphQLDocument:
        """Mock parse function."""
        self.parse_calls.append(query)
        
        if self.fail_on_parse:
            raise Exception("Mock parse error")
        
        if self.should_fail:
            raise ValueError("Invalid GraphQL syntax")
        
        # Create a simple mock document based on query content
        if "mutation" in query.lower():
            return MockGraphQLDocument("mutation")
        elif "subscription" in query.lower():
            return MockGraphQLDocument("subscription")
        else:
            return MockGraphQLDocument("query")
    
    def validate(self, schema, document):
        """Mock validate function."""
        if self.should_fail:
            return [{"message": "Validation error"}]
        return []


class MockRequest:
    """Mock FastAPI Request for testing."""
    
    def __init__(
        self,
        method: str = "POST",
        content_type: str = "application/json",
        body: Optional[Union[str, bytes, Dict]] = None,
        query_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        self.method = method
        self.query_params = query_params or {}
        self.headers = headers or {"content-type": content_type}
        self._body = body
        self._form_data = {}
    
    async def body(self) -> bytes:
        """Mock body method."""
        if isinstance(self._body, str):
            return self._body.encode()
        elif isinstance(self._body, bytes):
            return self._body
        elif isinstance(self._body, dict):
            import json
            return json.dumps(self._body).encode()
        return b""
    
    async def form(self) -> Dict[str, str]:
        """Mock form method."""
        return self._form_data
    
    def set_form_data(self, data: Dict[str, str]):
        """Set form data for testing."""
        self._form_data = data


class MockGraphQLQueryDepthShield:
    """Mock GraphQL Query Depth Shield for testing."""
    
    def __init__(self, should_block: bool = False, analysis_result: Optional[QueryAnalysisResult] = None):
        self.should_block = should_block
        self.analysis_result = analysis_result or QueryAnalysisResult(
            max_depth=3,
            total_nodes=5,
            complexity_score=10.0,
            operation_type=GraphQLQueryType.QUERY
        )
        self.validate_calls = []
        self.analyze_calls = []
    
    def validate_query(self, query: str) -> None:
        """Mock validate_query method."""
        self.validate_calls.append(query)
        if self.should_block:
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail="Mock validation failure")
    
    def analyze_query(self, query: str) -> QueryAnalysisResult:
        """Mock analyze_query method."""
        self.analyze_calls.append(query)
        return self.analysis_result


def create_sample_queries() -> Dict[str, str]:
    """Create sample GraphQL queries for testing."""
    return {
        "simple": "{ user { id name } }",
        "nested": """
        {
            user {
                profile {
                    settings {
                        theme
                    }
                }
            }
        }
        """,
        "with_variables": """
        query GetUser($id: ID!) {
            user(id: $id) {
                id
                name
                email
            }
        }
        """,
        "with_fragments": """
        fragment UserInfo on User {
            id
            name
            email
        }
        
        query GetUser {
            user {
                ...UserInfo
                posts {
                    title
                }
            }
        }
        """,
        "introspection": """
        {
            __schema {
                types {
                    name
                    fields {
                        name
                        type {
                            name
                        }
                    }
                }
            }
        }
        """,
        "mutation": """
        mutation CreateUser($input: UserInput!) {
            createUser(input: $input) {
                id
                name
                email
            }
        }
        """,
        "subscription": """
        subscription UserUpdates {
            userUpdated {
                id
                name
                status
            }
        }
        """,
        "deep_nested": """
        {
            level1 {
                level2 {
                    level3 {
                        level4 {
                            level5 {
                                level6 {
                                    level7 {
                                        level8 {
                                            level9 {
                                                level10 {
                                                    data
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """,
        "many_fields": """
        {
            user {
                id name email username firstName lastName
                avatar bio website location company
                createdAt updatedAt lastLogin isActive
                preferences settings notifications permissions
                profile {
                    id bio avatar cover theme language
                    privacy security notifications customizations
                }
            }
        }
        """,
        "batched": [
            {"query": "{ user(id: 1) { id name } }"},
            {"query": "{ user(id: 2) { id email } }"}
        ],
        "malformed": "{ user { id name",  # Missing closing brace
        "empty": "",
        "with_comments": """
        # Get user information
        query GetUserInfo {
            user { # User fields
                id    # User ID
                name  # User name
                email # User email
            }
        }
        """
    }


def create_complex_field_complexities() -> Dict[str, FieldComplexity]:
    """Create complex field complexity configurations for testing."""
    return {
        "user": FieldComplexity(base_cost=2.0, multiplier=1.0),
        "posts": FieldComplexity(base_cost=5.0, multiplier=2.0, max_depth=3),
        "comments": FieldComplexity(base_cost=3.0, multiplier=1.5),
        "likes": FieldComplexity(base_cost=1.0, multiplier=0.5),
        "followers": FieldComplexity(base_cost=10.0, multiplier=3.0, max_depth=2),
        "media": FieldComplexity(
            base_cost=8.0,
            multiplier=2.5,
            custom_calculator=lambda data: data.get('count', 1) * 15.0
        ),
        "notifications": FieldComplexity(base_cost=2.0, multiplier=1.2),
        "settings": FieldComplexity(base_cost=1.5, multiplier=1.0),
        "permissions": FieldComplexity(base_cost=4.0, multiplier=1.8),
        "analytics": FieldComplexity(base_cost=20.0, multiplier=5.0, max_depth=1)
    }


class MockAsyncContextManager:
    """Mock async context manager for testing."""
    
    def __init__(self, return_value=None, raise_exception=None):
        self.return_value = return_value
        self.raise_exception = raise_exception
        self.entered = False
        self.exited = False
    
    async def __aenter__(self):
        self.entered = True
        if self.raise_exception:
            raise self.raise_exception
        return self.return_value
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.exited = True
        return False


def create_mock_graphql_server_response(
    data: Optional[Dict] = None,
    errors: Optional[List[Dict]] = None,
    extensions: Optional[Dict] = None
) -> Dict[str, Any]:
    """Create a mock GraphQL server response."""
    response = {}
    
    if data is not None:
        response["data"] = data
    
    if errors:
        response["errors"] = errors
    
    if extensions:
        response["extensions"] = extensions
    
    return response


class MockGraphQLServer:
    """Mock GraphQL server for integration testing."""
    
    def __init__(self, responses: Optional[Dict[str, Dict]] = None):
        self.responses = responses or {}
        self.requests_received = []
        self.default_response = {
            "data": {"user": {"id": "1", "name": "Test User"}}
        }
    
    async def process_query(self, query: str, variables: Optional[Dict] = None) -> Dict[str, Any]:
        """Process a GraphQL query and return mock response."""
        self.requests_received.append({"query": query, "variables": variables})
        
        # Return specific response if configured
        query_hash = hash(query.strip())
        if query_hash in self.responses:
            return self.responses[query_hash]
        
        # Return default response
        return self.default_response
    
    def add_response(self, query: str, response: Dict[str, Any]):
        """Add a specific response for a query."""
        query_hash = hash(query.strip())
        self.responses[query_hash] = response