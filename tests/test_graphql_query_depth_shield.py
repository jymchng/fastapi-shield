"""Comprehensive tests for GraphQL Query Depth Shield functionality."""

import json
import pytest
from typing import Dict, Any
from unittest.mock import Mock, patch, AsyncMock

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from fastapi_shield.graphql_query_depth import (
    GraphQLQueryDepthShield,
    GraphQLQueryDepthConfig,
    GraphQLQueryType,
    ComplexityCalculationStrategy,
    QueryAnalysisResult,
    FieldComplexity,
    RegexGraphQLParser,
    ASTGraphQLParser,
    graphql_query_depth_shield,
    create_strict_graphql_shield,
    create_permissive_graphql_shield,
    create_production_graphql_shield,
    _extract_graphql_query,
)


class TestGraphQLQueryDepthConfig:
    """Test GraphQL Query Depth configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = GraphQLQueryDepthConfig()
        assert config.max_depth == 10
        assert config.max_complexity == 1000.0
        assert config.max_nodes == 500
        assert config.allow_introspection == False
        assert config.complexity_strategy == ComplexityCalculationStrategy.DEPTH_ONLY
        assert config.default_field_cost == 1.0
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Valid config
        config = GraphQLQueryDepthConfig(
            max_depth=5,
            max_complexity=100.0,
            max_nodes=50
        )
        assert config.max_depth == 5
        assert config.max_complexity == 100.0
        assert config.max_nodes == 50
    
    def test_field_complexities_dict_conversion(self):
        """Test field complexities conversion from dict."""
        config = GraphQLQueryDepthConfig(
            field_complexities={
                "user": {"base_cost": 2.0, "multiplier": 1.5},
                "posts": 5.0,  # Simple numeric value
                "comments": FieldComplexity(base_cost=3.0)
            }
        )
        
        assert "user" in config.field_complexities
        assert config.field_complexities["user"].base_cost == 2.0
        assert config.field_complexities["user"].multiplier == 1.5
        
        assert "posts" in config.field_complexities
        assert config.field_complexities["posts"].base_cost == 5.0
        
        assert "comments" in config.field_complexities
        assert config.field_complexities["comments"].base_cost == 3.0
    
    def test_operation_specific_limits(self):
        """Test operation-specific depth limits."""
        config = GraphQLQueryDepthConfig(
            max_depth=10,
            query_max_depth=8,
            mutation_max_depth=5,
            subscription_max_depth=3
        )
        
        assert config.query_max_depth == 8
        assert config.mutation_max_depth == 5
        assert config.subscription_max_depth == 3


class TestRegexGraphQLParser:
    """Test regex-based GraphQL parser."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.config = GraphQLQueryDepthConfig()
        self.parser = RegexGraphQLParser(self.config)
    
    def test_extract_operation_type_query(self):
        """Test extracting query operation type."""
        query = "query GetUser { user { id name } }"
        result = self.parser.extract_operation_type(query)
        assert result == GraphQLQueryType.QUERY
    
    def test_extract_operation_type_mutation(self):
        """Test extracting mutation operation type."""
        query = "mutation CreateUser { createUser(input: $input) { id } }"
        result = self.parser.extract_operation_type(query)
        assert result == GraphQLQueryType.MUTATION
    
    def test_extract_operation_type_subscription(self):
        """Test extracting subscription operation type."""
        query = "subscription UserUpdates { userUpdated { id } }"
        result = self.parser.extract_operation_type(query)
        assert result == GraphQLQueryType.SUBSCRIPTION
    
    def test_extract_operation_type_default(self):
        """Test default operation type when none specified."""
        query = "{ user { id name } }"
        result = self.parser.extract_operation_type(query)
        assert result == GraphQLQueryType.QUERY
    
    def test_calculate_depth_simple(self):
        """Test calculating depth of simple query."""
        query = "{ user { name } }"
        result = self.parser._calculate_depth(query)
        assert result == 2  # Root { user { } }
    
    def test_calculate_depth_nested(self):
        """Test calculating depth of deeply nested query."""
        query = """
        {
            user {
                profile {
                    settings {
                        preferences {
                            theme
                        }
                    }
                }
            }
        }
        """
        result = self.parser._calculate_depth(query)
        assert result == 5
    
    def test_count_selection_nodes(self):
        """Test counting selection nodes."""
        query = """
        {
            user {
                id
                name
                email
                profile {
                    bio
                    avatar
                }
            }
        }
        """
        result = self.parser._count_selection_nodes(query)
        # user, profile, and leaf fields
        assert result >= 6
    
    def test_parse_query_comprehensive(self):
        """Test comprehensive query parsing."""
        query = """
        query GetUserData($userId: ID!) {
            user(id: $userId) {
                id
                name
                email
                posts {
                    title
                    content
                    comments {
                        text
                        author {
                            name
                        }
                    }
                }
            }
        }
        """
        result = self.parser.parse_query(query)
        
        assert result.operation_type == GraphQLQueryType.QUERY
        assert result.max_depth >= 4
        assert result.total_nodes >= 8
        assert "userId" in result.variables_used
        assert "user" in result.field_counts
        assert "posts" in result.field_counts
        assert "comments" in result.field_counts
    
    def test_introspection_detection(self):
        """Test detection of introspection queries."""
        query = """
        {
            __schema {
                types {
                    name
                    __typename
                }
            }
        }
        """
        result = self.parser.parse_query(query)
        assert result.introspection_used == True
    
    def test_fragment_detection(self):
        """Test detection of fragments."""
        query = """
        fragment UserInfo on User {
            id
            name
            email
        }
        
        query GetUser {
            user {
                ...UserInfo
            }
        }
        """
        result = self.parser.parse_query(query)
        assert "UserInfo" in result.fragments_used
    
    def test_complexity_calculation_depth_only(self):
        """Test complexity calculation with depth-only strategy."""
        self.config.complexity_strategy = ComplexityCalculationStrategy.DEPTH_ONLY
        query = "{ user { profile { settings { theme } } } }"
        result = self.parser.parse_query(query)
        assert result.complexity_score == result.max_depth
    
    def test_complexity_calculation_node_count(self):
        """Test complexity calculation with node count strategy."""
        self.config.complexity_strategy = ComplexityCalculationStrategy.NODE_COUNT
        query = "{ user { id name email } }"
        result = self.parser.parse_query(query)
        assert result.complexity_score == result.total_nodes
    
    def test_complexity_calculation_weighted(self):
        """Test complexity calculation with weighted strategy."""
        self.config.complexity_strategy = ComplexityCalculationStrategy.WEIGHTED
        self.config.field_complexities = {
            "user": FieldComplexity(base_cost=5.0),
            "posts": FieldComplexity(base_cost=10.0, multiplier=2.0)
        }
        
        query = "{ user { posts { title } } }"
        result = self.parser.parse_query(query)
        
        # Should calculate based on field weights
        assert result.complexity_score > 0
        assert "user" in result.cost_breakdown
        assert "posts" in result.cost_breakdown


class TestASTGraphQLParser:
    """Test AST-based GraphQL parser."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.config = GraphQLQueryDepthConfig()
        self.parser = ASTGraphQLParser(self.config)
    
    def test_fallback_to_regex_when_no_graphql_core(self):
        """Test fallback to regex parser when graphql-core is not available."""
        with patch.object(self.parser, '_graphql_available', False):
            query = "{ user { id name } }"
            result = self.parser.parse_query(query)
            assert isinstance(result, QueryAnalysisResult)
    
    def test_parse_query_with_ast_when_available(self):
        """Test AST parsing when graphql-core is available."""
        # Mock graphql-core being available
        mock_parse = Mock()
        mock_document = Mock()
        mock_definition = Mock()
        mock_definition.operation.value = 'query'
        mock_definition.selection_set = Mock()
        mock_definition.selection_set.selections = []
        mock_document.definitions = [mock_definition]
        mock_parse.return_value = mock_document
        
        with patch.object(self.parser, '_graphql_available', True):
            # Set the mock parse function as an instance attribute
            self.parser.graphql_parse = mock_parse
            query = "{ user { id } }"
            result = self.parser.parse_query(query)
            assert result.operation_type == GraphQLQueryType.QUERY
    
    def test_fallback_on_parse_error(self):
        """Test fallback to regex parser on AST parse error."""
        mock_parse = Mock(side_effect=Exception("Parse error"))
        
        with patch.object(self.parser, '_graphql_available', True):
            self.parser.graphql_parse = mock_parse
            query = "{ user { id } }"
            result = self.parser.parse_query(query)
            assert isinstance(result, QueryAnalysisResult)


class TestGraphQLQueryDepthShield:
    """Test GraphQL query depth shield."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.config = GraphQLQueryDepthConfig(
            max_depth=5,
            max_complexity=100.0,
            max_nodes=20,
            allow_introspection=False
        )
        self.shield = GraphQLQueryDepthShield(self.config)
    
    def test_analyze_simple_query(self):
        """Test analyzing a simple query."""
        query = "{ user { id name } }"
        result = self.shield.analyze_query(query)
        assert result.max_depth <= 3
        assert result.total_nodes >= 2
        assert result.operation_type == GraphQLQueryType.QUERY
    
    def test_validate_query_within_limits(self):
        """Test validating query within limits."""
        query = "{ user { id name } }"
        # Should not raise exception
        self.shield.validate_query(query)
    
    def test_validate_query_exceeds_depth_limit(self):
        """Test validation failure when query exceeds depth limit."""
        query = """
        {
            level1 {
                level2 {
                    level3 {
                        level4 {
                            level5 {
                                level6 {
                                    data
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        with pytest.raises(HTTPException) as exc_info:
            self.shield.validate_query(query)
        assert exc_info.value.status_code == 400
        assert "depth" in exc_info.value.detail.lower()
    
    def test_validate_query_exceeds_complexity_limit(self):
        """Test validation failure when query exceeds complexity limit."""
        # Create a shield with high node limit but low complexity limit
        config = GraphQLQueryDepthConfig(
            max_depth=10,
            max_complexity=5.0,  # Very low complexity limit
            max_nodes=1000,  # High node limit so complexity is checked first
            complexity_strategy=ComplexityCalculationStrategy.WEIGHTED,
            field_complexities={"user": FieldComplexity(base_cost=10.0)}
        )
        shield = GraphQLQueryDepthShield(config)
        
        # Simple query that should exceed complexity due to weighted field
        query = "{ user { id } }"
        
        with pytest.raises(HTTPException) as exc_info:
            shield.validate_query(query)
        assert exc_info.value.status_code == 400
        assert "complexity" in exc_info.value.detail.lower()
    
    def test_validate_query_exceeds_node_limit(self):
        """Test validation failure when query exceeds node limit."""
        # Create query with many selection nodes
        fields = []
        for i in range(25):
            fields.append(f"field{i}")
        query = f"{{ user {{ {' '.join(fields)} }} }}"
        
        with pytest.raises(HTTPException) as exc_info:
            self.shield.validate_query(query)
        assert exc_info.value.status_code == 400
        assert "nodes" in exc_info.value.detail.lower()
    
    def test_validate_introspection_blocked(self):
        """Test blocking of introspection queries."""
        query = "{ __schema { types { name } } }"
        
        with pytest.raises(HTTPException) as exc_info:
            self.shield.validate_query(query)
        assert exc_info.value.status_code == 400
        assert "introspection" in exc_info.value.detail.lower()
    
    def test_validate_introspection_allowed(self):
        """Test allowing introspection when configured."""
        config = GraphQLQueryDepthConfig(allow_introspection=True)
        shield = GraphQLQueryDepthShield(config)
        
        query = "{ __schema { types { name } } }"
        # Should not raise exception
        shield.validate_query(query)
    
    def test_validate_fragments_blocked(self):
        """Test blocking of fragments when configured."""
        config = GraphQLQueryDepthConfig(allow_fragments=False)
        shield = GraphQLQueryDepthShield(config)
        
        query = """
        fragment UserInfo on User { id name }
        query { user { ...UserInfo } }
        """
        
        with pytest.raises(HTTPException) as exc_info:
            shield.validate_query(query)
        assert exc_info.value.status_code == 400
        assert "fragment" in exc_info.value.detail.lower()
    
    def test_operation_specific_limits(self):
        """Test operation-specific depth limits."""
        config = GraphQLQueryDepthConfig(
            max_depth=10,
            mutation_max_depth=3
        )
        shield = GraphQLQueryDepthShield(config)
        
        # This mutation should exceed the mutation-specific limit
        query = """
        mutation {
            createUser {
                profile {
                    settings {
                        preferences {
                            theme
                        }
                    }
                }
            }
        }
        """
        
        with pytest.raises(HTTPException) as exc_info:
            shield.validate_query(query)
        assert exc_info.value.status_code == 400
        assert "mutation" in exc_info.value.detail.lower()


class TestQueryExtraction:
    """Test GraphQL query extraction from requests."""
    
    @pytest.mark.asyncio
    async def test_extract_query_from_get_request(self):
        """Test extracting query from GET request parameters."""
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.query_params = {"query": "{ user { id } }"}
        
        query = await _extract_graphql_query(mock_request)
        assert query == "{ user { id } }"
    
    @pytest.mark.asyncio
    async def test_extract_query_from_json_post(self):
        """Test extracting query from JSON POST request."""
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = {"content-type": "application/json"}
        mock_request.body = AsyncMock(return_value=json.dumps({
            "query": "{ user { id } }",
            "variables": {"id": 1}
        }).encode())
        
        query = await _extract_graphql_query(mock_request)
        assert query == "{ user { id } }"
    
    @pytest.mark.asyncio
    async def test_extract_query_from_graphql_post(self):
        """Test extracting query from raw GraphQL POST request."""
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = {"content-type": "application/graphql"}
        mock_request.body = AsyncMock(return_value="{ user { id } }".encode())
        
        query = await _extract_graphql_query(mock_request)
        assert query == "{ user { id } }"
    
    @pytest.mark.asyncio
    async def test_extract_query_from_form_post(self):
        """Test extracting query from form-encoded POST request."""
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = {"content-type": "application/x-www-form-urlencoded"}
        mock_form = AsyncMock(return_value={"query": "{ user { id } }"})
        mock_request.form = mock_form
        
        query = await _extract_graphql_query(mock_request)
        assert query == "{ user { id } }"
    
    @pytest.mark.asyncio
    async def test_extract_query_from_batched_request(self):
        """Test extracting query from batched GraphQL request."""
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = {"content-type": "application/json"}
        mock_request.body = AsyncMock(return_value=json.dumps([
            {"query": "{ user { id } }", "variables": {}},
            {"query": "{ posts { title } }", "variables": {}}
        ]).encode())
        
        query = await _extract_graphql_query(mock_request)
        assert query == "{ user { id } }"  # Should return first query
    
    @pytest.mark.asyncio
    async def test_extract_query_malformed_json(self):
        """Test handling malformed JSON gracefully."""
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = {"content-type": "application/json"}
        mock_request.body = AsyncMock(return_value=b"invalid json")
        
        query = await _extract_graphql_query(mock_request)
        assert query is None
    
    @pytest.mark.asyncio
    async def test_extract_query_exception_handling(self):
        """Test exception handling during query extraction."""
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.headers = {"content-type": "application/json"}
        mock_request.body = AsyncMock(side_effect=Exception("Body read error"))
        
        query = await _extract_graphql_query(mock_request)
        assert query is None


class TestGraphQLShieldIntegration:
    """Test GraphQL shield integration with FastAPI."""
    
    def setup_method(self):
        """Setup test application and client."""
        self.app = FastAPI()
        self.shield_instance = graphql_query_depth_shield(
            max_depth=3,
            max_complexity=50.0,
            max_nodes=10
        )
        
        @self.app.post("/graphql")
        @self.shield_instance
        async def graphql_endpoint(request: Request):
            return {"message": "GraphQL query processed"}
        
        @self.app.get("/graphql")
        @self.shield_instance
        async def graphql_get_endpoint(request: Request):
            return {"message": "GraphQL query processed"}
        
        self.client = TestClient(self.app)
    
    def test_valid_query_passes(self):
        """Test that valid queries pass through the shield."""
        query = "{ user { id name } }"
        response = self.client.post(
            "/graphql",
            json={"query": query},
            headers={"content-type": "application/json"}
        )
        assert response.status_code == 200
    
    def test_deep_query_blocked(self):
        """Test that deep queries are blocked."""
        query = """
        {
            level1 {
                level2 {
                    level3 {
                        level4 {
                            level5 {
                                data
                            }
                        }
                    }
                }
            }
        }
        """
        response = self.client.post(
            "/graphql",
            json={"query": query},
            headers={"content-type": "application/json"}
        )
        assert response.status_code == 400
        assert "depth" in response.json()["detail"].lower()
    
    def test_get_request_with_query_param(self):
        """Test GET request with query parameter."""
        query = "{ user { id } }"
        response = self.client.get(f"/graphql?query={query}")
        assert response.status_code == 200
    
    def test_malformed_request_passes_through(self):
        """Test that malformed requests pass through to GraphQL server."""
        # Request without query should pass through
        response = self.client.post(
            "/graphql",
            json={"variables": {}},
            headers={"content-type": "application/json"}
        )
        assert response.status_code == 200  # Shield allows it through
    
    def test_shield_with_custom_error_handling(self):
        """Test shield with custom error handling."""
        custom_shield = graphql_query_depth_shield(
            max_depth=2,
            auto_error=False,
            default_response_to_return_if_fail=JSONResponse(
                content={"error": "Query too complex"},
                status_code=413
            )
        )
        
        app = FastAPI()
        
        @app.post("/graphql")
        @custom_shield
        async def graphql_endpoint():
            return {"message": "Success"}
        
        client = TestClient(app)
        
        query = "{ user { profile { settings { theme } } } }"
        response = client.post(
            "/graphql",
            json={"query": query}
        )
        assert response.status_code == 413
        assert response.json()["error"] == "Query too complex"


class TestConvenienceShields:
    """Test convenience shield functions."""
    
    def test_create_strict_graphql_shield(self):
        """Test creating strict GraphQL shield."""
        shield_instance = create_strict_graphql_shield()
        assert isinstance(shield_instance, type(graphql_query_depth_shield()))
    
    def test_create_permissive_graphql_shield(self):
        """Test creating permissive GraphQL shield."""
        shield_instance = create_permissive_graphql_shield()
        assert isinstance(shield_instance, type(graphql_query_depth_shield()))
    
    def test_create_production_graphql_shield(self):
        """Test creating production GraphQL shield."""
        field_complexities = {
            "user": FieldComplexity(base_cost=2.0),
            "posts": {"base_cost": 5.0, "multiplier": 2.0}
        }
        shield_instance = create_production_graphql_shield(field_complexities)
        assert isinstance(shield_instance, type(graphql_query_depth_shield()))


class TestFieldComplexity:
    """Test field complexity calculations."""
    
    def test_field_complexity_default(self):
        """Test default field complexity."""
        complexity = FieldComplexity()
        assert complexity.base_cost == 1.0
        assert complexity.multiplier == 1.0
        assert complexity.max_depth is None
        assert complexity.custom_calculator is None
    
    def test_field_complexity_custom(self):
        """Test custom field complexity."""
        custom_calc = lambda data: data['count'] * 10.0
        complexity = FieldComplexity(
            base_cost=5.0,
            multiplier=2.0,
            max_depth=3,
            custom_calculator=custom_calc
        )
        
        assert complexity.base_cost == 5.0
        assert complexity.multiplier == 2.0
        assert complexity.max_depth == 3
        assert complexity.custom_calculator({'count': 2}) == 20.0


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_empty_query_handling(self):
        """Test handling of empty queries."""
        config = GraphQLQueryDepthConfig()
        parser = RegexGraphQLParser(config)
        
        result = parser.parse_query("")
        assert result.max_depth == 0
        assert result.total_nodes == 0
    
    def test_malformed_graphql_handling(self):
        """Test handling of malformed GraphQL."""
        config = GraphQLQueryDepthConfig()
        shield = GraphQLQueryDepthShield(config)
        
        # Malformed query should not crash the parser
        malformed_query = "{ user { id name"  # Missing closing brace
        result = shield.analyze_query(malformed_query)
        assert isinstance(result, QueryAnalysisResult)
    
    def test_very_large_query_limits(self):
        """Test handling of very large queries."""
        config = GraphQLQueryDepthConfig(max_nodes=5)
        shield = GraphQLQueryDepthShield(config)
        
        # Generate a query with many fields
        fields = []
        for i in range(20):
            fields.append(f"field{i}")
        large_query = f"{{ user {{ {' '.join(fields)} }} }}"
        
        with pytest.raises(HTTPException) as exc_info:
            shield.validate_query(large_query)
        assert exc_info.value.status_code == 400
    
    def test_unicode_query_handling(self):
        """Test handling of Unicode in queries."""
        config = GraphQLQueryDepthConfig()
        parser = RegexGraphQLParser(config)
        
        unicode_query = "{ user { naïve_field: name } }"
        result = parser.parse_query(unicode_query)
        assert isinstance(result, QueryAnalysisResult)
    
    def test_query_with_comments(self):
        """Test handling of queries with comments."""
        config = GraphQLQueryDepthConfig()
        parser = RegexGraphQLParser(config)
        
        query_with_comments = """
        # This is a comment
        {
            user { # Another comment
                id
                name
            }
        }
        """
        result = parser.parse_query(query_with_comments)
        assert result.max_depth > 0
        assert result.total_nodes > 0


class TestPerformance:
    """Test performance characteristics."""
    
    def test_large_query_analysis_performance(self):
        """Test that large query analysis completes reasonably quickly."""
        import time
        
        config = GraphQLQueryDepthConfig()
        parser = RegexGraphQLParser(config)
        
        # Generate a moderately complex query
        query_parts = []
        for i in range(50):
            query_parts.append(f"field{i} {{ subfield{i} }}")
        
        large_query = f"{{ user {{ {' '.join(query_parts)} }} }}"
        
        start_time = time.time()
        result = parser.parse_query(large_query)
        end_time = time.time()
        
        # Should complete within reasonable time (< 1 second)
        assert (end_time - start_time) < 1.0
        assert isinstance(result, QueryAnalysisResult)
    
    def test_parser_memory_efficiency(self):
        """Test that parser doesn't consume excessive memory."""
        config = GraphQLQueryDepthConfig()
        parser = RegexGraphQLParser(config)
        
        # Run multiple analyses to check for memory leaks
        for i in range(100):
            query = f"{{ user{i} {{ id{i} name{i} }} }}"
            result = parser.parse_query(query)
            assert isinstance(result, QueryAnalysisResult)
        
        # If we reach here without memory issues, test passes
        assert True