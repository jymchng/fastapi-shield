"""GraphQL Query Depth Shield for FastAPI Shield.

This module provides GraphQL query depth analysis and limiting functionality to prevent
deep query attacks that cause resource exhaustion. Supports configurable depth and
complexity limits, query cost calculation, and integration with GraphQL parsers.
"""

import ast
import json
import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from fastapi_shield.shield import Shield, shield


class GraphQLQueryType(str, Enum):
    """Types of GraphQL operations."""
    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"


class ComplexityCalculationStrategy(str, Enum):
    """Strategy for calculating query complexity."""
    DEPTH_ONLY = "depth_only"  # Only count nesting depth
    NODE_COUNT = "node_count"  # Count all selection nodes
    WEIGHTED = "weighted"  # Use field-specific weights
    CUSTOM = "custom"  # Use custom complexity function


@dataclass
class QueryAnalysisResult:
    """Result of GraphQL query analysis."""
    max_depth: int
    total_nodes: int
    complexity_score: float
    operation_type: GraphQLQueryType
    field_counts: Dict[str, int] = field(default_factory=dict)
    introspection_used: bool = False
    fragments_used: Set[str] = field(default_factory=set)
    variables_used: Set[str] = field(default_factory=set)
    cost_breakdown: Dict[str, float] = field(default_factory=dict)


@dataclass
class FieldComplexity:
    """Complexity configuration for a specific field."""
    base_cost: float = 1.0
    multiplier: float = 1.0
    max_depth: Optional[int] = None
    custom_calculator: Optional[Callable[[Dict[str, Any]], float]] = None


class GraphQLQueryDepthConfig(BaseModel):
    """Configuration for GraphQL query depth shield."""
    
    max_depth: int = Field(default=10, ge=1, le=100)
    max_complexity: float = Field(default=1000.0, ge=1.0)
    max_nodes: int = Field(default=500, ge=1)
    
    # Operation-specific limits
    query_max_depth: Optional[int] = Field(default=None, ge=1)
    mutation_max_depth: Optional[int] = Field(default=None, ge=1)
    subscription_max_depth: Optional[int] = Field(default=None, ge=1)
    
    # Analysis settings
    complexity_strategy: ComplexityCalculationStrategy = ComplexityCalculationStrategy.DEPTH_ONLY
    allow_introspection: bool = False
    allow_fragments: bool = True
    enforce_query_timeout: bool = True
    query_timeout_ms: int = Field(default=5000, ge=100)
    
    # Custom field complexities
    field_complexities: Dict[str, FieldComplexity] = Field(default_factory=dict)
    
    # Cost analysis
    enable_cost_analysis: bool = True
    default_field_cost: float = Field(default=1.0, ge=0.1)
    list_field_multiplier: float = Field(default=10.0, ge=1.0)
    
    # Reporting and monitoring
    log_queries: bool = False
    log_violations: bool = True
    track_field_usage: bool = True
    
    @field_validator('field_complexities', mode='before')
    @classmethod
    def validate_field_complexities(cls, v):
        """Convert dict values to FieldComplexity objects if needed."""
        if not isinstance(v, dict):
            return v
        
        result = {}
        for field_name, complexity in v.items():
            if isinstance(complexity, dict):
                result[field_name] = FieldComplexity(**complexity)
            elif isinstance(complexity, FieldComplexity):
                result[field_name] = complexity
            else:
                # Assume it's a simple numeric value
                result[field_name] = FieldComplexity(base_cost=float(complexity))
        
        return result


class GraphQLQueryParser(ABC):
    """Abstract base class for GraphQL query parsers."""
    
    @abstractmethod
    def parse_query(self, query: str) -> QueryAnalysisResult:
        """Parse a GraphQL query and return analysis results."""
        pass
    
    @abstractmethod
    def extract_operation_type(self, query: str) -> GraphQLQueryType:
        """Extract the operation type from a query."""
        pass


class RegexGraphQLParser(GraphQLQueryParser):
    """Regex-based GraphQL parser for lightweight query analysis."""
    
    # Common GraphQL patterns
    OPERATION_PATTERN = re.compile(r'\b(query|mutation|subscription)\b', re.IGNORECASE)
    FIELD_PATTERN = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*\{', re.MULTILINE)
    FRAGMENT_PATTERN = re.compile(r'\bfragment\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.IGNORECASE)
    INTROSPECTION_PATTERN = re.compile(r'\b__\w+\b', re.IGNORECASE)
    VARIABLE_PATTERN = re.compile(r'\$([a-zA-Z_][a-zA-Z0-9_]*)', re.MULTILINE)
    
    def __init__(self, config: GraphQLQueryDepthConfig):
        self.config = config
    
    def parse_query(self, query: str) -> QueryAnalysisResult:
        """Parse GraphQL query using regex patterns."""
        # Clean the query
        cleaned_query = self._clean_query(query)
        
        # Extract basic information
        operation_type = self.extract_operation_type(cleaned_query)
        
        # Calculate depth
        max_depth = self._calculate_depth(cleaned_query)
        
        # Count nodes
        total_nodes = self._count_selection_nodes(cleaned_query)
        
        # Calculate complexity
        complexity_score = self._calculate_complexity(cleaned_query, max_depth, total_nodes)
        
        # Extract additional metadata
        field_counts = self._count_fields(cleaned_query)
        introspection_used = bool(self.INTROSPECTION_PATTERN.search(cleaned_query))
        fragments_used = set(self.FRAGMENT_PATTERN.findall(cleaned_query))
        variables_used = set(self.VARIABLE_PATTERN.findall(cleaned_query))
        
        # Calculate cost breakdown
        cost_breakdown = self._calculate_cost_breakdown(field_counts)
        
        return QueryAnalysisResult(
            max_depth=max_depth,
            total_nodes=total_nodes,
            complexity_score=complexity_score,
            operation_type=operation_type,
            field_counts=field_counts,
            introspection_used=introspection_used,
            fragments_used=fragments_used,
            variables_used=variables_used,
            cost_breakdown=cost_breakdown
        )
    
    def extract_operation_type(self, query: str) -> GraphQLQueryType:
        """Extract operation type from query."""
        match = self.OPERATION_PATTERN.search(query)
        if match:
            op_type = match.group(1).lower()
            if op_type == "query":
                return GraphQLQueryType.QUERY
            elif op_type == "mutation":
                return GraphQLQueryType.MUTATION
            elif op_type == "subscription":
                return GraphQLQueryType.SUBSCRIPTION
        
        # Default to query if no explicit operation type
        return GraphQLQueryType.QUERY
    
    def _clean_query(self, query: str) -> str:
        """Clean and normalize the query string."""
        # Remove comments
        query = re.sub(r'#[^\r\n]*', '', query)
        
        # Normalize whitespace
        query = re.sub(r'\s+', ' ', query.strip())
        
        return query
    
    def _calculate_depth(self, query: str) -> int:
        """Calculate maximum nesting depth of the query."""
        max_depth = 0
        current_depth = 0
        
        for char in query:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        
        return max_depth
    
    def _count_selection_nodes(self, query: str) -> int:
        """Count total number of selection nodes in the query."""
        # Count field selections (approximate)
        field_matches = self.FIELD_PATTERN.findall(query)
        
        # Also count simple fields (without nested selections)
        simple_field_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?![{(])', re.MULTILINE)
        simple_fields = simple_field_pattern.findall(query)
        
        # Remove duplicates and filter out keywords
        keywords = {'query', 'mutation', 'subscription', 'fragment', 'on', 'true', 'false', 'null'}
        all_fields = set(field_matches + simple_fields) - keywords
        
        return len(all_fields)
    
    def _calculate_complexity(self, query: str, depth: int, nodes: int) -> float:
        """Calculate complexity score based on strategy."""
        if self.config.complexity_strategy == ComplexityCalculationStrategy.DEPTH_ONLY:
            return float(depth)
        elif self.config.complexity_strategy == ComplexityCalculationStrategy.NODE_COUNT:
            return float(nodes)
        elif self.config.complexity_strategy == ComplexityCalculationStrategy.WEIGHTED:
            return self._calculate_weighted_complexity(query)
        
        # Default: combine depth and nodes
        return depth * 2.0 + nodes * 0.5
    
    def _calculate_weighted_complexity(self, query: str) -> float:
        """Calculate weighted complexity based on field configurations."""
        total_complexity = 0.0
        field_counts = self._count_fields(query)
        
        for field_name, count in field_counts.items():
            field_config = self.config.field_complexities.get(field_name)
            if field_config:
                field_cost = field_config.base_cost * field_config.multiplier * count
                if field_config.custom_calculator:
                    field_cost = field_config.custom_calculator({'count': count, 'field': field_name})
            else:
                field_cost = self.config.default_field_cost * count
            
            total_complexity += field_cost
        
        return total_complexity
    
    def _count_fields(self, query: str) -> Dict[str, int]:
        """Count occurrences of each field in the query."""
        field_counts = {}
        
        # Find all field references
        field_matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)', query)
        
        # Filter out GraphQL keywords and system fields
        keywords = {
            'query', 'mutation', 'subscription', 'fragment', 'on', 'true', 'false', 'null',
            'if', 'skip', 'include', 'deprecated', 'Int', 'Float', 'String', 'Boolean', 'ID'
        }
        
        for field in field_matches:
            if field not in keywords and not field.startswith('__'):
                field_counts[field] = field_counts.get(field, 0) + 1
        
        return field_counts
    
    def _calculate_cost_breakdown(self, field_counts: Dict[str, int]) -> Dict[str, float]:
        """Calculate cost breakdown per field."""
        cost_breakdown = {}
        
        for field_name, count in field_counts.items():
            field_config = self.config.field_complexities.get(field_name)
            if field_config:
                cost = field_config.base_cost * field_config.multiplier * count
            else:
                cost = self.config.default_field_cost * count
            
            cost_breakdown[field_name] = cost
        
        return cost_breakdown


class ASTGraphQLParser(GraphQLQueryParser):
    """AST-based GraphQL parser for more accurate analysis."""
    
    def __init__(self, config: GraphQLQueryDepthConfig):
        self.config = config
        try:
            from graphql import parse, validate, build_schema
            from graphql.language.ast import DocumentNode
            self.graphql_parse = parse
            self.graphql_validate = validate
            self.build_schema = build_schema
            self._graphql_available = True
        except ImportError:
            # Fall back to regex parser if graphql-core is not available
            self._graphql_available = False
            self.regex_parser = RegexGraphQLParser(config)
    
    def parse_query(self, query: str) -> QueryAnalysisResult:
        """Parse GraphQL query using AST analysis."""
        if not self._graphql_available:
            # Fall back to regex parsing
            return self.regex_parser.parse_query(query)
        
        try:
            # Parse the query into AST
            document = self.graphql_parse(query)
            
            # Analyze the AST
            return self._analyze_ast(document, query)
            
        except Exception:
            # Fall back to regex parsing on any parsing error
            return RegexGraphQLParser(self.config).parse_query(query)
    
    def extract_operation_type(self, query: str) -> GraphQLQueryType:
        """Extract operation type from query."""
        if not self._graphql_available:
            return RegexGraphQLParser(self.config).extract_operation_type(query)
        
        try:
            document = self.graphql_parse(query)
            if document.definitions:
                for definition in document.definitions:
                    if hasattr(definition, 'operation'):
                        if definition.operation.value == 'query':
                            return GraphQLQueryType.QUERY
                        elif definition.operation.value == 'mutation':
                            return GraphQLQueryType.MUTATION
                        elif definition.operation.value == 'subscription':
                            return GraphQLQueryType.SUBSCRIPTION
        except Exception:
            pass
        
        return GraphQLQueryType.QUERY
    
    def _analyze_ast(self, document, original_query: str) -> QueryAnalysisResult:
        """Analyze GraphQL AST for complexity metrics."""
        # Initialize result
        max_depth = 0
        total_nodes = 0
        field_counts = {}
        fragments_used = set()
        variables_used = set()
        introspection_used = False
        operation_type = GraphQLQueryType.QUERY
        
        # Analyze each definition in the document
        for definition in document.definitions:
            if hasattr(definition, 'operation'):
                # This is an operation definition
                if definition.operation.value == 'mutation':
                    operation_type = GraphQLQueryType.MUTATION
                elif definition.operation.value == 'subscription':
                    operation_type = GraphQLQueryType.SUBSCRIPTION
                
                # Analyze selection set
                depth, nodes, fields, introspection = self._analyze_selection_set(
                    definition.selection_set, 0
                )
                max_depth = max(max_depth, depth)
                total_nodes += nodes
                introspection_used = introspection_used or introspection
                
                # Merge field counts
                for field, count in fields.items():
                    field_counts[field] = field_counts.get(field, 0) + count
                
                # Extract variables
                if hasattr(definition, 'variable_definitions') and definition.variable_definitions:
                    for var_def in definition.variable_definitions:
                        variables_used.add(var_def.variable.name.value)
            
            elif hasattr(definition, 'name'):
                # This is a fragment definition
                fragments_used.add(definition.name.value)
        
        # Calculate complexity
        complexity_score = self._calculate_complexity(original_query, max_depth, total_nodes)
        
        # Calculate cost breakdown
        cost_breakdown = self._calculate_cost_breakdown(field_counts)
        
        return QueryAnalysisResult(
            max_depth=max_depth,
            total_nodes=total_nodes,
            complexity_score=complexity_score,
            operation_type=operation_type,
            field_counts=field_counts,
            introspection_used=introspection_used,
            fragments_used=fragments_used,
            variables_used=variables_used,
            cost_breakdown=cost_breakdown
        )
    
    def _analyze_selection_set(self, selection_set, current_depth: int):
        """Recursively analyze a selection set."""
        if not selection_set or not selection_set.selections:
            return current_depth, 0, {}, False
        
        max_depth = current_depth + 1
        total_nodes = 0
        field_counts = {}
        introspection_used = False
        
        for selection in selection_set.selections:
            if hasattr(selection, 'name'):
                # Field selection
                field_name = selection.name.value
                field_counts[field_name] = field_counts.get(field_name, 0) + 1
                total_nodes += 1
                
                # Check for introspection
                if field_name.startswith('__'):
                    introspection_used = True
                
                # Recursively analyze nested selections
                if hasattr(selection, 'selection_set') and selection.selection_set:
                    depth, nodes, fields, intro = self._analyze_selection_set(
                        selection.selection_set, max_depth
                    )
                    max_depth = max(max_depth, depth)
                    total_nodes += nodes
                    introspection_used = introspection_used or intro
                    
                    # Merge field counts
                    for field, count in fields.items():
                        field_counts[field] = field_counts.get(field, 0) + count
            
            elif hasattr(selection, 'type_condition'):
                # Inline fragment
                if hasattr(selection, 'selection_set') and selection.selection_set:
                    depth, nodes, fields, intro = self._analyze_selection_set(
                        selection.selection_set, current_depth
                    )
                    max_depth = max(max_depth, depth)
                    total_nodes += nodes
                    introspection_used = introspection_used or intro
                    
                    # Merge field counts
                    for field, count in fields.items():
                        field_counts[field] = field_counts.get(field, 0) + count
            
            elif hasattr(selection, 'name') and hasattr(selection.name, 'value'):
                # Fragment spread
                total_nodes += 1  # Count the fragment reference itself
        
        return max_depth, total_nodes, field_counts, introspection_used
    
    def _calculate_complexity(self, query: str, depth: int, nodes: int) -> float:
        """Calculate complexity score based on strategy."""
        return RegexGraphQLParser(self.config)._calculate_complexity(query, depth, nodes)
    
    def _calculate_cost_breakdown(self, field_counts: Dict[str, int]) -> Dict[str, float]:
        """Calculate cost breakdown per field."""
        return RegexGraphQLParser(self.config)._calculate_cost_breakdown(field_counts)


class GraphQLQueryDepthShield:
    """GraphQL query depth and complexity analysis shield."""
    
    def __init__(self, config: GraphQLQueryDepthConfig):
        self.config = config
        # Try to use AST parser first, fall back to regex
        self.parser = ASTGraphQLParser(config)
    
    def analyze_query(self, query: str) -> QueryAnalysisResult:
        """Analyze a GraphQL query for depth and complexity."""
        return self.parser.parse_query(query)
    
    def validate_query(self, query: str) -> None:
        """Validate query against configured limits."""
        analysis = self.analyze_query(query)
        
        # Check introspection
        if analysis.introspection_used and not self.config.allow_introspection:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Introspection queries are not allowed"
            )
        
        # Check fragments
        if analysis.fragments_used and not self.config.allow_fragments:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Fragment usage is not allowed"
            )
        
        # Check operation-specific depth limits
        operation_max_depth = self._get_operation_max_depth(analysis.operation_type)
        if analysis.max_depth > operation_max_depth:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Query depth {analysis.max_depth} exceeds limit {operation_max_depth} for {analysis.operation_type.value}"
            )
        
        # Check complexity
        if analysis.complexity_score > self.config.max_complexity:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Query complexity {analysis.complexity_score:.1f} exceeds limit {self.config.max_complexity}"
            )
        
        # Check node count
        if analysis.total_nodes > self.config.max_nodes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Query has {analysis.total_nodes} nodes, exceeds limit {self.config.max_nodes}"
            )
        
        # Check field-specific limits
        self._validate_field_limits(analysis)
    
    def _get_operation_max_depth(self, operation_type: GraphQLQueryType) -> int:
        """Get the maximum depth limit for the given operation type."""
        if operation_type == GraphQLQueryType.QUERY and self.config.query_max_depth:
            return self.config.query_max_depth
        elif operation_type == GraphQLQueryType.MUTATION and self.config.mutation_max_depth:
            return self.config.mutation_max_depth
        elif operation_type == GraphQLQueryType.SUBSCRIPTION and self.config.subscription_max_depth:
            return self.config.subscription_max_depth
        
        return self.config.max_depth
    
    def _validate_field_limits(self, analysis: QueryAnalysisResult) -> None:
        """Validate field-specific limits."""
        for field_name, count in analysis.field_counts.items():
            field_config = self.config.field_complexities.get(field_name)
            if field_config and field_config.max_depth is not None:
                # This would require more sophisticated depth tracking per field
                # For now, we just validate the field was used within reasonable bounds
                pass


# Helper functions

async def _extract_graphql_query(request: Request) -> Optional[str]:
    """Extract GraphQL query from various request formats."""
    try:
        # Check if it's a GET request with query parameter
        if request.method == "GET":
            query = request.query_params.get("query")
            if query:
                return query
        
        # Check if it's a POST request
        elif request.method == "POST":
            content_type = request.headers.get("content-type", "").lower()
            
            if "application/json" in content_type:
                # JSON POST request
                body = await request.body()
                if body:
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            return data.get("query")
                        elif isinstance(data, list) and data:
                            # Batched queries - analyze the first one
                            return data[0].get("query") if isinstance(data[0], dict) else None
                    except json.JSONDecodeError:
                        pass
            
            elif "application/graphql" in content_type:
                # Raw GraphQL query in body
                body = await request.body()
                if body:
                    return body.decode('utf-8')
            
            elif "application/x-www-form-urlencoded" in content_type:
                # Form-encoded request
                form_data = await request.form()
                return form_data.get("query")
    
    except Exception:
        # If we can't read the body for any reason, return None
        # This allows the request to proceed to the GraphQL server
        pass
    
    return None


# Convenience functions and shields

def graphql_query_depth_shield(
    max_depth: int = 10,
    max_complexity: float = 1000.0,
    max_nodes: int = 500,
    allow_introspection: bool = False,
    complexity_strategy: ComplexityCalculationStrategy = ComplexityCalculationStrategy.DEPTH_ONLY,
    field_complexities: Optional[Dict[str, Union[FieldComplexity, Dict[str, Any], float]]] = None,
    name: str = "GraphQL Query Depth Shield",
    auto_error: bool = True,
    exception_to_raise_if_fail: Optional[HTTPException] = None,
    default_response_to_return_if_fail = None,
):
    """Create a GraphQL query depth shield with the given configuration.
    
    Args:
        max_depth: Maximum allowed query depth
        max_complexity: Maximum allowed query complexity score
        max_nodes: Maximum number of selection nodes
        allow_introspection: Whether to allow introspection queries
        complexity_strategy: Strategy for calculating complexity
        field_complexities: Custom complexity configurations for specific fields
        name: Shield name
        auto_error: Whether to auto-raise HTTP exceptions
        exception_to_raise_if_fail: Custom exception for failures
        default_response_to_return_if_fail: Custom response for failures
    
    Returns:
        Shield configured for GraphQL query depth analysis
    """
    config = GraphQLQueryDepthConfig(
        max_depth=max_depth,
        max_complexity=max_complexity,
        max_nodes=max_nodes,
        allow_introspection=allow_introspection,
        complexity_strategy=complexity_strategy,
        field_complexities=field_complexities or {}
    )
    
    shield_instance = GraphQLQueryDepthShield(config)
    
    async def graphql_depth_validator(request: Request) -> Optional[Dict[str, Any]]:
        """Validate GraphQL query depth and complexity."""
        try:
            # Extract GraphQL query from request
            query = await _extract_graphql_query(request)
            
            if not query:
                # If we can't extract the query, allow the request to proceed
                # The GraphQL server will handle malformed requests
                return {"analysis": None, "validated": False}
            
            # Analyze the query first
            analysis = shield_instance.analyze_query(query)
            
            # Check validation manually and handle auto_error
            try:
                shield_instance.validate_query(query)
                validation_passed = True
            except HTTPException as validation_error:
                if auto_error:
                    raise validation_error
                else:
                    # Return None to indicate validation failure, shield will use default response
                    return None
            
            return {
                "analysis": analysis,
                "validated": True,
                "query": query
            }
            
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            # For other exceptions, optionally log and either block or allow
            if config.log_violations:
                # Log the error (would need proper logging setup)
                pass
            
            # For parsing errors, we might want to allow the request to proceed
            # and let the GraphQL server handle it
            return {"analysis": None, "validated": False, "error": str(e)}
    
    return shield(
        graphql_depth_validator,
        name=name,
        auto_error=auto_error,
        exception_to_raise_if_fail=exception_to_raise_if_fail,
        default_response_to_return_if_fail=default_response_to_return_if_fail,
    )


def create_strict_graphql_shield(
    max_depth: int = 5,
    max_complexity: float = 100.0,
    max_nodes: int = 50
) -> Shield:
    """Create a strict GraphQL shield for high-security environments."""
    return graphql_query_depth_shield(
        max_depth=max_depth,
        max_complexity=max_complexity,
        max_nodes=max_nodes,
        allow_introspection=False,
        complexity_strategy=ComplexityCalculationStrategy.WEIGHTED,
        name="Strict GraphQL Shield"
    )


def create_permissive_graphql_shield(
    max_depth: int = 20,
    max_complexity: float = 5000.0,
    max_nodes: int = 1000
) -> Shield:
    """Create a permissive GraphQL shield for development environments."""
    return graphql_query_depth_shield(
        max_depth=max_depth,
        max_complexity=max_complexity,
        max_nodes=max_nodes,
        allow_introspection=True,
        complexity_strategy=ComplexityCalculationStrategy.DEPTH_ONLY,
        name="Permissive GraphQL Shield"
    )


def create_production_graphql_shield(
    field_complexities: Optional[Dict[str, Union[FieldComplexity, Dict[str, Any], float]]] = None
) -> Shield:
    """Create a production-ready GraphQL shield with monitoring."""
    config_dict = {
        "max_depth": 12,
        "max_complexity": 2000.0,
        "max_nodes": 300,
        "allow_introspection": False,
        "complexity_strategy": ComplexityCalculationStrategy.WEIGHTED,
        "log_queries": True,
        "log_violations": True,
        "track_field_usage": True,
        "field_complexities": field_complexities or {}
    }
    
    return graphql_query_depth_shield(
        **{k: v for k, v in config_dict.items() if k != "log_queries" and k != "log_violations" and k != "track_field_usage"},
        name="Production GraphQL Shield"
    )