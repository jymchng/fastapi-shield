"""Mock objects and utilities for Database Connection Shield testing."""

import asyncio
import time
from typing import Any, Dict, List, Optional, Union
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi_shield.database_connection import (
    DatabaseConnection,
    DatabaseConnectionConfig,
    ConnectionState,
    PoolState,
    RetryStrategy,
    DatabaseType,
    ConnectionMetrics,
    QueryResult,
)


class MockDatabaseConnection(DatabaseConnection):
    """Mock database connection for testing."""
    
    def __init__(self, connection_id: str, config: DatabaseConnectionConfig, should_fail: bool = False):
        super().__init__(connection_id, config)
        self.should_fail = should_fail
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.execute_calls = 0
        self.validate_calls = 0
        self.query_history = []
        self.connection_delay = 0.01
        self.query_delay = 0.001
        self.validation_delay = 0.001
        
    async def connect(self) -> bool:
        """Mock database connection."""
        self.connect_calls += 1
        await asyncio.sleep(self.connection_delay)
        
        if self.should_fail:
            self.state = ConnectionState.INVALID
            return False
        
        self.state = ConnectionState.IDLE
        return True
    
    async def disconnect(self) -> None:
        """Mock database disconnection."""
        self.disconnect_calls += 1
        await asyncio.sleep(0.001)
        self.state = ConnectionState.CLOSED
    
    async def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> Any:
        """Mock query execution."""
        self.execute_calls += 1
        self.query_history.append({"query": query, "parameters": parameters, "timestamp": time.time()})
        
        if self.state != ConnectionState.ACTIVE:
            raise RuntimeError("Connection not active")
        
        await asyncio.sleep(self.query_delay)
        
        if self.should_fail:
            raise RuntimeError("Mock query execution failed")
        
        # Mock different query results
        if query.strip().upper().startswith('SELECT'):
            return [{"id": 1, "name": "test_data", "value": 42}]
        elif query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')):
            return {"affected_rows": 1, "last_insert_id": 123}
        elif query.strip().upper().startswith('CREATE'):
            return {"status": "table_created"}
        else:
            return {"status": "success", "message": "Query executed"}
    
    async def validate_connection(self) -> bool:
        """Mock connection validation."""
        self.validate_calls += 1
        await asyncio.sleep(self.validation_delay)
        
        if self.should_fail or self.state == ConnectionState.INVALID:
            return False
        
        return True
    
    def set_should_fail(self, should_fail: bool) -> None:
        """Set whether operations should fail."""
        self.should_fail = should_fail
    
    def set_delays(self, connection: float = 0.01, query: float = 0.001, validation: float = 0.001):
        """Set operation delays for testing."""
        self.connection_delay = connection
        self.query_delay = query
        self.validation_delay = validation


class MockConnectionPool:
    """Mock connection pool for testing."""
    
    def __init__(self, config: DatabaseConnectionConfig, should_fail: bool = False):
        self.config = config
        self.should_fail = should_fail
        self.state = PoolState.INITIALIZING
        self.connections = []
        self.metrics = ConnectionMetrics()
        self.initialize_calls = 0
        self.get_connection_calls = 0
        self.return_connection_calls = 0
        self.close_calls = 0
        
    async def initialize(self) -> None:
        """Mock pool initialization."""
        self.initialize_calls += 1
        
        if self.should_fail:
            self.state = PoolState.FAILING
            return
        
        # Create mock connections
        for i in range(self.config.min_pool_size):
            connection = MockDatabaseConnection(f"mock_conn_{i}", self.config)
            await connection.connect()
            self.connections.append(connection)
        
        self.state = PoolState.HEALTHY
        self.metrics.total_connections = len(self.connections)
    
    async def get_connection(self) -> Optional[MockDatabaseConnection]:
        """Mock getting connection from pool."""
        self.get_connection_calls += 1
        
        if self.should_fail or self.state == PoolState.FAILING:
            return None
        
        if not self.connections:
            # Create new connection if none available
            connection = MockDatabaseConnection(f"mock_conn_{len(self.connections)}", self.config)
            if await connection.connect():
                self.connections.append(connection)
            else:
                return None
        
        connection = self.connections[0]
        await connection.mark_active()
        self.metrics.active_connections += 1
        return connection
    
    async def return_connection(self, connection: MockDatabaseConnection) -> None:
        """Mock returning connection to pool."""
        self.return_connection_calls += 1
        await connection.mark_idle()
        self.metrics.active_connections = max(0, self.metrics.active_connections - 1)
    
    async def close(self) -> None:
        """Mock closing pool."""
        self.close_calls += 1
        self.state = PoolState.SHUTDOWN
        
        for connection in self.connections:
            await connection.disconnect()
        
        self.connections.clear()
    
    def get_metrics(self) -> ConnectionMetrics:
        """Get pool metrics."""
        self.metrics.total_connections = len(self.connections)
        self.metrics.last_updated = datetime.now(timezone.utc)
        return self.metrics


class MockRetryManager:
    """Mock retry manager for testing."""
    
    def __init__(self, config: DatabaseConnectionConfig):
        self.config = config
        self.calculate_delay_calls = 0
        self.should_retry_calls = 0
        
    def calculate_delay(self, attempt: int) -> float:
        """Mock delay calculation."""
        self.calculate_delay_calls += 1
        
        if self.config.retry_strategy == RetryStrategy.NONE:
            return 0.0
        elif self.config.retry_strategy == RetryStrategy.FIXED_DELAY:
            return self.config.base_retry_delay
        elif self.config.retry_strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            return min(
                self.config.base_retry_delay * (2 ** (attempt - 1)),
                self.config.max_retry_delay
            )
        else:
            return self.config.base_retry_delay
    
    def should_retry(self, attempt: int, error: Exception) -> bool:
        """Mock retry decision."""
        self.should_retry_calls += 1
        
        if attempt > self.config.max_retries:
            return False
        
        if self.config.retry_strategy == RetryStrategy.NONE:
            return False
        
        # Don't retry for certain error types
        if isinstance(error, (ValueError, TypeError)):
            return False
        
        return True


class DatabaseTestHelper:
    """Helper class for database testing scenarios."""
    
    @staticmethod
    def create_test_config(**overrides) -> DatabaseConnectionConfig:
        """Create a test database configuration."""
        defaults = {
            "connection_string": "mock://test:test@localhost:5432/testdb",
            "database_type": DatabaseType.GENERIC,
            "min_pool_size": 2,
            "max_pool_size": 5,
            "query_timeout": 1.0,
            "connection_timeout": 1.0,
            "pool_timeout": 1.0,
            "max_retries": 2,
            "base_retry_delay": 0.1,
            "max_retry_delay": 1.0,
            "enable_health_checks": True,
            "health_check_interval": 0.5,
            "health_check_timeout": 0.5
        }
        defaults.update(overrides)
        return DatabaseConnectionConfig(**defaults)
    
    @staticmethod
    def create_mock_query_result(
        success: bool = True,
        data: Optional[Any] = None,
        error: Optional[Exception] = None,
        execution_time: float = 0.01,
        retries_used: int = 0
    ) -> QueryResult[Any]:
        """Create a mock query result."""
        return QueryResult(
            success=success,
            data=data or {"mock": "data"},
            error=error,
            execution_time=execution_time,
            retries_used=retries_used,
            connection_id="mock_connection_123",
            query_hash="mock_hash_abc123"
        )
    
    @staticmethod
    def create_test_queries() -> Dict[str, str]:
        """Create test queries for different operations."""
        return {
            "select": "SELECT * FROM users WHERE id = ?",
            "insert": "INSERT INTO users (name, email) VALUES (?, ?)",
            "update": "UPDATE users SET name = ? WHERE id = ?",
            "delete": "DELETE FROM users WHERE id = ?",
            "create_table": "CREATE TABLE test_table (id INT PRIMARY KEY, name VARCHAR(100))",
            "health_check": "SELECT 1",
            "slow_query": "SELECT * FROM large_table ORDER BY created_at LIMIT 1000000",
            "invalid_syntax": "SELCT * FROM users",  # Intentional typo
            "complex_join": """
                SELECT u.name, p.title, c.content 
                FROM users u 
                JOIN posts p ON u.id = p.user_id 
                LEFT JOIN comments c ON p.id = c.post_id 
                WHERE u.created_at > ?
            """
        }
    
    @staticmethod
    def simulate_connection_failure() -> Exception:
        """Simulate a connection failure."""
        return ConnectionError("Connection to database failed")
    
    @staticmethod
    def simulate_query_timeout() -> Exception:
        """Simulate a query timeout."""
        return asyncio.TimeoutError("Query execution timed out")
    
    @staticmethod
    def simulate_syntax_error() -> Exception:
        """Simulate a SQL syntax error."""
        return ValueError("SQL syntax error near 'SELCT'")


class MockDatabaseDriver:
    """Mock database driver for testing different database types."""
    
    def __init__(self, db_type: DatabaseType, should_fail: bool = False):
        self.db_type = db_type
        self.should_fail = should_fail
        self.connections = {}
        self.connection_count = 0
        
    async def create_connection(self, connection_string: str) -> str:
        """Create a new connection and return connection ID."""
        if self.should_fail:
            raise ConnectionError(f"Failed to connect to {self.db_type}")
        
        self.connection_count += 1
        connection_id = f"{self.db_type}_conn_{self.connection_count}"
        self.connections[connection_id] = {
            "created_at": time.time(),
            "query_count": 0,
            "last_query": None
        }
        return connection_id
    
    async def execute_query(self, connection_id: str, query: str, params: Optional[Dict] = None) -> Any:
        """Execute query on connection."""
        if connection_id not in self.connections:
            raise RuntimeError("Invalid connection ID")
        
        if self.should_fail:
            raise RuntimeError(f"Query failed on {self.db_type}")
        
        conn_info = self.connections[connection_id]
        conn_info["query_count"] += 1
        conn_info["last_query"] = query
        
        # Return database-specific mock results
        if self.db_type == DatabaseType.POSTGRESQL:
            return {"rows": [{"id": 1, "data": "postgresql_data"}], "row_count": 1}
        elif self.db_type == DatabaseType.MYSQL:
            return {"rows": [{"id": 1, "data": "mysql_data"}], "affected_rows": 1}
        elif self.db_type == DatabaseType.REDIS:
            return {"value": "redis_value", "type": "string"}
        elif self.db_type == DatabaseType.MONGODB:
            return {"documents": [{"_id": "507f1f77bcf86cd799439011", "data": "mongo_data"}]}
        else:
            return {"result": "generic_result", "status": "success"}
    
    async def close_connection(self, connection_id: str) -> None:
        """Close connection."""
        if connection_id in self.connections:
            del self.connections[connection_id]
    
    def get_connection_info(self, connection_id: str) -> Optional[Dict]:
        """Get connection information."""
        return self.connections.get(connection_id)


class ConnectionPoolTestScenarios:
    """Pre-defined test scenarios for connection pool testing."""
    
    @staticmethod
    async def pool_exhaustion_scenario(pool_size: int = 2, concurrent_requests: int = 5) -> Dict[str, Any]:
        """Simulate pool exhaustion scenario."""
        results = {
            "successful_connections": 0,
            "failed_connections": 0,
            "timeout_errors": 0,
            "execution_times": []
        }
        
        async def get_connection():
            start_time = time.time()
            try:
                # Simulate getting connection with timeout
                await asyncio.sleep(0.1)  # Simulate connection acquisition time
                results["successful_connections"] += 1
            except asyncio.TimeoutError:
                results["timeout_errors"] += 1
            except Exception:
                results["failed_connections"] += 1
            finally:
                results["execution_times"].append(time.time() - start_time)
        
        # Execute concurrent requests
        tasks = [get_connection() for _ in range(concurrent_requests)]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    @staticmethod
    async def connection_recovery_scenario() -> Dict[str, Any]:
        """Simulate connection recovery after failures."""
        return {
            "initial_failures": 3,
            "recovery_attempts": 5,
            "final_success_rate": 0.8,
            "recovery_time": 2.5
        }
    
    @staticmethod
    async def health_check_scenario(healthy_connections: int, total_connections: int) -> Dict[str, Any]:
        """Simulate health check scenario."""
        health_rate = healthy_connections / total_connections if total_connections > 0 else 0
        
        return {
            "healthy_connections": healthy_connections,
            "total_connections": total_connections,
            "health_rate": health_rate,
            "pool_status": "healthy" if health_rate > 0.7 else "degraded" if health_rate > 0.3 else "failing"
        }


def create_database_shield_test_suite():
    """Create a comprehensive test suite configuration."""
    return {
        "configurations": [
            DatabaseTestHelper.create_test_config(),
            DatabaseTestHelper.create_test_config(database_type=DatabaseType.POSTGRESQL, max_pool_size=20),
            DatabaseTestHelper.create_test_config(database_type=DatabaseType.MYSQL, retry_strategy=RetryStrategy.FIXED_DELAY),
            DatabaseTestHelper.create_test_config(database_type=DatabaseType.REDIS, enable_health_checks=False),
        ],
        "test_scenarios": [
            "basic_operations",
            "connection_pooling",
            "retry_logic",
            "health_checks",
            "error_handling",
            "performance_testing",
            "concurrent_access",
            "pool_exhaustion",
            "connection_recovery",
            "timeout_handling"
        ],
        "mock_data": {
            "connection_strings": {
                DatabaseType.POSTGRESQL: "postgresql://test:test@localhost:5432/testdb",
                DatabaseType.MYSQL: "mysql://test:test@localhost:3306/testdb",
                DatabaseType.REDIS: "redis://localhost:6379/0",
                DatabaseType.MONGODB: "mongodb://localhost:27017/testdb"
            },
            "test_queries": DatabaseTestHelper.create_test_queries(),
            "error_scenarios": [
                "connection_timeout",
                "query_timeout",
                "syntax_error",
                "permission_denied",
                "database_unavailable"
            ]
        }
    }