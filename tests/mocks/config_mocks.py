"""Mock classes and utilities for testing the Shield Configuration Management system."""

import asyncio
import json
import tempfile
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Tuple
from unittest.mock import Mock, AsyncMock, MagicMock

from fastapi_shield.config import ConfigLoader, ConfigSource


class MockConfigLoader(ConfigLoader):
    """Mock configuration loader for testing."""
    
    def __init__(self, source_config: Dict[str, Any]):
        super().__init__(source_config)
        self.config_data = source_config.get('data', {})
        self.load_calls = 0
        self.save_calls = 0
        self.watch_calls = 0
        self.should_fail_load = source_config.get('should_fail_load', False)
        self.should_fail_save = source_config.get('should_fail_save', False)
        self.load_delay = source_config.get('load_delay', 0)
        self.save_delay = source_config.get('save_delay', 0)
        self.watch_callback = None
        self.supports_watching = source_config.get('supports_watch', True)
        self.supports_saving = source_config.get('supports_save', True)
    
    async def load(self) -> Dict[str, Any]:
        """Mock load configuration."""
        self.load_calls += 1
        
        if self.load_delay > 0:
            await asyncio.sleep(self.load_delay)
        
        if self.should_fail_load:
            raise Exception("Mock load failure")
        
        return self.config_data.copy()
    
    async def save(self, config: Dict[str, Any]) -> bool:
        """Mock save configuration."""
        self.save_calls += 1
        
        if self.save_delay > 0:
            await asyncio.sleep(self.save_delay)
        
        if self.should_fail_save:
            return False
        
        self.config_data = config.copy()
        return True
    
    async def watch(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Mock watch for configuration changes."""
        self.watch_calls += 1
        self.watch_callback = callback
    
    def supports_watch(self) -> bool:
        """Check if loader supports watching."""
        return self.supports_watching
    
    def supports_save(self) -> bool:
        """Check if loader supports saving."""
        return self.supports_saving
    
    def trigger_change(self, new_config: Dict[str, Any]):
        """Trigger a configuration change event."""
        if self.watch_callback:
            self.watch_callback(new_config)
    
    def update_config(self, updates: Dict[str, Any]):
        """Update the mock configuration data."""
        self.config_data.update(updates)
    
    def reset_counters(self):
        """Reset call counters."""
        self.load_calls = 0
        self.save_calls = 0
        self.watch_calls = 0


class MockConsulClient:
    """Mock Consul client for testing."""
    
    def __init__(self):
        self.data = {}
        self.kv = MockConsulKV(self.data)
    
    def reset(self):
        """Reset all data."""
        self.data.clear()


class MockConsulKV:
    """Mock Consul KV store."""
    
    def __init__(self, data_store: Dict[str, Any]):
        self.data = data_store
        self.index = 1
    
    def get(self, key: str, recurse: bool = False, index: int = None, wait: str = None):
        """Mock get from Consul KV."""
        if recurse:
            # Return all keys with the prefix
            matching_items = []
            for k, v in self.data.items():
                if k.startswith(key):
                    matching_items.append({
                        'Key': k,
                        'Value': v.encode('utf-8') if isinstance(v, str) else json.dumps(v).encode('utf-8')
                    })
            return self.index, matching_items
        else:
            value = self.data.get(key)
            if value is not None:
                return self.index, [{
                    'Key': key,
                    'Value': value.encode('utf-8') if isinstance(value, str) else json.dumps(value).encode('utf-8')
                }]
            return self.index, None
    
    def put(self, key: str, value: str):
        """Mock put to Consul KV."""
        self.data[key] = value
        self.index += 1
        return True


class MockRedisClient:
    """Mock Redis client for testing."""
    
    def __init__(self):
        self.data = {}
        self.keyspace_notifications = {}
        self.pubsub_instance = MockRedisPubSub(self)
    
    def get(self, key: str) -> Optional[str]:
        """Mock get from Redis."""
        return self.data.get(key)
    
    def set(self, key: str, value: str) -> bool:
        """Mock set to Redis."""
        self.data[key] = value
        # Trigger keyspace notification
        if key in self.keyspace_notifications:
            for callback in self.keyspace_notifications[key]:
                callback({'type': 'pmessage', 'channel': f'__keyspace@0__:{key}', 'data': 'set'})
        return True
    
    def delete(self, *keys: str) -> int:
        """Mock delete from Redis."""
        deleted = 0
        for key in keys:
            if key in self.data:
                del self.data[key]
                deleted += 1
        return deleted
    
    def keys(self, pattern: str) -> List[str]:
        """Mock keys pattern search."""
        import fnmatch
        return [key for key in self.data.keys() if fnmatch.fnmatch(key, pattern)]
    
    def pubsub(self) -> 'MockRedisPubSub':
        """Mock pubsub instance."""
        return self.pubsub_instance
    
    def config_set(self, name: str, value: str) -> bool:
        """Mock config set."""
        return True
    
    def reset(self):
        """Reset all data."""
        self.data.clear()
        self.keyspace_notifications.clear()


class MockRedisPubSub:
    """Mock Redis PubSub."""
    
    def __init__(self, client: MockRedisClient):
        self.client = client
        self.patterns = []
        self.messages = []
    
    def psubscribe(self, *patterns: str):
        """Mock pattern subscribe."""
        self.patterns.extend(patterns)
        for pattern in patterns:
            if pattern not in self.client.keyspace_notifications:
                self.client.keyspace_notifications[pattern] = []
    
    def get_message(self, timeout: float = None) -> Optional[Dict[str, Any]]:
        """Mock get message."""
        if self.messages:
            return self.messages.pop(0)
        return None
    
    def add_message(self, message: Dict[str, Any]):
        """Add message to queue."""
        self.messages.append(message)


class TempConfigFile:
    """Temporary configuration file for testing."""
    
    def __init__(self, content: str, suffix: str = '.yaml'):
        self.suffix = suffix
        self.content = content
        self.temp_file = None
        self.file_path = None
    
    def __enter__(self) -> str:
        """Enter context manager."""
        self.temp_file = tempfile.NamedTemporaryFile(
            mode='w', 
            suffix=self.suffix, 
            delete=False,
            encoding='utf-8'
        )
        self.temp_file.write(self.content)
        self.temp_file.close()
        self.file_path = self.temp_file.name
        return self.file_path
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        if self.file_path and os.path.exists(self.file_path):
            os.unlink(self.file_path)


class ConfigTestScenarios:
    """Pre-built configuration test scenarios."""
    
    @staticmethod
    def basic_yaml_config() -> str:
        """Basic YAML configuration."""
        return """
debug: true
timeout: 30
database:
  host: localhost
  port: 5432
  name: testdb
shields:
  - name: rate_limit
    enabled: true
    config:
      max_requests: 100
      window: 60
  - name: auth
    enabled: false
    config:
      secret_key: test123
"""
    
    @staticmethod
    def basic_json_config() -> str:
        """Basic JSON configuration."""
        return """
{
  "debug": true,
  "timeout": 30,
  "database": {
    "host": "localhost",
    "port": 5432,
    "name": "testdb"
  },
  "shields": [
    {
      "name": "rate_limit",
      "enabled": true,
      "config": {
        "max_requests": 100,
        "window": 60
      }
    },
    {
      "name": "auth",
      "enabled": false,
      "config": {
        "secret_key": "test123"
      }
    }
  ]
}
"""
    
    @staticmethod
    def basic_toml_config() -> str:
        """Basic TOML configuration."""
        return """
debug = true
timeout = 30

[database]
host = "localhost"
port = 5432
name = "testdb"

[[shields]]
name = "rate_limit"
enabled = true

[shields.config]
max_requests = 100
window = 60

[[shields]]
name = "auth"
enabled = false

[shields.config]
secret_key = "test123"
"""
    
    @staticmethod
    def env_file_config() -> str:
        """Environment file configuration."""
        return """
DEBUG=true
TIMEOUT=30
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=testdb
SHIELD_RATE_LIMIT_ENABLED=true
SHIELD_RATE_LIMIT_MAX_REQUESTS=100
SHIELD_AUTH_ENABLED=false
"""
    
    @staticmethod
    def complex_nested_config() -> Dict[str, Any]:
        """Complex nested configuration."""
        return {
            "environment": "production",
            "debug": False,
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "handlers": {
                    "file": {
                        "enabled": True,
                        "path": "/var/log/shield.log",
                        "max_size": "10MB"
                    },
                    "console": {
                        "enabled": True,
                        "level": "DEBUG"
                    }
                }
            },
            "shields": {
                "rate_limiting": {
                    "enabled": True,
                    "global": {
                        "max_requests": 1000,
                        "window_seconds": 60,
                        "burst_allowance": 50
                    },
                    "per_ip": {
                        "max_requests": 100,
                        "window_seconds": 60
                    }
                },
                "authentication": {
                    "enabled": True,
                    "jwt": {
                        "secret_key": "super-secret-key",
                        "algorithm": "HS256",
                        "expiration": 3600
                    },
                    "oauth": {
                        "providers": {
                            "google": {
                                "client_id": "google-client-id",
                                "client_secret": "google-client-secret"
                            },
                            "github": {
                                "client_id": "github-client-id",
                                "client_secret": "github-client-secret"
                            }
                        }
                    }
                },
                "cors": {
                    "enabled": True,
                    "allowed_origins": ["https://example.com", "https://app.example.com"],
                    "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
                    "allowed_headers": ["Content-Type", "Authorization"],
                    "max_age": 3600
                }
            },
            "database": {
                "primary": {
                    "host": "db1.example.com",
                    "port": 5432,
                    "database": "shield_prod",
                    "username": "shield_user",
                    "pool": {
                        "min_size": 5,
                        "max_size": 20,
                        "timeout": 30
                    }
                },
                "replica": {
                    "host": "db2.example.com",
                    "port": 5432,
                    "database": "shield_prod",
                    "username": "shield_readonly"
                }
            },
            "cache": {
                "redis": {
                    "host": "redis.example.com",
                    "port": 6379,
                    "db": 0,
                    "cluster": {
                        "enabled": True,
                        "nodes": [
                            {"host": "redis1.example.com", "port": 6379},
                            {"host": "redis2.example.com", "port": 6379},
                            {"host": "redis3.example.com", "port": 6379}
                        ]
                    }
                }
            },
            "monitoring": {
                "metrics": {
                    "enabled": True,
                    "endpoint": "/metrics",
                    "interval": 15
                },
                "health_checks": {
                    "enabled": True,
                    "endpoint": "/health",
                    "checks": ["database", "redis", "external_api"]
                }
            }
        }
    
    @staticmethod
    def environment_variables() -> Dict[str, str]:
        """Environment variables for testing."""
        return {
            "SHIELD_DEBUG": "true",
            "SHIELD_TIMEOUT": "45",
            "SHIELD_DATABASE__HOST": "env-db-host",
            "SHIELD_DATABASE__PORT": "3306",
            "SHIELD_SHIELDS__RATE_LIMIT__ENABLED": "false",
            "SHIELD_SHIELDS__RATE_LIMIT__MAX_REQUESTS": "200",
            "SHIELD_NEW_FEATURE": "enabled",
            "OTHER_VAR": "ignored",  # Should be ignored due to prefix
        }
    
    @staticmethod
    def consul_kv_data() -> Dict[str, Any]:
        """Consul KV data for testing."""
        return {
            "shield/config/debug": "false",
            "shield/config/timeout": "60",
            "shield/config/database/host": "consul-db-host",
            "shield/config/database/port": "5432",
            "shield/config/shields/rate_limit/enabled": "true",
            "shield/config/shields/rate_limit/max_requests": "500",
            "shield/config/consul_feature": "enabled"
        }
    
    @staticmethod
    def redis_kv_data() -> Dict[str, str]:
        """Redis KV data for testing."""
        return {
            "shield:config:debug": "true",
            "shield:config:timeout": "90",
            "shield:config:database:host": "redis-db-host",
            "shield:config:database:port": "5432",
            "shield:config:shields:auth:enabled": "true",
            "shield:config:shields:auth:secret": "redis-secret",
            "shield:config:redis_feature": "active"
        }


class ConfigurationTestHelper:
    """Helper for configuration testing scenarios."""
    
    @staticmethod
    def create_test_environment(env_vars: Dict[str, str]) -> Dict[str, str]:
        """Create test environment variables and return original values."""
        original_values = {}
        
        for key, value in env_vars.items():
            original_values[key] = os.environ.get(key)
            os.environ[key] = value
        
        return original_values
    
    @staticmethod
    def restore_environment(original_values: Dict[str, str]):
        """Restore original environment variables."""
        for key, value in original_values.items():
            if value is None:
                # Remove if it didn't exist before
                if key in os.environ:
                    del os.environ[key]
            else:
                # Restore original value
                os.environ[key] = value
    
    @staticmethod
    def assert_config_equal(actual: Dict[str, Any], expected: Dict[str, Any], path: str = ""):
        """Assert two configuration dictionaries are equal."""
        assert isinstance(actual, dict), f"Expected dict at {path}, got {type(actual)}"
        assert isinstance(expected, dict), f"Expected dict at {path}, got {type(expected)}"
        
        for key, expected_value in expected.items():
            current_path = f"{path}.{key}" if path else key
            
            assert key in actual, f"Missing key: {current_path}"
            
            actual_value = actual[key]
            
            if isinstance(expected_value, dict):
                ConfigurationTestHelper.assert_config_equal(actual_value, expected_value, current_path)
            else:
                assert actual_value == expected_value, f"Value mismatch at {current_path}: expected {expected_value}, got {actual_value}"
    
    @staticmethod
    def create_mock_consul_loader(data: Dict[str, Any]) -> MockConfigLoader:
        """Create mock Consul loader with test data."""
        return MockConfigLoader({
            'data': data,
            'source_type': 'consul'
        })
    
    @staticmethod
    def create_mock_redis_loader(data: Dict[str, Any]) -> MockConfigLoader:
        """Create mock Redis loader with test data."""
        return MockConfigLoader({
            'data': data,
            'source_type': 'redis'
        })
    
    @staticmethod
    def create_failing_loader(load_fail: bool = True, save_fail: bool = False) -> MockConfigLoader:
        """Create a loader that fails operations."""
        return MockConfigLoader({
            'should_fail_load': load_fail,
            'should_fail_save': save_fail,
            'data': {}
        })
    
    @staticmethod
    def create_slow_loader(load_delay: float = 0.1, save_delay: float = 0.1) -> MockConfigLoader:
        """Create a loader with delays."""
        return MockConfigLoader({
            'load_delay': load_delay,
            'save_delay': save_delay,
            'data': {'slow': 'loader'}
        })


class MockFileWatcher:
    """Mock file watcher for testing file change notifications."""
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.callbacks = []
        self.is_watching = False
    
    def add_callback(self, callback: Callable):
        """Add callback for file changes."""
        self.callbacks.append(callback)
    
    def start_watching(self):
        """Start watching the file."""
        self.is_watching = True
    
    def stop_watching(self):
        """Stop watching the file."""
        self.is_watching = False
    
    def trigger_change(self):
        """Trigger file change event."""
        if self.is_watching:
            for callback in self.callbacks:
                try:
                    callback()
                except Exception as e:
                    print(f"Error in file watcher callback: {e}")
    
    def simulate_file_change(self, new_content: str):
        """Simulate file change by writing new content."""
        if self.file_path.exists():
            with open(self.file_path, 'w') as f:
                f.write(new_content)
            self.trigger_change()


class ValidationTestCases:
    """Test cases for configuration validation."""
    
    @staticmethod
    def valid_shield_config() -> Dict[str, Any]:
        """Valid shield configuration."""
        return {
            "debug": False,
            "timeout": 30,
            "shields": [
                {
                    "name": "rate_limit",
                    "enabled": True,
                    "max_requests": 100
                }
            ],
            "database": {
                "host": "localhost",
                "port": 5432
            }
        }
    
    @staticmethod
    def invalid_configs() -> List[Tuple[Dict[str, Any], str]]:
        """List of invalid configurations with expected error descriptions."""
        return [
            # Missing required field
            ({"debug": True}, "missing shields"),
            
            # Wrong type
            ({"shields": "not-a-list", "debug": True}, "wrong type for shields"),
            
            # Invalid timeout range
            ({"shields": [], "timeout": -5}, "invalid timeout range"),
            
            # Invalid timeout range (too high)
            ({"shields": [], "timeout": 500}, "invalid timeout range"),
            
            # Wrong debug type
            ({"shields": [], "debug": "not-boolean"}, "wrong debug type"),
        ]
    
    @staticmethod
    def validation_rules_config() -> Dict[str, Any]:
        """Configuration for testing validation rules."""
        return {
            "required_field": "present",
            "string_field": "test_string",
            "number_field": 42,
            "boolean_field": True,
            "email_field": "test@example.com",
            "range_field": 50,
            "enum_field": "option_b",
            "nested": {
                "required_nested": "value"
            }
        }