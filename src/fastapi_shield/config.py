"""Shield Configuration Management for FastAPI Shield.

This module provides comprehensive configuration management including support for
multiple file formats, environment variables, runtime updates, validation,
and integration with external configuration services.
"""

import asyncio
import json
import os
import logging
import yaml
import toml
import re
from abc import ABC, abstractmethod
from collections import defaultdict, ChainMap
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable, Set, Type, Tuple
from urllib.parse import urlparse
import warnings

try:
    import consul
    CONSUL_AVAILABLE = True
except ImportError:
    CONSUL_AVAILABLE = False

try:
    import etcd3
    ETCD_AVAILABLE = True
except ImportError:
    ETCD_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class ConfigFormat(str, Enum):
    """Configuration file format enumeration."""
    JSON = "json"
    YAML = "yaml"
    YML = "yml"
    TOML = "toml"
    ENV = "env"
    INI = "ini"


class ConfigSource(str, Enum):
    """Configuration source enumeration."""
    FILE = "file"
    ENVIRONMENT = "environment"
    CONSUL = "consul"
    ETCD = "etcd"
    REDIS = "redis"
    HTTP = "http"
    DICT = "dict"
    ENV_FILE = "env_file"


class ConfigUpdateStrategy(str, Enum):
    """Configuration update strategy enumeration."""
    MERGE = "merge"
    REPLACE = "replace"
    DEEP_MERGE = "deep_merge"
    OVERLAY = "overlay"


@dataclass
class ConfigValidationRule:
    """Configuration validation rule."""
    path: str
    rule_type: str  # "required", "type", "regex", "range", "enum", "custom"
    constraint: Any = None
    message: str = ""
    severity: str = "error"  # "error", "warning", "info"
    
    def __post_init__(self):
        if not self.message:
            self.message = f"Validation failed for {self.path}: {self.rule_type}"


@dataclass
class ConfigValidationResult:
    """Configuration validation result."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)
    
    def add_error(self, message: str):
        """Add error message."""
        self.errors.append(message)
        self.valid = False
    
    def add_warning(self, message: str):
        """Add warning message."""
        self.warnings.append(message)
    
    def add_info(self, message: str):
        """Add info message."""
        self.info.append(message)
    
    def merge(self, other: 'ConfigValidationResult'):
        """Merge another validation result."""
        if not other.valid:
            self.valid = False
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        self.info.extend(other.info)


@dataclass
class ConfigChangeEvent:
    """Configuration change event."""
    source: str
    path: str
    old_value: Any
    new_value: Any
    timestamp: datetime
    change_type: str = "update"  # "update", "add", "remove"
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc)


class ConfigLoader(ABC):
    """Abstract base class for configuration loaders."""
    
    def __init__(self, source_config: Dict[str, Any]):
        self.source_config = source_config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    async def load(self) -> Dict[str, Any]:
        """Load configuration from source."""
        pass
    
    @abstractmethod
    async def watch(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Watch for configuration changes."""
        pass
    
    @abstractmethod
    async def save(self, config: Dict[str, Any]) -> bool:
        """Save configuration to source."""
        pass
    
    def supports_watch(self) -> bool:
        """Check if loader supports watching for changes."""
        return True
    
    def supports_save(self) -> bool:
        """Check if loader supports saving configuration."""
        return True


class FileConfigLoader(ConfigLoader):
    """File-based configuration loader."""
    
    def __init__(self, source_config: Dict[str, Any]):
        super().__init__(source_config)
        self.file_path = Path(source_config.get('path', 'config.yaml'))
        self.format = ConfigFormat(source_config.get('format', self._detect_format()))
        self.encoding = source_config.get('encoding', 'utf-8')
        self.watch_interval = source_config.get('watch_interval', 1.0)
        self._last_modified = None
        self._watch_task = None
    
    def _detect_format(self) -> str:
        """Detect file format from extension."""
        suffix = self.file_path.suffix.lower()
        format_map = {
            '.json': ConfigFormat.JSON,
            '.yaml': ConfigFormat.YAML,
            '.yml': ConfigFormat.YAML,
            '.toml': ConfigFormat.TOML,
            '.env': ConfigFormat.ENV,
            '.ini': ConfigFormat.INI
        }
        return format_map.get(suffix, ConfigFormat.YAML).value
    
    async def load(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if not self.file_path.exists():
            self.logger.warning(f"Configuration file not found: {self.file_path}")
            return {}
        
        try:
            with open(self.file_path, 'r', encoding=self.encoding) as f:
                content = f.read()
            
            if self.format == ConfigFormat.JSON:
                return json.loads(content)
            elif self.format in (ConfigFormat.YAML, ConfigFormat.YML):
                return yaml.safe_load(content) or {}
            elif self.format == ConfigFormat.TOML:
                return toml.loads(content)
            elif self.format == ConfigFormat.ENV:
                return self._parse_env_file(content)
            elif self.format == ConfigFormat.INI:
                import configparser
                parser = configparser.ConfigParser()
                parser.read_string(content)
                return {section: dict(parser[section]) for section in parser.sections()}
            else:
                raise ValueError(f"Unsupported format: {self.format}")
        
        except Exception as e:
            self.logger.error(f"Failed to load config from {self.file_path}: {e}")
            raise
    
    def _parse_env_file(self, content: str) -> Dict[str, Any]:
        """Parse environment file format."""
        config = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"\'')
                
                # Convert to appropriate type
                if value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                elif value.isdigit():
                    value = int(value)
                elif self._is_float(value):
                    value = float(value)
                
                config[key] = value
        
        return config
    
    def _is_float(self, value: str) -> bool:
        """Check if string represents a float."""
        try:
            float(value)
            return '.' in value
        except ValueError:
            return False
    
    async def save(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            # Ensure directory exists
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            
            if self.format == ConfigFormat.JSON:
                content = json.dumps(config, indent=2, ensure_ascii=False)
            elif self.format in (ConfigFormat.YAML, ConfigFormat.YML):
                content = yaml.dump(config, default_flow_style=False, allow_unicode=True)
            elif self.format == ConfigFormat.TOML:
                content = toml.dumps(config)
            elif self.format == ConfigFormat.ENV:
                content = self._format_env_file(config)
            else:
                raise ValueError(f"Save not supported for format: {self.format}")
            
            with open(self.file_path, 'w', encoding=self.encoding) as f:
                f.write(content)
            
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to save config to {self.file_path}: {e}")
            return False
    
    def _format_env_file(self, config: Dict[str, Any]) -> str:
        """Format configuration as environment file."""
        lines = []
        for key, value in config.items():
            if isinstance(value, (dict, list)):
                # Skip complex types in env format
                continue
            lines.append(f"{key}={value}")
        return '\n'.join(lines)
    
    async def watch(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Watch file for changes."""
        if self._watch_task:
            self._watch_task.cancel()
        
        self._watch_task = asyncio.create_task(self._watch_file(callback))
    
    async def _watch_file(self, callback: Callable[[Dict[str, Any]], None]):
        """Watch file for changes (polling-based)."""
        while True:
            try:
                if self.file_path.exists():
                    stat = self.file_path.stat()
                    modified = stat.st_mtime
                    
                    if self._last_modified is None:
                        self._last_modified = modified
                    elif modified > self._last_modified:
                        self._last_modified = modified
                        try:
                            config = await self.load()
                            callback(config)
                        except Exception as e:
                            self.logger.error(f"Error loading config during watch: {e}")
                
                await asyncio.sleep(self.watch_interval)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in file watcher: {e}")
                await asyncio.sleep(self.watch_interval)


class EnvironmentConfigLoader(ConfigLoader):
    """Environment variables configuration loader."""
    
    def __init__(self, source_config: Dict[str, Any]):
        super().__init__(source_config)
        self.prefix = source_config.get('prefix', 'SHIELD_')
        self.separator = source_config.get('separator', '__')
        self.case_sensitive = source_config.get('case_sensitive', False)
        self.type_conversion = source_config.get('type_conversion', True)
    
    async def load(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        config = {}
        
        for key, value in os.environ.items():
            if self.case_sensitive:
                if not key.startswith(self.prefix):
                    continue
                config_key = key[len(self.prefix):]
            else:
                if not key.upper().startswith(self.prefix.upper()):
                    continue
                config_key = key[len(self.prefix):]
            
            # Handle nested keys
            if self.separator in config_key:
                self._set_nested_key(config, config_key, value)
            else:
                config[config_key.lower() if not self.case_sensitive else config_key] = self._convert_type(value)
        
        return config
    
    def _set_nested_key(self, config: Dict[str, Any], key_path: str, value: str):
        """Set nested dictionary key from dotted path."""
        keys = key_path.split(self.separator)
        if not self.case_sensitive:
            keys = [k.lower() for k in keys]
        
        current = config
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = self._convert_type(value)
    
    def _convert_type(self, value: str) -> Any:
        """Convert string value to appropriate type."""
        if not self.type_conversion:
            return value
        
        # Boolean conversion
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Numeric conversion
        if value.isdigit():
            return int(value)
        
        try:
            return float(value)
        except ValueError:
            pass
        
        # List conversion (comma-separated)
        if ',' in value:
            return [self._convert_type(item.strip()) for item in value.split(',')]
        
        return value
    
    async def save(self, config: Dict[str, Any]) -> bool:
        """Save configuration to environment (not persistent)."""
        try:
            flattened = self._flatten_config(config)
            for key, value in flattened.items():
                env_key = f"{self.prefix}{key}"
                os.environ[env_key] = str(value)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save config to environment: {e}")
            return False
    
    def _flatten_config(self, config: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
        """Flatten nested configuration dictionary."""
        result = {}
        
        for key, value in config.items():
            full_key = f"{prefix}{self.separator}{key}" if prefix else key
            
            if isinstance(value, dict):
                result.update(self._flatten_config(value, full_key))
            else:
                result[full_key] = value
        
        return result
    
    async def watch(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Environment variables don't support watching."""
        self.logger.warning("Environment variable watching not supported")
    
    def supports_watch(self) -> bool:
        """Environment variables don't support watching."""
        return False


class ConsulConfigLoader(ConfigLoader):
    """Consul configuration loader."""
    
    def __init__(self, source_config: Dict[str, Any]):
        super().__init__(source_config)
        if not CONSUL_AVAILABLE:
            raise ImportError("python-consul package required for Consul support")
        
        self.host = source_config.get('host', 'localhost')
        self.port = source_config.get('port', 8500)
        self.token = source_config.get('token')
        self.key_prefix = source_config.get('key_prefix', 'shield/config')
        self.client = consul.Consul(host=self.host, port=self.port, token=self.token)
        self._watch_task = None
    
    async def load(self) -> Dict[str, Any]:
        """Load configuration from Consul."""
        try:
            index, data = self.client.kv.get(self.key_prefix, recurse=True)
            
            if not data:
                return {}
            
            config = {}
            for item in data:
                key = item['Key'][len(self.key_prefix):].lstrip('/')
                value = item['Value'].decode('utf-8') if item['Value'] else ''
                
                try:
                    # Try to parse as JSON
                    value = json.loads(value)
                except json.JSONDecodeError:
                    # Keep as string
                    pass
                
                self._set_nested_key(config, key, value)
            
            return config
        
        except Exception as e:
            self.logger.error(f"Failed to load config from Consul: {e}")
            raise
    
    def _set_nested_key(self, config: Dict[str, Any], key_path: str, value: Any):
        """Set nested dictionary key from path."""
        keys = key_path.split('/')
        current = config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    async def save(self, config: Dict[str, Any]) -> bool:
        """Save configuration to Consul."""
        try:
            flattened = self._flatten_config(config)
            
            for key, value in flattened.items():
                consul_key = f"{self.key_prefix}/{key}"
                value_str = json.dumps(value) if not isinstance(value, str) else value
                self.client.kv.put(consul_key, value_str)
            
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to save config to Consul: {e}")
            return False
    
    def _flatten_config(self, config: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
        """Flatten nested configuration dictionary."""
        result = {}
        
        for key, value in config.items():
            full_key = f"{prefix}/{key}" if prefix else key
            
            if isinstance(value, dict):
                result.update(self._flatten_config(value, full_key))
            else:
                result[full_key] = value
        
        return result
    
    async def watch(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Watch Consul for configuration changes."""
        if self._watch_task:
            self._watch_task.cancel()
        
        self._watch_task = asyncio.create_task(self._watch_consul(callback))
    
    async def _watch_consul(self, callback: Callable[[Dict[str, Any]], None]):
        """Watch Consul for changes."""
        index = None
        
        while True:
            try:
                new_index, _ = self.client.kv.get(self.key_prefix, index=index, wait='10s')
                
                if new_index and new_index != index:
                    index = new_index
                    config = await self.load()
                    callback(config)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in Consul watcher: {e}")
                await asyncio.sleep(5)


class RedisConfigLoader(ConfigLoader):
    """Redis configuration loader."""
    
    def __init__(self, source_config: Dict[str, Any]):
        super().__init__(source_config)
        if not REDIS_AVAILABLE:
            raise ImportError("redis package required for Redis support")
        
        self.host = source_config.get('host', 'localhost')
        self.port = source_config.get('port', 6379)
        self.db = source_config.get('db', 0)
        self.password = source_config.get('password')
        self.key_prefix = source_config.get('key_prefix', 'shield:config')
        self.client = redis.Redis(
            host=self.host, 
            port=self.port, 
            db=self.db, 
            password=self.password,
            decode_responses=True
        )
        self._watch_task = None
    
    async def load(self) -> Dict[str, Any]:
        """Load configuration from Redis."""
        try:
            keys = self.client.keys(f"{self.key_prefix}:*")
            
            if not keys:
                return {}
            
            config = {}
            for key in keys:
                config_key = key[len(self.key_prefix)+1:]  # Remove prefix and colon
                value = self.client.get(key)
                
                try:
                    value = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    pass
                
                self._set_nested_key(config, config_key, value)
            
            return config
        
        except Exception as e:
            self.logger.error(f"Failed to load config from Redis: {e}")
            raise
    
    def _set_nested_key(self, config: Dict[str, Any], key_path: str, value: Any):
        """Set nested dictionary key from path."""
        keys = key_path.split(':')
        current = config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    async def save(self, config: Dict[str, Any]) -> bool:
        """Save configuration to Redis."""
        try:
            # Clear existing keys
            existing_keys = self.client.keys(f"{self.key_prefix}:*")
            if existing_keys:
                self.client.delete(*existing_keys)
            
            # Save new configuration
            flattened = self._flatten_config(config)
            
            for key, value in flattened.items():
                redis_key = f"{self.key_prefix}:{key}"
                value_str = json.dumps(value) if not isinstance(value, str) else value
                self.client.set(redis_key, value_str)
            
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to save config to Redis: {e}")
            return False
    
    def _flatten_config(self, config: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
        """Flatten nested configuration dictionary."""
        result = {}
        
        for key, value in config.items():
            full_key = f"{prefix}:{key}" if prefix else key
            
            if isinstance(value, dict):
                result.update(self._flatten_config(value, full_key))
            else:
                result[full_key] = value
        
        return result
    
    async def watch(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Watch Redis for configuration changes."""
        if self._watch_task:
            self._watch_task.cancel()
        
        self._watch_task = asyncio.create_task(self._watch_redis(callback))
    
    async def _watch_redis(self, callback: Callable[[Dict[str, Any]], None]):
        """Watch Redis for changes using keyspace notifications."""
        try:
            # Enable keyspace notifications if not enabled
            self.client.config_set('notify-keyspace-events', 'KEA')
            
            pubsub = self.client.pubsub()
            pubsub.psubscribe(f"__keyspace@{self.db}__:{self.key_prefix}:*")
            
            while True:
                try:
                    message = pubsub.get_message(timeout=1.0)
                    if message and message['type'] == 'pmessage':
                        config = await self.load()
                        callback(config)
                
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Error in Redis watcher: {e}")
                    await asyncio.sleep(1)
        
        except Exception as e:
            self.logger.error(f"Failed to setup Redis watcher: {e}")


class ConfigValidator:
    """Configuration validator with schema support."""
    
    def __init__(self):
        self.rules: List[ConfigValidationRule] = []
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def add_rule(self, rule: ConfigValidationRule):
        """Add validation rule."""
        self.rules.append(rule)
    
    def required(self, path: str, message: str = "") -> 'ConfigValidator':
        """Add required field rule."""
        rule = ConfigValidationRule(
            path=path,
            rule_type="required",
            message=message or f"Field '{path}' is required"
        )
        self.add_rule(rule)
        return self
    
    def type_check(self, path: str, expected_type: Type, message: str = "") -> 'ConfigValidator':
        """Add type validation rule."""
        rule = ConfigValidationRule(
            path=path,
            rule_type="type",
            constraint=expected_type,
            message=message or f"Field '{path}' must be of type {expected_type.__name__}"
        )
        self.add_rule(rule)
        return self
    
    def regex(self, path: str, pattern: str, message: str = "") -> 'ConfigValidator':
        """Add regex validation rule."""
        rule = ConfigValidationRule(
            path=path,
            rule_type="regex",
            constraint=re.compile(pattern),
            message=message or f"Field '{path}' must match pattern {pattern}"
        )
        self.add_rule(rule)
        return self
    
    def range_check(self, path: str, min_val=None, max_val=None, message: str = "") -> 'ConfigValidator':
        """Add range validation rule."""
        rule = ConfigValidationRule(
            path=path,
            rule_type="range",
            constraint=(min_val, max_val),
            message=message or f"Field '{path}' must be between {min_val} and {max_val}"
        )
        self.add_rule(rule)
        return self
    
    def enum_check(self, path: str, allowed_values: List[Any], message: str = "") -> 'ConfigValidator':
        """Add enum validation rule."""
        rule = ConfigValidationRule(
            path=path,
            rule_type="enum",
            constraint=allowed_values,
            message=message or f"Field '{path}' must be one of {allowed_values}"
        )
        self.add_rule(rule)
        return self
    
    def custom(self, path: str, validator_func: Callable[[Any], bool], message: str = "") -> 'ConfigValidator':
        """Add custom validation rule."""
        rule = ConfigValidationRule(
            path=path,
            rule_type="custom",
            constraint=validator_func,
            message=message or f"Field '{path}' failed custom validation"
        )
        self.add_rule(rule)
        return self
    
    def validate(self, config: Dict[str, Any]) -> ConfigValidationResult:
        """Validate configuration against all rules."""
        result = ConfigValidationResult(valid=True)
        
        for rule in self.rules:
            rule_result = self._validate_rule(config, rule)
            result.merge(rule_result)
        
        return result
    
    def _validate_rule(self, config: Dict[str, Any], rule: ConfigValidationRule) -> ConfigValidationResult:
        """Validate a single rule."""
        result = ConfigValidationResult(valid=True)
        value = self._get_nested_value(config, rule.path)
        
        try:
            if rule.rule_type == "required":
                if value is None:
                    result.add_error(rule.message)
            
            elif rule.rule_type == "type":
                if value is not None and not isinstance(value, rule.constraint):
                    result.add_error(rule.message)
            
            elif rule.rule_type == "regex":
                if value is not None and isinstance(value, str):
                    if not rule.constraint.match(value):
                        result.add_error(rule.message)
            
            elif rule.rule_type == "range":
                if value is not None and isinstance(value, (int, float)):
                    min_val, max_val = rule.constraint
                    if min_val is not None and value < min_val:
                        result.add_error(rule.message)
                    if max_val is not None and value > max_val:
                        result.add_error(rule.message)
            
            elif rule.rule_type == "enum":
                if value is not None and value not in rule.constraint:
                    result.add_error(rule.message)
            
            elif rule.rule_type == "custom":
                if value is not None:
                    if not rule.constraint(value):
                        result.add_error(rule.message)
        
        except Exception as e:
            result.add_error(f"Validation error for {rule.path}: {e}")
        
        return result
    
    def _get_nested_value(self, config: Dict[str, Any], path: str) -> Any:
        """Get nested value from configuration using dot notation."""
        keys = path.split('.')
        current = config
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current


class ConfigManager:
    """Central configuration manager with multiple source support."""
    
    def __init__(self, name: str = "default"):
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        self._config: Dict[str, Any] = {}
        self._loaders: List[Tuple[ConfigLoader, int]] = []  # (loader, priority)
        self._validators: List[ConfigValidator] = []
        self._change_callbacks: List[Callable[[ConfigChangeEvent], None]] = []
        self._watch_tasks: List[asyncio.Task] = []
        self._update_strategy = ConfigUpdateStrategy.DEEP_MERGE
        self._auto_reload = True
    
    def add_source(self, source_type: ConfigSource, config: Dict[str, Any], priority: int = 100) -> 'ConfigManager':
        """Add configuration source."""
        loader = self._create_loader(source_type, config)
        self._loaders.append((loader, priority))
        # Sort loaders by priority (higher priority first)
        self._loaders.sort(key=lambda x: x[1], reverse=True)
        return self
    
    def _create_loader(self, source_type: ConfigSource, config: Dict[str, Any]) -> ConfigLoader:
        """Create appropriate configuration loader."""
        if source_type == ConfigSource.FILE:
            return FileConfigLoader(config)
        elif source_type == ConfigSource.ENVIRONMENT:
            return EnvironmentConfigLoader(config)
        elif source_type == ConfigSource.CONSUL:
            return ConsulConfigLoader(config)
        elif source_type == ConfigSource.REDIS:
            return RedisConfigLoader(config)
        else:
            raise ValueError(f"Unsupported source type: {source_type}")
    
    def add_validator(self, validator: ConfigValidator) -> 'ConfigManager':
        """Add configuration validator."""
        self._validators.append(validator)
        return self
    
    def on_change(self, callback: Callable[[ConfigChangeEvent], None]) -> 'ConfigManager':
        """Register change callback."""
        self._change_callbacks.append(callback)
        return self
    
    def set_update_strategy(self, strategy: ConfigUpdateStrategy) -> 'ConfigManager':
        """Set configuration update strategy."""
        self._update_strategy = strategy
        return self
    
    def set_auto_reload(self, enabled: bool) -> 'ConfigManager':
        """Enable/disable automatic reloading."""
        self._auto_reload = enabled
        return self
    
    async def load(self) -> Dict[str, Any]:
        """Load configuration from all sources."""
        configs = []
        
        for loader, priority in self._loaders:
            try:
                config = await loader.load()
                if config:
                    configs.append((config, priority))
                    self.logger.debug(f"Loaded config from {loader.__class__.__name__} with priority {priority}")
            except Exception as e:
                self.logger.error(f"Failed to load from {loader.__class__.__name__}: {e}")
                continue
        
        # Merge configurations based on priority
        merged_config = self._merge_configs(configs)
        
        # Validate configuration
        validation_result = self._validate_config(merged_config)
        if not validation_result.valid:
            error_msg = "Configuration validation failed:\n" + "\n".join(validation_result.errors)
            raise ValueError(error_msg)
        
        # Log warnings
        for warning in validation_result.warnings:
            self.logger.warning(warning)
        
        # Update internal config and notify changes
        old_config = deepcopy(self._config)
        self._config = merged_config
        self._notify_changes(old_config, merged_config)
        
        return self._config
    
    def _merge_configs(self, configs: List[Tuple[Dict[str, Any], int]]) -> Dict[str, Any]:
        """Merge configurations based on update strategy."""
        if not configs:
            return {}
        
        # Sort by priority (highest first)
        configs.sort(key=lambda x: x[1], reverse=True)
        
        if self._update_strategy == ConfigUpdateStrategy.REPLACE:
            # Use highest priority config only
            return configs[0][0]
        
        elif self._update_strategy == ConfigUpdateStrategy.MERGE:
            # Simple merge (dict.update)
            result = {}
            for config, _ in reversed(configs):  # Start with lowest priority
                result.update(config)
            return result
        
        elif self._update_strategy == ConfigUpdateStrategy.DEEP_MERGE:
            # Deep merge
            result = {}
            for config, _ in reversed(configs):  # Start with lowest priority
                result = self._deep_merge(result, config)
            return result
        
        elif self._update_strategy == ConfigUpdateStrategy.OVERLAY:
            # Overlay (ChainMap)
            config_dicts = [config for config, _ in configs]
            return dict(ChainMap(*config_dicts))
        
        return configs[0][0]
    
    def _deep_merge(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = deepcopy(base)
        
        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = deepcopy(value)
        
        return result
    
    def _validate_config(self, config: Dict[str, Any]) -> ConfigValidationResult:
        """Validate configuration using all validators."""
        result = ConfigValidationResult(valid=True)
        
        for validator in self._validators:
            validator_result = validator.validate(config)
            result.merge(validator_result)
        
        return result
    
    def _notify_changes(self, old_config: Dict[str, Any], new_config: Dict[str, Any]):
        """Notify change callbacks of configuration changes."""
        changes = self._detect_changes(old_config, new_config)
        
        for change in changes:
            for callback in self._change_callbacks:
                try:
                    callback(change)
                except Exception as e:
                    self.logger.error(f"Error in change callback: {e}")
    
    def _detect_changes(self, old: Dict[str, Any], new: Dict[str, Any], path: str = '') -> List[ConfigChangeEvent]:
        """Detect changes between two configuration dictionaries."""
        changes = []
        
        # Check for updated/added keys
        for key, new_value in new.items():
            current_path = f"{path}.{key}" if path else key
            
            if key not in old:
                # New key
                changes.append(ConfigChangeEvent(
                    source=self.name,
                    path=current_path,
                    old_value=None,
                    new_value=new_value,
                    change_type="add",
                    timestamp=datetime.now(timezone.utc)
                ))
            elif old[key] != new_value:
                if isinstance(old[key], dict) and isinstance(new_value, dict):
                    # Recursive check for nested dictionaries
                    changes.extend(self._detect_changes(old[key], new_value, current_path))
                else:
                    # Value changed
                    changes.append(ConfigChangeEvent(
                        source=self.name,
                        path=current_path,
                        old_value=old[key],
                        new_value=new_value,
                        change_type="update",
                        timestamp=datetime.now(timezone.utc)
                    ))
        
        # Check for removed keys
        for key in old.keys():
            if key not in new:
                current_path = f"{path}.{key}" if path else key
                changes.append(ConfigChangeEvent(
                    source=self.name,
                    path=current_path,
                    old_value=old[key],
                    new_value=None,
                    change_type="remove",
                    timestamp=datetime.now(timezone.utc)
                ))
        
        return changes
    
    async def save(self, config: Dict[str, Any] = None) -> bool:
        """Save configuration to all writable sources."""
        if config is None:
            config = self._config
        
        success_count = 0
        total_count = 0
        
        for loader, _ in self._loaders:
            if loader.supports_save():
                total_count += 1
                try:
                    if await loader.save(config):
                        success_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to save to {loader.__class__.__name__}: {e}")
        
        return success_count == total_count and total_count > 0
    
    async def start_watching(self):
        """Start watching all sources for changes."""
        if not self._auto_reload:
            return
        
        for loader, _ in self._loaders:
            if loader.supports_watch():
                try:
                    await loader.watch(self._on_source_change)
                except Exception as e:
                    self.logger.error(f"Failed to start watching {loader.__class__.__name__}: {e}")
    
    async def _on_source_change(self, source_config: Dict[str, Any]):
        """Handle configuration change from source."""
        try:
            await self.load()
        except Exception as e:
            self.logger.error(f"Failed to reload configuration: {e}")
    
    async def stop_watching(self):
        """Stop watching for configuration changes."""
        for task in self._watch_tasks:
            task.cancel()
        self._watch_tasks.clear()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)."""
        return self._get_nested_value(self._config, key, default)
    
    def _get_nested_value(self, config: Dict[str, Any], key: str, default: Any = None) -> Any:
        """Get nested value using dot notation."""
        keys = key.split('.')
        current = config
        
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        
        return current
    
    def set(self, key: str, value: Any):
        """Set configuration value by key (supports dot notation)."""
        self._set_nested_value(self._config, key, value)
    
    def _set_nested_value(self, config: Dict[str, Any], key: str, value: Any):
        """Set nested value using dot notation."""
        keys = key.split('.')
        current = config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def update(self, updates: Dict[str, Any]):
        """Update configuration with dictionary."""
        if self._update_strategy == ConfigUpdateStrategy.DEEP_MERGE:
            self._config = self._deep_merge(self._config, updates)
        else:
            self._config.update(updates)
    
    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary."""
        return deepcopy(self._config)
    
    def keys(self) -> List[str]:
        """Get all configuration keys."""
        return self._get_all_keys(self._config)
    
    def _get_all_keys(self, config: Dict[str, Any], prefix: str = '') -> List[str]:
        """Get all keys from nested configuration."""
        keys = []
        
        for key, value in config.items():
            full_key = f"{prefix}.{key}" if prefix else key
            keys.append(full_key)
            
            if isinstance(value, dict):
                keys.extend(self._get_all_keys(value, full_key))
        
        return keys


# Convenience functions for common configuration patterns

def create_file_config_manager(
    file_path: str, 
    format: ConfigFormat = None, 
    name: str = "file_config"
) -> ConfigManager:
    """Create a file-based configuration manager."""
    config_manager = ConfigManager(name)
    
    source_config = {'path': file_path}
    if format:
        source_config['format'] = format.value
    
    config_manager.add_source(ConfigSource.FILE, source_config)
    return config_manager


def create_env_config_manager(
    prefix: str = "SHIELD_",
    name: str = "env_config"
) -> ConfigManager:
    """Create an environment-based configuration manager."""
    config_manager = ConfigManager(name)
    config_manager.add_source(ConfigSource.ENVIRONMENT, {'prefix': prefix})
    return config_manager


def create_multi_source_config_manager(
    sources: List[Tuple[ConfigSource, Dict[str, Any], int]],
    name: str = "multi_config"
) -> ConfigManager:
    """Create a multi-source configuration manager."""
    config_manager = ConfigManager(name)
    
    for source_type, config, priority in sources:
        config_manager.add_source(source_type, config, priority)
    
    return config_manager


def create_shield_config_validator() -> ConfigValidator:
    """Create a validator for shield configuration."""
    validator = ConfigValidator()
    
    # Common shield validation rules
    validator.required("shields", "At least one shield must be configured")
    validator.type_check("shields", list)
    validator.type_check("debug", bool)
    validator.range_check("timeout", min_val=0, max_val=300)
    
    return validator