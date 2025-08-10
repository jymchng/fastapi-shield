"""Tests for Shield Configuration Management."""

import asyncio
import json
import os
import pytest
import tempfile
import yaml
import toml
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock

from fastapi_shield.config import (
    ConfigManager,
    ConfigValidator,
    ConfigFormat,
    ConfigSource,
    ConfigUpdateStrategy,
    ConfigValidationRule,
    ConfigValidationResult,
    ConfigChangeEvent,
    FileConfigLoader,
    EnvironmentConfigLoader,
    ConsulConfigLoader,
    RedisConfigLoader,
    create_file_config_manager,
    create_env_config_manager,
    create_multi_source_config_manager,
    create_shield_config_validator,
)

from tests.mocks.config_mocks import (
    MockConfigLoader,
    MockConsulClient,
    MockRedisClient,
    TempConfigFile,
    ConfigTestScenarios,
    ConfigurationTestHelper,
    ValidationTestCases,
)


class TestConfigValidationRule:
    """Test ConfigValidationRule functionality."""
    
    def test_basic_rule_creation(self):
        """Test basic validation rule creation."""
        rule = ConfigValidationRule(
            path="test.field",
            rule_type="required",
            message="Test field is required"
        )
        
        assert rule.path == "test.field"
        assert rule.rule_type == "required"
        assert rule.message == "Test field is required"
        assert rule.severity == "error"
    
    def test_rule_with_constraint(self):
        """Test validation rule with constraint."""
        rule = ConfigValidationRule(
            path="test.number",
            rule_type="range",
            constraint=(0, 100),
            message="Number must be between 0 and 100"
        )
        
        assert rule.constraint == (0, 100)
    
    def test_auto_generated_message(self):
        """Test auto-generated validation message."""
        rule = ConfigValidationRule(
            path="auto.field",
            rule_type="type"
        )
        
        assert "auto.field" in rule.message
        assert "type" in rule.message


class TestConfigValidationResult:
    """Test ConfigValidationResult functionality."""
    
    def test_initial_state(self):
        """Test initial validation result state."""
        result = ConfigValidationResult(valid=True)
        
        assert result.valid is True
        assert len(result.errors) == 0
        assert len(result.warnings) == 0
        assert len(result.info) == 0
    
    def test_add_error(self):
        """Test adding error to result."""
        result = ConfigValidationResult(valid=True)
        result.add_error("Test error")
        
        assert result.valid is False
        assert "Test error" in result.errors
    
    def test_add_warning(self):
        """Test adding warning to result."""
        result = ConfigValidationResult(valid=True)
        result.add_warning("Test warning")
        
        assert result.valid is True  # Warnings don't affect validity
        assert "Test warning" in result.warnings
    
    def test_merge_results(self):
        """Test merging validation results."""
        result1 = ConfigValidationResult(valid=True)
        result1.add_warning("Warning 1")
        
        result2 = ConfigValidationResult(valid=False)
        result2.add_error("Error 1")
        result2.add_info("Info 1")
        
        result1.merge(result2)
        
        assert result1.valid is False
        assert "Error 1" in result1.errors
        assert "Warning 1" in result1.warnings
        assert "Info 1" in result1.info


class TestConfigChangeEvent:
    """Test ConfigChangeEvent functionality."""
    
    def test_basic_event(self):
        """Test basic change event creation."""
        event = ConfigChangeEvent(
            source="test",
            path="config.field",
            old_value="old",
            new_value="new",
            timestamp=None
        )
        
        assert event.source == "test"
        assert event.path == "config.field"
        assert event.old_value == "old"
        assert event.new_value == "new"
        assert event.change_type == "update"
        assert event.timestamp is not None


class TestFileConfigLoader:
    """Test FileConfigLoader functionality."""
    
    @pytest.mark.asyncio
    async def test_load_yaml_config(self):
        """Test loading YAML configuration."""
        yaml_content = ConfigTestScenarios.basic_yaml_config()
        
        with TempConfigFile(yaml_content, '.yaml') as temp_file:
            loader = FileConfigLoader({'path': temp_file})
            config = await loader.load()
            
            assert config['debug'] is True
            assert config['timeout'] == 30
            assert config['database']['host'] == 'localhost'
            assert len(config['shields']) == 2
    
    @pytest.mark.asyncio
    async def test_load_json_config(self):
        """Test loading JSON configuration."""
        json_content = ConfigTestScenarios.basic_json_config()
        
        with TempConfigFile(json_content, '.json') as temp_file:
            loader = FileConfigLoader({'path': temp_file, 'format': 'json'})
            config = await loader.load()
            
            assert config['debug'] is True
            assert config['database']['port'] == 5432
            assert config['shields'][0]['name'] == 'rate_limit'
    
    @pytest.mark.asyncio
    async def test_load_toml_config(self):
        """Test loading TOML configuration."""
        toml_content = ConfigTestScenarios.basic_toml_config()
        
        with TempConfigFile(toml_content, '.toml') as temp_file:
            loader = FileConfigLoader({'path': temp_file})
            config = await loader.load()
            
            assert config['debug'] is True
            assert config['timeout'] == 30
            assert config['database']['host'] == 'localhost'
    
    @pytest.mark.asyncio
    async def test_load_env_config(self):
        """Test loading environment file configuration."""
        env_content = ConfigTestScenarios.env_file_config()
        
        with TempConfigFile(env_content, '.env') as temp_file:
            loader = FileConfigLoader({'path': temp_file, 'format': 'env'})
            config = await loader.load()
            
            assert config['DEBUG'] is True
            assert config['TIMEOUT'] == 30
            assert config['DATABASE_HOST'] == 'localhost'
    
    @pytest.mark.asyncio
    async def test_load_nonexistent_file(self):
        """Test loading non-existent file."""
        loader = FileConfigLoader({'path': 'nonexistent.yaml'})
        config = await loader.load()
        
        assert config == {}
    
    @pytest.mark.asyncio
    async def test_save_yaml_config(self):
        """Test saving YAML configuration."""
        test_config = {'test': 'value', 'nested': {'key': 'value'}}
        
        with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            loader = FileConfigLoader({'path': temp_path})
            success = await loader.save(test_config)
            
            assert success is True
            
            # Verify saved content
            with open(temp_path, 'r') as f:
                saved_content = yaml.safe_load(f)
            
            assert saved_content == test_config
        
        finally:
            os.unlink(temp_path)
    
    @pytest.mark.asyncio
    async def test_save_json_config(self):
        """Test saving JSON configuration."""
        test_config = {'test': 'value', 'number': 42}
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            loader = FileConfigLoader({'path': temp_path, 'format': 'json'})
            success = await loader.save(test_config)
            
            assert success is True
            
            # Verify saved content
            with open(temp_path, 'r') as f:
                saved_content = json.load(f)
            
            assert saved_content == test_config
        
        finally:
            os.unlink(temp_path)
    
    def test_format_detection(self):
        """Test automatic format detection."""
        yaml_loader = FileConfigLoader({'path': 'config.yaml'})
        assert yaml_loader.format == ConfigFormat.YAML
        
        json_loader = FileConfigLoader({'path': 'config.json'})
        assert json_loader.format == ConfigFormat.JSON
        
        toml_loader = FileConfigLoader({'path': 'config.toml'})
        assert toml_loader.format == ConfigFormat.TOML


class TestEnvironmentConfigLoader:
    """Test EnvironmentConfigLoader functionality."""
    
    @pytest.mark.asyncio
    async def test_load_environment_config(self):
        """Test loading configuration from environment variables."""
        test_env = ConfigTestScenarios.environment_variables()
        original_env = ConfigurationTestHelper.create_test_environment(test_env)
        
        try:
            loader = EnvironmentConfigLoader({'prefix': 'SHIELD_'})
            config = await loader.load()
            
            # Keys are lowercased by default (case_sensitive=False)
            assert config['debug'] is True
            assert config['timeout'] == 45
            assert config['database']['host'] == 'env-db-host'
            assert config['database']['port'] == 3306
            assert config['shields']['rate_limit']['enabled'] is False
            assert config['shields']['rate_limit']['max_requests'] == 200
            assert config['new_feature'] == 'enabled'
            assert 'OTHER_VAR' not in str(config)  # Should be ignored
        
        finally:
            ConfigurationTestHelper.restore_environment(original_env)
    
    @pytest.mark.asyncio
    async def test_case_insensitive_loading(self):
        """Test case-insensitive environment variable loading."""
        os.environ['shield_test'] = 'value'
        os.environ['SHIELD_other'] = 'other_value'
        
        try:
            loader = EnvironmentConfigLoader({
                'prefix': 'SHIELD_',
                'case_sensitive': False
            })
            config = await loader.load()
            
            assert 'test' in config or 'TEST' in config
            assert 'other' in config or 'OTHER' in config
        
        finally:
            if 'shield_test' in os.environ:
                del os.environ['shield_test']
            if 'SHIELD_other' in os.environ:
                del os.environ['SHIELD_other']
    
    @pytest.mark.asyncio
    async def test_type_conversion(self):
        """Test automatic type conversion."""
        test_env = {
            'TEST_STRING': 'hello',
            'TEST_INT': '42',
            'TEST_FLOAT': '3.14',
            'TEST_BOOL_TRUE': 'true',
            'TEST_BOOL_FALSE': 'false',
            'TEST_LIST': 'item1,item2,item3'
        }
        
        original_env = ConfigurationTestHelper.create_test_environment(test_env)
        
        try:
            loader = EnvironmentConfigLoader({'prefix': 'TEST_', 'type_conversion': True})
            config = await loader.load()
            
            # Keys are lowercased by default (case_sensitive=False)
            assert isinstance(config['string'], str)
            assert isinstance(config['int'], int)
            assert isinstance(config['float'], float)
            assert isinstance(config['bool_true'], bool)
            assert config['bool_true'] is True
            assert config['bool_false'] is False
            assert isinstance(config['list'], list)
            assert len(config['list']) == 3
        
        finally:
            ConfigurationTestHelper.restore_environment(original_env)
    
    def test_supports_methods(self):
        """Test loader capability methods."""
        loader = EnvironmentConfigLoader({'prefix': 'TEST_'})
        
        assert loader.supports_save() is True
        assert loader.supports_watch() is False


class TestConsulConfigLoader:
    """Test ConsulConfigLoader functionality."""
    
    @pytest.mark.asyncio
    async def test_load_consul_config(self):
        """Test loading configuration from Consul."""
        pytest.skip("Consul integration test - requires external dependencies")
    
    @pytest.mark.asyncio
    async def test_save_consul_config(self):
        """Test saving configuration to Consul."""
        pytest.skip("Consul integration test - requires external dependencies")
    
    def test_consul_not_available(self):
        """Test behavior when Consul is not available."""
        with patch('fastapi_shield.config.CONSUL_AVAILABLE', False):
            with pytest.raises(ImportError, match="python-consul package required"):
                ConsulConfigLoader({'host': 'localhost'})


class TestRedisConfigLoader:
    """Test RedisConfigLoader functionality."""
    
    @pytest.mark.asyncio
    async def test_load_redis_config(self):
        """Test loading configuration from Redis."""
        pytest.skip("Redis integration test - requires external dependencies")
    
    @pytest.mark.asyncio
    async def test_save_redis_config(self):
        """Test saving configuration to Redis."""
        pytest.skip("Redis integration test - requires external dependencies")
    
    def test_redis_not_available(self):
        """Test behavior when Redis is not available."""
        with patch('fastapi_shield.config.REDIS_AVAILABLE', False):
            with pytest.raises(ImportError, match="redis package required"):
                RedisConfigLoader({'host': 'localhost'})


class TestConfigValidator:
    """Test ConfigValidator functionality."""
    
    def test_required_validation(self):
        """Test required field validation."""
        validator = ConfigValidator()
        validator.required('required_field')
        
        # Valid config with required field
        valid_config = {'required_field': 'present'}
        result = validator.validate(valid_config)
        assert result.valid is True
        
        # Invalid config missing required field
        invalid_config = {'other_field': 'present'}
        result = validator.validate(invalid_config)
        assert result.valid is False
        assert len(result.errors) == 1
    
    def test_type_validation(self):
        """Test type validation."""
        validator = ConfigValidator()
        validator.type_check('string_field', str)
        validator.type_check('number_field', int)
        
        valid_config = {'string_field': 'text', 'number_field': 42}
        result = validator.validate(valid_config)
        assert result.valid is True
        
        invalid_config = {'string_field': 123, 'number_field': 'not_number'}
        result = validator.validate(invalid_config)
        assert result.valid is False
        assert len(result.errors) == 2
    
    def test_regex_validation(self):
        """Test regex validation."""
        validator = ConfigValidator()
        validator.regex('email_field', r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        
        valid_config = {'email_field': 'test@example.com'}
        result = validator.validate(valid_config)
        assert result.valid is True
        
        invalid_config = {'email_field': 'invalid-email'}
        result = validator.validate(invalid_config)
        assert result.valid is False
    
    def test_range_validation(self):
        """Test range validation."""
        validator = ConfigValidator()
        validator.range_check('port', min_val=1, max_val=65535)
        
        valid_config = {'port': 8080}
        result = validator.validate(valid_config)
        assert result.valid is True
        
        invalid_config_low = {'port': 0}
        result = validator.validate(invalid_config_low)
        assert result.valid is False
        
        invalid_config_high = {'port': 70000}
        result = validator.validate(invalid_config_high)
        assert result.valid is False
    
    def test_enum_validation(self):
        """Test enum validation."""
        validator = ConfigValidator()
        validator.enum_check('log_level', ['DEBUG', 'INFO', 'WARNING', 'ERROR'])
        
        valid_config = {'log_level': 'INFO'}
        result = validator.validate(valid_config)
        assert result.valid is True
        
        invalid_config = {'log_level': 'INVALID'}
        result = validator.validate(invalid_config)
        assert result.valid is False
    
    def test_custom_validation(self):
        """Test custom validation function."""
        def validate_positive_even(value):
            return isinstance(value, int) and value > 0 and value % 2 == 0
        
        validator = ConfigValidator()
        validator.custom('even_field', validate_positive_even)
        
        valid_config = {'even_field': 42}
        result = validator.validate(valid_config)
        assert result.valid is True
        
        invalid_config = {'even_field': 43}  # Odd number
        result = validator.validate(invalid_config)
        assert result.valid is False
    
    def test_nested_field_validation(self):
        """Test validation of nested fields."""
        validator = ConfigValidator()
        validator.required('database.host')
        validator.type_check('database.port', int)
        
        valid_config = {
            'database': {
                'host': 'localhost',
                'port': 5432
            }
        }
        result = validator.validate(valid_config)
        assert result.valid is True
        
        invalid_config = {
            'database': {
                'port': 'not_int'  # Missing host, wrong type for port
            }
        }
        result = validator.validate(invalid_config)
        assert result.valid is False
        assert len(result.errors) == 2


class TestConfigManager:
    """Test ConfigManager functionality."""
    
    @pytest.mark.asyncio
    async def test_single_source_loading(self):
        """Test loading from single configuration source."""
        test_config = {'debug': True, 'timeout': 30}
        mock_loader = MockConfigLoader({'data': test_config})
        
        manager = ConfigManager()
        manager._loaders = [(mock_loader, 100)]
        
        config = await manager.load()
        
        assert config == test_config
        assert mock_loader.load_calls == 1
    
    @pytest.mark.asyncio
    async def test_multi_source_loading_with_priority(self):
        """Test loading from multiple sources with priority."""
        high_priority_config = {'debug': True, 'timeout': 60, 'high_only': 'value'}
        low_priority_config = {'debug': False, 'timeout': 30, 'low_only': 'value'}
        
        high_loader = MockConfigLoader({'data': high_priority_config})
        low_loader = MockConfigLoader({'data': low_priority_config})
        
        manager = ConfigManager()
        manager.add_source(ConfigSource.FILE, {'data': low_priority_config}, priority=50)
        manager.add_source(ConfigSource.ENVIRONMENT, {'data': high_priority_config}, priority=100)
        
        # Replace with mock loaders
        manager._loaders = [(high_loader, 100), (low_loader, 50)]
        
        config = await manager.load()
        
        # High priority values should win
        assert config['debug'] is True  # High priority
        assert config['timeout'] == 60  # High priority
        assert config['high_only'] == 'value'
        assert config['low_only'] == 'value'  # From low priority, not conflicting
    
    @pytest.mark.asyncio
    async def test_deep_merge_strategy(self):
        """Test deep merge configuration strategy."""
        config1 = {
            'database': {'host': 'localhost', 'port': 5432},
            'features': {'feature1': True}
        }
        config2 = {
            'database': {'port': 3306, 'ssl': True},
            'features': {'feature2': False}
        }
        
        loader1 = MockConfigLoader({'data': config1})
        loader2 = MockConfigLoader({'data': config2})
        
        manager = ConfigManager()
        manager.set_update_strategy(ConfigUpdateStrategy.DEEP_MERGE)
        manager._loaders = [(loader2, 100), (loader1, 50)]  # loader2 has higher priority
        
        config = await manager.load()
        
        assert config['database']['host'] == 'localhost'  # From config1
        assert config['database']['port'] == 3306  # From config2 (higher priority)
        assert config['database']['ssl'] is True  # From config2
        assert config['features']['feature1'] is True  # From config1
        assert config['features']['feature2'] is False  # From config2
    
    @pytest.mark.asyncio
    async def test_configuration_validation(self):
        """Test configuration validation during load."""
        invalid_config = {'debug': 'not_boolean'}
        mock_loader = MockConfigLoader({'data': invalid_config})
        
        validator = ConfigValidator()
        validator.type_check('debug', bool)
        
        manager = ConfigManager()
        manager.add_validator(validator)
        manager._loaders = [(mock_loader, 100)]
        
        with pytest.raises(ValueError, match="Configuration validation failed"):
            await manager.load()
    
    @pytest.mark.asyncio
    async def test_change_detection(self):
        """Test configuration change detection and callbacks."""
        initial_config = {'debug': False, 'timeout': 30}
        mock_loader = MockConfigLoader({'data': initial_config})
        
        changes_received = []
        
        def change_callback(event):
            changes_received.append(event)
        
        manager = ConfigManager()
        manager.on_change(change_callback)
        manager._loaders = [(mock_loader, 100)]
        
        # Initial load
        await manager.load()
        
        # Update configuration
        new_config = {'debug': True, 'timeout': 60, 'new_field': 'value'}
        mock_loader.update_config(new_config)
        await manager.load()
        
        # Should have detected changes
        assert len(changes_received) >= 2  # debug change, timeout change, new_field added
        
        change_paths = [change.path for change in changes_received]
        assert 'debug' in change_paths
        assert 'timeout' in change_paths
        assert 'new_field' in change_paths
    
    def test_get_and_set_methods(self):
        """Test get and set methods with dot notation."""
        manager = ConfigManager()
        manager._config = {
            'database': {
                'host': 'localhost',
                'port': 5432
            },
            'debug': True
        }
        
        # Test get with simple key
        assert manager.get('debug') is True
        
        # Test get with nested key
        assert manager.get('database.host') == 'localhost'
        assert manager.get('database.port') == 5432
        
        # Test get with default value
        assert manager.get('nonexistent', 'default') == 'default'
        
        # Test set with simple key
        manager.set('new_field', 'new_value')
        assert manager.get('new_field') == 'new_value'
        
        # Test set with nested key
        manager.set('database.ssl', True)
        assert manager.get('database.ssl') is True
    
    def test_update_method(self):
        """Test configuration update method."""
        manager = ConfigManager()
        manager._config = {'existing': 'value'}
        
        updates = {
            'new_field': 'new_value',
            'existing': 'updated_value'
        }
        
        manager.update(updates)
        
        assert manager.get('new_field') == 'new_value'
        assert manager.get('existing') == 'updated_value'
    
    def test_keys_method(self):
        """Test getting all configuration keys."""
        manager = ConfigManager()
        manager._config = {
            'debug': True,
            'database': {
                'host': 'localhost',
                'credentials': {
                    'username': 'user'
                }
            }
        }
        
        keys = manager.keys()
        
        expected_keys = [
            'debug',
            'database',
            'database.host',
            'database.credentials',
            'database.credentials.username'
        ]
        
        for key in expected_keys:
            assert key in keys
    
    @pytest.mark.asyncio
    async def test_save_to_sources(self):
        """Test saving configuration to sources."""
        test_config = {'test': 'value'}
        mock_loader = MockConfigLoader({'data': {}, 'supports_save': True})
        
        manager = ConfigManager()
        manager._loaders = [(mock_loader, 100)]
        manager._config = test_config
        
        success = await manager.save()
        
        assert success is True
        assert mock_loader.save_calls == 1
    
    @pytest.mark.asyncio
    async def test_load_failure_handling(self):
        """Test handling of load failures."""
        failing_loader = MockConfigLoader({
            'should_fail_load': True,
            'data': {}
        })
        successful_loader = MockConfigLoader({
            'data': {'fallback': 'config'}
        })
        
        manager = ConfigManager()
        manager._loaders = [(failing_loader, 100), (successful_loader, 50)]
        
        # Should still load successfully from the working loader
        config = await manager.load()
        
        assert config['fallback'] == 'config'


class TestConvenienceFunctions:
    """Test convenience functions for configuration management."""
    
    def test_create_file_config_manager(self):
        """Test file configuration manager creation."""
        manager = create_file_config_manager('test.yaml', ConfigFormat.YAML)
        
        assert isinstance(manager, ConfigManager)
        assert len(manager._loaders) == 1
        assert isinstance(manager._loaders[0][0], FileConfigLoader)
    
    def test_create_env_config_manager(self):
        """Test environment configuration manager creation."""
        manager = create_env_config_manager(prefix='TEST_')
        
        assert isinstance(manager, ConfigManager)
        assert len(manager._loaders) == 1
        assert isinstance(manager._loaders[0][0], EnvironmentConfigLoader)
    
    def test_create_multi_source_config_manager(self):
        """Test multi-source configuration manager creation."""
        sources = [
            (ConfigSource.FILE, {'path': 'test.yaml'}, 100),
            (ConfigSource.ENVIRONMENT, {'prefix': 'TEST_'}, 50)
        ]
        
        manager = create_multi_source_config_manager(sources)
        
        assert isinstance(manager, ConfigManager)
        assert len(manager._loaders) == 2
    
    def test_create_shield_config_validator(self):
        """Test shield configuration validator creation."""
        validator = create_shield_config_validator()
        
        assert isinstance(validator, ConfigValidator)
        assert len(validator.rules) > 0


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple features."""
    
    @pytest.mark.asyncio
    async def test_file_and_environment_integration(self):
        """Test file and environment configuration integration."""
        # Create temporary YAML file
        yaml_content = """
debug: false
timeout: 30
database:
  host: file-host
  port: 5432
features:
  feature1: true
"""
        
        # Set up environment variables
        env_vars = {
            'APP_DEBUG': 'true',
            'APP_DATABASE__HOST': 'env-host',
            'APP_FEATURES__FEATURE2': 'true'
        }
        
        original_env = ConfigurationTestHelper.create_test_environment(env_vars)
        
        try:
            with TempConfigFile(yaml_content, '.yaml') as temp_file:
                manager = ConfigManager()
                manager.add_source(ConfigSource.FILE, {'path': temp_file}, priority=50)
                manager.add_source(ConfigSource.ENVIRONMENT, {'prefix': 'APP_'}, priority=100)
                
                config = await manager.load()
                
                # Environment should override file
                assert config['debug'] is True  # From environment
                assert config['timeout'] == 30  # From file
                assert config['database']['host'] == 'env-host'  # From environment
                assert config['database']['port'] == 5432  # From file
                assert config['features']['feature1'] is True  # From file
                assert config['features']['feature2'] is True  # From environment
        
        finally:
            ConfigurationTestHelper.restore_environment(original_env)
    
    @pytest.mark.asyncio
    async def test_validation_with_multiple_sources(self):
        """Test validation with multiple configuration sources."""
        # File config (valid)
        file_config = {'debug': True, 'shields': [{'name': 'test'}], 'timeout': 30}
        
        # Environment config (invalid timeout)
        env_config = {'timeout': 500}  # Too high
        
        file_loader = MockConfigLoader({'data': file_config})
        env_loader = MockConfigLoader({'data': env_config})
        
        validator = create_shield_config_validator()
        
        manager = ConfigManager()
        manager.add_validator(validator)
        manager._loaders = [(env_loader, 100), (file_loader, 50)]
        
        # Should fail validation due to high timeout from environment
        with pytest.raises(ValueError, match="Configuration validation failed"):
            await manager.load()
    
    @pytest.mark.asyncio
    async def test_dynamic_configuration_updates(self):
        """Test dynamic configuration updates with callbacks."""
        initial_config = {'debug': False, 'feature_flags': {'new_feature': False}}
        mock_loader = MockConfigLoader({'data': initial_config})
        
        updates_received = []
        
        def config_change_handler(event):
            updates_received.append({
                'path': event.path,
                'old': event.old_value,
                'new': event.new_value,
                'type': event.change_type
            })
        
        manager = ConfigManager()
        manager.on_change(config_change_handler)
        manager._loaders = [(mock_loader, 100)]
        
        # Initial load
        await manager.load()
        
        # Simulate configuration update
        updated_config = {
            'debug': True,  # Changed
            'feature_flags': {
                'new_feature': True,  # Changed
                'another_feature': True  # Added
            },
            'new_section': {'key': 'value'}  # Added
        }
        
        mock_loader.update_config(updated_config)
        await manager.load()
        
        # Verify change notifications
        assert len(updates_received) > 0
        
        change_paths = [update['path'] for update in updates_received]
        assert 'debug' in change_paths
        assert 'feature_flags.new_feature' in change_paths
    
    @pytest.mark.asyncio
    async def test_configuration_save_and_reload(self):
        """Test saving configuration and reloading."""
        initial_config = {'debug': False, 'timeout': 30}
        mock_loader = MockConfigLoader({'data': initial_config})
        
        manager = ConfigManager()
        manager._loaders = [(mock_loader, 100)]
        
        # Load initial configuration
        config = await manager.load()
        assert config['debug'] is False
        
        # Update configuration
        manager.set('debug', True)
        manager.set('new_feature', 'enabled')
        
        # Save configuration
        success = await manager.save()
        assert success is True
        
        # Verify configuration was saved to loader
        saved_config = mock_loader.config_data
        assert saved_config['debug'] is True
        assert saved_config['new_feature'] == 'enabled'
    
    @pytest.mark.asyncio
    async def test_error_recovery_and_fallbacks(self):
        """Test error recovery with fallback configurations."""
        primary_config = {'source': 'primary', 'debug': True}
        fallback_config = {'source': 'fallback', 'debug': False, 'timeout': 30}
        
        # Primary loader that fails
        primary_loader = MockConfigLoader({
            'should_fail_load': True,
            'data': primary_config
        })
        
        # Fallback loader that works
        fallback_loader = MockConfigLoader({'data': fallback_config})
        
        manager = ConfigManager()
        manager._loaders = [(primary_loader, 100), (fallback_loader, 50)]
        
        # Should fallback to secondary loader
        config = await manager.load()
        
        assert config['source'] == 'fallback'
        assert config['debug'] is False
        assert config['timeout'] == 30


class TestConfigurationFormats:
    """Test different configuration file formats."""
    
    @pytest.mark.asyncio
    async def test_yaml_configuration(self):
        """Test comprehensive YAML configuration."""
        complex_config = ConfigTestScenarios.complex_nested_config()
        yaml_content = yaml.dump(complex_config)
        
        with TempConfigFile(yaml_content, '.yaml') as temp_file:
            manager = create_file_config_manager(temp_file, ConfigFormat.YAML)
            config = await manager.load()
            
            ConfigurationTestHelper.assert_config_equal(config, complex_config)
    
    @pytest.mark.asyncio
    async def test_json_configuration(self):
        """Test comprehensive JSON configuration."""
        complex_config = ConfigTestScenarios.complex_nested_config()
        json_content = json.dumps(complex_config, indent=2)
        
        with TempConfigFile(json_content, '.json') as temp_file:
            manager = create_file_config_manager(temp_file, ConfigFormat.JSON)
            config = await manager.load()
            
            ConfigurationTestHelper.assert_config_equal(config, complex_config)
    
    @pytest.mark.asyncio
    async def test_toml_configuration(self):
        """Test TOML configuration."""
        # TOML has some limitations with nested structures
        toml_config = {
            'debug': True,
            'timeout': 30,
            'database': {
                'host': 'localhost',
                'port': 5432
            }
        }
        toml_content = toml.dumps(toml_config)
        
        with TempConfigFile(toml_content, '.toml') as temp_file:
            manager = create_file_config_manager(temp_file, ConfigFormat.TOML)
            config = await manager.load()
            
            assert config['debug'] is True
            assert config['timeout'] == 30
            assert config['database']['host'] == 'localhost'