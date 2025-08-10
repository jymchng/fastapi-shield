"""Comprehensive tests for the FastAPI Shield plugin system."""

import asyncio
import json
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Any
from unittest.mock import Mock, patch, AsyncMock

import pytest
import yaml

from fastapi_shield.plugin_system import (
    PluginInterface, ShieldPlugin, ProcessorPlugin, ValidatorPlugin,
    TransformerPlugin, ExtensionPlugin, PluginMetadata, PluginConfiguration,
    PluginType, PluginPriority, PluginState, PluginError, PluginNotFoundError,
    PluginVersionError, PluginDependencyError, PluginConflictError,
    PluginConfigurationError, VersionChecker, PluginDiscovery, PluginRegistry,
    PluginManager, get_plugin_manager, set_plugin_manager, discover_plugins,
    get_active_shield_plugins, get_shields_from_plugins
)
from tests.mocks.plugin_system_mocks import (
    MockShieldPlugin, MockProcessorPlugin, MockValidatorPlugin,
    MockTransformerPlugin, MockExtensionPlugin, MockFailingPlugin,
    MockRequest, MockResponse, MockPluginDiscovery, MockPluginRegistry,
    MockVersionChecker, create_temporary_plugin_file,
    create_temporary_plugin_package, cleanup_temporary_files
)


class TestPluginMetadata:
    """Test plugin metadata functionality."""
    
    def test_plugin_metadata_creation(self):
        """Test plugin metadata creation with all fields."""
        metadata = PluginMetadata(
            name="TestPlugin",
            version="1.2.3",
            description="Test plugin description",
            author="Test Author",
            author_email="test@example.com",
            homepage="https://example.com",
            license="MIT",
            keywords=["test", "plugin"],
            requires_python=">=3.8",
            requires_shield=">=0.1.0",
            dependencies=["requests", "pydantic"],
            plugin_type=PluginType.SHIELD,
            priority=PluginPriority.HIGH,
            config_schema={"type": "object"},
            entry_points={"main": "TestPluginClass"},
            tags=["security", "validation"]
        )
        
        assert metadata.name == "TestPlugin"
        assert metadata.version == "1.2.3"
        assert metadata.description == "Test plugin description"
        assert metadata.author == "Test Author"
        assert metadata.author_email == "test@example.com"
        assert metadata.homepage == "https://example.com"
        assert metadata.license == "MIT"
        assert metadata.keywords == ["test", "plugin"]
        assert metadata.requires_python == ">=3.8"
        assert metadata.requires_shield == ">=0.1.0"
        assert metadata.dependencies == ["requests", "pydantic"]
        assert metadata.plugin_type == PluginType.SHIELD
        assert metadata.priority == PluginPriority.HIGH
        assert metadata.config_schema == {"type": "object"}
        assert metadata.entry_points == {"main": "TestPluginClass"}
        assert metadata.tags == ["security", "validation"]
    
    def test_plugin_metadata_validation(self):
        """Test plugin metadata validation."""
        # Missing name
        with pytest.raises(ValueError, match="Plugin name is required"):
            PluginMetadata(name="", version="1.0.0", description="Test", author="Test")
        
        # Missing version
        with pytest.raises(ValueError, match="Plugin version is required"):
            PluginMetadata(name="Test", version="", description="Test", author="Test")
        
        # Missing author
        with pytest.raises(ValueError, match="Plugin author is required"):
            PluginMetadata(name="Test", version="1.0.0", description="Test", author="")
    
    def test_plugin_metadata_serialization(self):
        """Test plugin metadata to/from dict conversion."""
        metadata = PluginMetadata(
            name="TestPlugin",
            version="1.0.0",
            description="Test plugin",
            author="Test Author",
            plugin_type=PluginType.VALIDATOR,
            priority=PluginPriority.CRITICAL
        )
        
        # Test to_dict
        data = metadata.to_dict()
        assert data["name"] == "TestPlugin"
        assert data["version"] == "1.0.0"
        assert data["description"] == "Test plugin"
        assert data["author"] == "Test Author"
        assert data["plugin_type"] == "validator"
        assert data["priority"] == 100
        
        # Test from_dict
        restored = PluginMetadata.from_dict(data)
        assert restored.name == metadata.name
        assert restored.version == metadata.version
        assert restored.description == metadata.description
        assert restored.author == metadata.author
        assert restored.plugin_type == metadata.plugin_type
        assert restored.priority == metadata.priority


class TestPluginConfiguration:
    """Test plugin configuration functionality."""
    
    def test_plugin_configuration_creation(self):
        """Test plugin configuration creation."""
        config = PluginConfiguration(
            enabled=True,
            config={"max_requests": 100, "timeout": 30},
            auto_activate=False,
            priority_override=PluginPriority.HIGH,
            dependencies=["dependency1", "dependency2"],
            conflicts=["conflict1"],
            environment_variables={"ENV_VAR": "value"},
            feature_flags={"feature1": True, "feature2": False}
        )
        
        assert config.enabled is True
        assert config.config == {"max_requests": 100, "timeout": 30}
        assert config.auto_activate is False
        assert config.priority_override == PluginPriority.HIGH
        assert config.dependencies == ["dependency1", "dependency2"]
        assert config.conflicts == ["conflict1"]
        assert config.environment_variables == {"ENV_VAR": "value"}
        assert config.feature_flags == {"feature1": True, "feature2": False}
    
    def test_plugin_configuration_serialization(self):
        """Test plugin configuration to/from dict conversion."""
        config = PluginConfiguration(
            enabled=False,
            priority_override=PluginPriority.LOW,
            dependencies=["dep1"]
        )
        
        # Test to_dict
        data = config.to_dict()
        assert data["enabled"] is False
        assert data["priority_override"] == 25
        assert data["dependencies"] == ["dep1"]
        
        # Test from_dict
        restored = PluginConfiguration.from_dict(data)
        assert restored.enabled is False
        assert restored.priority_override == PluginPriority.LOW
        assert restored.dependencies == ["dep1"]


class TestPluginInterface:
    """Test plugin interface base functionality."""
    
    @pytest.fixture
    def mock_plugin(self):
        """Create a mock plugin for testing."""
        plugin = MockShieldPlugin()
        return plugin
    
    def test_plugin_interface_initialization(self, mock_plugin):
        """Test plugin interface initialization."""
        assert mock_plugin.state == PluginState.UNREGISTERED
        assert mock_plugin.config is not None
        assert mock_plugin._logger is not None
    
    @pytest.mark.asyncio
    async def test_plugin_lifecycle_methods(self, mock_plugin):
        """Test plugin lifecycle methods."""
        # Initialize
        await mock_plugin.initialize()
        assert mock_plugin.initialization_count == 1
        assert len(mock_plugin.get_shields()) > 0
        
        # Activate
        await mock_plugin.activate()
        assert mock_plugin.activation_count == 1
        
        # Deactivate
        await mock_plugin.deactivate()
        assert mock_plugin.deactivation_count == 1
        
        # Cleanup
        await mock_plugin.cleanup()
        assert mock_plugin.cleanup_count == 1
    
    @pytest.mark.asyncio
    async def test_plugin_configuration_validation(self, mock_plugin):
        """Test plugin configuration validation."""
        # Valid configuration
        errors = await mock_plugin.validate_configuration()
        assert len(errors) == 0
        
        # Invalid configuration (mock schema validation)
        mock_plugin.config.config = {"max_requests": "invalid"}
        
        # Mock the _validate_config_schema method to simulate validation error
        original_validate = mock_plugin._validate_config_schema
        def mock_validate(errors_list):
            errors_list.append("Configuration validation error: Invalid configuration")
        mock_plugin._validate_config_schema = mock_validate
        
        errors = await mock_plugin.validate_configuration()
        assert len(errors) > 0
        assert "Configuration validation error" in errors[0]
        
        # Restore original method
        mock_plugin._validate_config_schema = original_validate
    
    def test_plugin_health_status(self, mock_plugin):
        """Test plugin health status."""
        health = mock_plugin.get_health_status()
        
        assert health["name"] == mock_plugin.metadata.name
        assert health["version"] == mock_plugin.metadata.version
        assert health["state"] == mock_plugin.state.value
        assert health["enabled"] == mock_plugin.config.enabled
        assert "healthy" in health
    
    def test_plugin_metrics(self, mock_plugin):
        """Test plugin metrics."""
        metrics = mock_plugin.get_metrics()
        
        assert metrics["name"] == mock_plugin.metadata.name
        assert metrics["state"] == mock_plugin.state.value
        assert "uptime" in metrics
        assert "requests_processed" in metrics
        assert "errors" in metrics


class TestShieldPlugin:
    """Test shield plugin functionality."""
    
    @pytest.fixture
    def shield_plugin(self):
        """Create a shield plugin for testing."""
        return MockShieldPlugin(num_shields=3, shield_names=["Shield1", "Shield2", "Shield3"])
    
    @pytest.mark.asyncio
    async def test_shield_plugin_creation(self, shield_plugin):
        """Test shield plugin creation and shield generation."""
        await shield_plugin.initialize()
        
        shields = shield_plugin.get_shields()
        assert len(shields) == 3
        assert all(shield.name in ["Shield1", "Shield2", "Shield3"] for shield in shields)
    
    def test_shield_plugin_metadata(self, shield_plugin):
        """Test shield plugin metadata."""
        metadata = shield_plugin.metadata
        assert metadata.plugin_type == PluginType.SHIELD
        assert metadata.name == "MockShieldPlugin"
        assert metadata.version == "1.0.0"


class TestProcessorPlugin:
    """Test processor plugin functionality."""
    
    @pytest.fixture
    def processor_plugin(self):
        """Create a processor plugin for testing."""
        return MockProcessorPlugin()
    
    @pytest.mark.asyncio
    async def test_processor_plugin_request_processing(self, processor_plugin):
        """Test processor plugin request processing."""
        request = MockRequest(headers={"Content-Type": "application/json"})
        
        processed_request = await processor_plugin.process_request(request)
        
        assert processor_plugin.request_processing_count == 1
        assert processed_request is request  # Same instance returned
        assert processed_request.headers.get("X-Processed-By") == "MockProcessorPlugin"
    
    @pytest.mark.asyncio
    async def test_processor_plugin_response_processing(self, processor_plugin):
        """Test processor plugin response processing."""
        request = MockRequest()
        response = MockResponse(status_code=200)
        
        processed_response = await processor_plugin.process_response(request, response)
        
        assert processor_plugin.response_processing_count == 1
        assert processed_response is response  # Same instance returned
        assert processed_response.headers.get("X-Response-Processed-By") == "MockProcessorPlugin"


class TestValidatorPlugin:
    """Test validator plugin functionality."""
    
    @pytest.fixture
    def validator_plugin(self):
        """Create a validator plugin for testing."""
        return MockValidatorPlugin(validation_errors=["Error 1", "Error 2"])
    
    @pytest.mark.asyncio
    async def test_validator_plugin_validation(self, validator_plugin):
        """Test validator plugin request validation."""
        request = MockRequest()
        
        errors = await validator_plugin.validate_request(request)
        
        assert validator_plugin.validation_count == 1
        assert len(errors) == 2
        assert "Error 1" in errors
        assert "Error 2" in errors
    
    @pytest.mark.asyncio
    async def test_validator_plugin_no_errors(self):
        """Test validator plugin with no validation errors."""
        validator_plugin = MockValidatorPlugin(validation_errors=[])
        request = MockRequest()
        
        errors = await validator_plugin.validate_request(request)
        
        assert len(errors) == 0


class TestTransformerPlugin:
    """Test transformer plugin functionality."""
    
    @pytest.fixture
    def transformer_plugin(self):
        """Create a transformer plugin for testing."""
        return MockTransformerPlugin()
    
    @pytest.mark.asyncio
    async def test_transformer_plugin_string_transformation(self, transformer_plugin):
        """Test transformer plugin string transformations."""
        # Uppercase transformation
        result = await transformer_plugin.transform_data("hello world", "uppercase")
        assert result == "HELLO WORLD"
        assert transformer_plugin.transformation_count == 1
        
        # Reverse transformation
        result = await transformer_plugin.transform_data("hello", "reverse")
        assert result == "olleh"
        assert transformer_plugin.transformation_count == 2
    
    @pytest.mark.asyncio
    async def test_transformer_plugin_numeric_transformation(self, transformer_plugin):
        """Test transformer plugin numeric transformations."""
        result = await transformer_plugin.transform_data(42, "multiply")
        assert result == 84
        assert transformer_plugin.transformation_count == 1
    
    @pytest.mark.asyncio
    async def test_transformer_plugin_unsupported_transformation(self, transformer_plugin):
        """Test transformer plugin with unsupported transformation."""
        result = await transformer_plugin.transform_data("test", "unsupported")
        assert result == "test"  # Original data returned
        assert transformer_plugin.transformation_count == 1


class TestExtensionPlugin:
    """Test extension plugin functionality."""
    
    @pytest.fixture
    def extension_plugin(self):
        """Create an extension plugin for testing."""
        return MockExtensionPlugin()
    
    @pytest.mark.asyncio
    async def test_extension_plugin_functionality(self, extension_plugin):
        """Test extension plugin functionality."""
        context = {"existing_key": "existing_value"}
        
        extended_context = await extension_plugin.extend_functionality(context)
        
        assert extension_plugin.extension_count == 1
        assert extended_context["existing_key"] == "existing_value"
        assert extended_context["mock_extension"] == "added_by_mock_extension_plugin"
        assert extended_context["extension_count"] == 1


class TestVersionChecker:
    """Test version checking functionality."""
    
    @pytest.fixture
    def version_checker(self):
        """Create a version checker for testing."""
        return VersionChecker()
    
    @patch('fastapi_shield.plugin_system.PACKAGING_AVAILABLE', True)
    def test_python_version_checking(self, version_checker):
        """Test Python version compatibility checking."""
        with patch('fastapi_shield.plugin_system.packaging') as mock_packaging:
            mock_version = Mock()
            mock_version.__contains__ = Mock(return_value=True)
            mock_packaging.version.Version.return_value = Mock()
            mock_packaging.specifiers.SpecifierSet.return_value = mock_version
            
            result = version_checker.check_python_version(">=3.8")
            assert result is True
    
    @patch('fastapi_shield.plugin_system.PACKAGING_AVAILABLE', False)
    def test_python_version_checking_no_packaging(self, version_checker):
        """Test Python version checking without packaging library."""
        result = version_checker.check_python_version(">=3.8")
        assert result is True  # Should return True when packaging not available
    
    @patch('fastapi_shield.plugin_system.PACKAGING_AVAILABLE', True)
    def test_shield_version_checking(self, version_checker):
        """Test Shield version compatibility checking."""
        with patch('fastapi_shield.plugin_system.packaging') as mock_packaging:
            mock_version = Mock()
            mock_version.__contains__ = Mock(return_value=True)
            mock_packaging.version.Version.return_value = Mock()
            mock_packaging.specifiers.SpecifierSet.return_value = mock_version
            
            result = version_checker.check_shield_version(">=0.1.0", "0.2.0")
            assert result is True
    
    def test_version_checking_error_handling(self, version_checker):
        """Test version checking error handling."""
        with patch('fastapi_shield.plugin_system.packaging') as mock_packaging:
            mock_packaging.version.Version.side_effect = Exception("Parse error")
            
            result = version_checker.check_python_version("invalid_version")
            assert result is False


class TestPluginDiscovery:
    """Test plugin discovery functionality."""
    
    @pytest.fixture
    def temp_plugin_dir(self):
        """Create temporary plugin directory."""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        cleanup_temporary_files(temp_dir)
    
    def test_plugin_discovery_initialization(self):
        """Test plugin discovery initialization."""
        discovery = PluginDiscovery()
        assert len(discovery.search_paths) > 0
        assert all(isinstance(path, Path) for path in discovery.search_paths)
    
    def test_plugin_discovery_custom_paths(self):
        """Test plugin discovery with custom search paths."""
        custom_paths = [Path("/custom/path1"), Path("/custom/path2")]
        discovery = PluginDiscovery(search_paths=custom_paths)
        assert discovery.search_paths == custom_paths
    
    def test_discover_plugins_empty_directory(self, temp_plugin_dir):
        """Test plugin discovery in empty directory."""
        discovery = PluginDiscovery(search_paths=[temp_plugin_dir])
        plugins = discovery.discover_plugins()
        assert len(plugins) == 0
    
    def test_discover_standalone_python_plugin(self, temp_plugin_dir):
        """Test discovery of standalone Python plugin."""
        plugin_metadata = {
            "name": "StandalonePlugin",
            "version": "1.0.0",
            "description": "Standalone test plugin",
            "author": "Test Author"
        }
        
        plugin_code = '''
from fastapi_shield.plugin_system import ShieldPlugin
from fastapi_shield.shield import Shield

class StandalonePlugin(ShieldPlugin):
    def create_shields(self):
        return []
'''
        
        plugin_file = create_temporary_plugin_file(plugin_code, plugin_metadata)
        temp_plugin_dir.joinpath(plugin_file.name).write_text(plugin_file.read_text())
        cleanup_temporary_files(plugin_file)
        
        discovery = PluginDiscovery(search_paths=[temp_plugin_dir])
        plugins = discovery.discover_plugins()
        
        assert len(plugins) == 1
        assert plugins[0]["metadata"]["name"] == "StandalonePlugin"
        assert plugins[0]["type"] == "standalone"
    
    def test_discover_package_plugin_yaml(self, temp_plugin_dir):
        """Test discovery of package plugin with YAML metadata."""
        plugin_metadata = {
            "name": "PackagePlugin",
            "version": "2.0.0", 
            "description": "Package test plugin",
            "author": "Test Author",
            "plugin_type": "shield"
        }
        
        plugin_code = '''
from fastapi_shield.plugin_system import ShieldPlugin

class PackagePlugin(ShieldPlugin):
    def create_shields(self):
        return []
'''
        
        package_dir = create_temporary_plugin_package(
            plugin_code, plugin_metadata, "plugin.yaml"
        )
        
        # Move to temp directory
        import shutil
        final_package_dir = temp_plugin_dir / package_dir.name
        shutil.move(str(package_dir), str(final_package_dir))
        cleanup_temporary_files(package_dir.parent)
        
        discovery = PluginDiscovery(search_paths=[temp_plugin_dir])
        plugins = discovery.discover_plugins()
        
        assert len(plugins) == 1
        assert plugins[0]["metadata"]["name"] == "PackagePlugin"
        assert plugins[0]["type"] == "package"
    
    def test_discover_package_plugin_json(self, temp_plugin_dir):
        """Test discovery of package plugin with JSON metadata."""
        plugin_metadata = {
            "name": "JSONPlugin",
            "version": "1.5.0",
            "description": "JSON test plugin", 
            "author": "Test Author"
        }
        
        plugin_code = '''
from fastapi_shield.plugin_system import ExtensionPlugin

class JSONPlugin(ExtensionPlugin):
    async def extend_functionality(self, context):
        return context
'''
        
        package_dir = create_temporary_plugin_package(
            plugin_code, plugin_metadata, "plugin.json"
        )
        
        # Move to temp directory
        import shutil
        final_package_dir = temp_plugin_dir / package_dir.name
        shutil.move(str(package_dir), str(final_package_dir))
        cleanup_temporary_files(package_dir.parent)
        
        discovery = PluginDiscovery(search_paths=[temp_plugin_dir])
        plugins = discovery.discover_plugins()
        
        assert len(plugins) == 1
        assert plugins[0]["metadata"]["name"] == "JSONPlugin"
    
    def test_discover_plugins_deduplication(self, temp_plugin_dir):
        """Test plugin discovery deduplication."""
        plugin_metadata = {
            "name": "DuplicatePlugin",
            "version": "1.0.0",
            "description": "Duplicate test plugin",
            "author": "Test Author"
        }
        
        plugin_code = '''
from fastapi_shield.plugin_system import ShieldPlugin

class DuplicatePlugin(ShieldPlugin):
    def create_shields(self):
        return []
'''
        
        # Create two identical plugins in different formats
        package_dir1 = create_temporary_plugin_package(
            plugin_code, plugin_metadata, "plugin.yaml"
        )
        package_dir2 = create_temporary_plugin_package(
            plugin_code, plugin_metadata, "plugin.json"
        )
        
        # Move to temp directory
        import shutil
        shutil.move(str(package_dir1), str(temp_plugin_dir / "duplicate1"))
        shutil.move(str(package_dir2), str(temp_plugin_dir / "duplicate2"))
        cleanup_temporary_files(package_dir1.parent, package_dir2.parent)
        
        discovery = PluginDiscovery(search_paths=[temp_plugin_dir])
        plugins = discovery.discover_plugins()
        
        # Should only find one due to deduplication
        assert len(plugins) == 1
        assert plugins[0]["metadata"]["name"] == "DuplicatePlugin"


class TestPluginRegistry:
    """Test plugin registry functionality."""
    
    @pytest.fixture
    def registry(self):
        """Create a plugin registry for testing."""
        return PluginRegistry()
    
    @pytest.fixture
    def mock_plugin(self):
        """Create a mock plugin for testing."""
        return MockShieldPlugin()
    
    def test_registry_initialization(self, registry):
        """Test registry initialization."""
        assert len(registry._plugins) == 0
        assert len(registry._metadata) == 0
        assert len(registry._configurations) == 0
        assert len(registry._states) == 0
    
    @pytest.mark.asyncio
    async def test_register_plugin(self, registry, mock_plugin):
        """Test plugin registration."""
        await registry.register_plugin(mock_plugin)
        
        assert mock_plugin.metadata.name in registry._plugins
        assert mock_plugin.state == PluginState.REGISTERED
        assert registry.get_plugin(mock_plugin.metadata.name) is mock_plugin
    
    @pytest.mark.asyncio
    async def test_register_plugin_duplicate(self, registry, mock_plugin):
        """Test registering duplicate plugin."""
        await registry.register_plugin(mock_plugin)
        
        # Try to register again
        with pytest.raises(PluginError, match="already registered"):
            await registry.register_plugin(mock_plugin)
    
    @pytest.mark.asyncio
    async def test_register_plugin_with_configuration(self, registry, mock_plugin):
        """Test plugin registration with custom configuration."""
        config = PluginConfiguration(enabled=False)
        await registry.register_plugin(mock_plugin, config)
        
        assert mock_plugin.config is config
        assert not mock_plugin.config.enabled
    
    @pytest.mark.asyncio
    async def test_unregister_plugin(self, registry, mock_plugin):
        """Test plugin unregistration."""
        await registry.register_plugin(mock_plugin)
        
        registry.unregister_plugin(mock_plugin.metadata.name)
        
        assert mock_plugin.metadata.name not in registry._plugins
        assert mock_plugin.state == PluginState.REMOVED
    
    def test_unregister_nonexistent_plugin(self, registry):
        """Test unregistering non-existent plugin."""
        with pytest.raises(PluginNotFoundError):
            registry.unregister_plugin("nonexistent")
    
    @pytest.mark.asyncio
    async def test_get_plugins_by_type(self, registry):
        """Test getting plugins by type."""
        shield_plugin = MockShieldPlugin()
        processor_plugin = MockProcessorPlugin()
        
        await registry.register_plugin(shield_plugin)
        await registry.register_plugin(processor_plugin)
        
        shield_plugins = registry.get_plugins(plugin_type=PluginType.SHIELD)
        processor_plugins = registry.get_plugins(plugin_type=PluginType.PROCESSOR)
        
        assert len(shield_plugins) == 1
        assert len(processor_plugins) == 1
        assert shield_plugins[0] is shield_plugin
        assert processor_plugins[0] is processor_plugin
    
    @pytest.mark.asyncio
    async def test_get_plugins_by_state(self, registry, mock_plugin):
        """Test getting plugins by state."""
        await registry.register_plugin(mock_plugin)
        
        registered_plugins = registry.get_plugins(state=PluginState.REGISTERED)
        active_plugins = registry.get_plugins(state=PluginState.ACTIVE)
        
        assert len(registered_plugins) == 1
        assert len(active_plugins) == 0
        assert registered_plugins[0] is mock_plugin
    
    @pytest.mark.asyncio
    async def test_set_plugin_state(self, registry, mock_plugin):
        """Test setting plugin state."""
        await registry.register_plugin(mock_plugin)
        
        registry.set_plugin_state(mock_plugin.metadata.name, PluginState.ACTIVE)
        
        assert registry.get_plugin_state(mock_plugin.metadata.name) == PluginState.ACTIVE
        assert mock_plugin.state == PluginState.ACTIVE
    
    @pytest.mark.asyncio
    async def test_list_plugins(self, registry):
        """Test listing plugins."""
        shield_plugin = MockShieldPlugin()
        processor_plugin = MockProcessorPlugin()
        
        await registry.register_plugin(shield_plugin)
        await registry.register_plugin(processor_plugin)
        
        plugins_info = registry.list_plugins()
        
        assert len(plugins_info) == 2
        plugin_names = [info["name"] for info in plugins_info]
        assert "MockShieldPlugin" in plugin_names
        assert "MockProcessorPlugin" in plugin_names
    
    @pytest.mark.asyncio
    async def test_dependency_checking(self, registry):
        """Test plugin dependency checking."""
        plugin1 = MockShieldPlugin()
        plugin2 = MockProcessorPlugin()
        plugin2.config.dependencies = ["MockShieldPlugin"]
        
        # Register dependency first
        await registry.register_plugin(plugin1)
        await registry.register_plugin(plugin2)  # Should succeed
        
        # Try to register plugin with missing dependency
        plugin3 = MockValidatorPlugin()
        plugin3.config.dependencies = ["NonExistentPlugin"]
        
        with pytest.raises(PluginDependencyError):
            await registry.register_plugin(plugin3)
    
    @pytest.mark.asyncio
    async def test_conflict_checking(self, registry):
        """Test plugin conflict checking."""
        plugin1 = MockShieldPlugin()
        await registry.register_plugin(plugin1)
        
        # Try to register conflicting plugin
        plugin2 = MockProcessorPlugin()
        plugin2.config.conflicts = ["MockShieldPlugin"]
        
        with pytest.raises(PluginConflictError):
            await registry.register_plugin(plugin2)


class TestPluginManager:
    """Test plugin manager functionality."""
    
    @pytest.fixture
    def mock_discovery(self):
        """Create a mock discovery for testing."""
        return MockPluginDiscovery()
    
    @pytest.fixture
    def mock_registry(self):
        """Create a mock registry for testing."""
        return MockPluginRegistry()
    
    @pytest.fixture
    def mock_version_checker(self):
        """Create a mock version checker for testing."""
        return MockVersionChecker()
    
    @pytest.fixture
    def plugin_manager(self, mock_discovery, mock_registry, mock_version_checker):
        """Create a plugin manager for testing."""
        return PluginManager(mock_discovery, mock_registry, mock_version_checker)
    
    @pytest.mark.asyncio
    async def test_plugin_manager_initialization(self, plugin_manager):
        """Test plugin manager initialization."""
        assert plugin_manager.discovery is not None
        assert plugin_manager.registry is not None
        assert plugin_manager.version_checker is not None
        assert len(plugin_manager._active_plugins) == 0
    
    @pytest.mark.asyncio
    async def test_discover_and_load_plugins(self, plugin_manager, mock_discovery):
        """Test discovering and loading plugins."""
        # Mock discovered plugins
        plugin_info = {
            "metadata": {
                "name": "TestPlugin",
                "version": "1.0.0",
                "description": "Test plugin",
                "author": "Test Author"
            },
            "path": "/fake/path",
            "type": "standalone"
        }
        mock_discovery.plugins_to_discover = [plugin_info]
        
        # Mock loading
        with patch.object(plugin_manager, 'load_plugin', new_callable=AsyncMock) as mock_load:
            mock_plugin = MockShieldPlugin()
            mock_load.return_value = mock_plugin
            
            with patch.object(plugin_manager, 'activate_plugin', new_callable=AsyncMock) as mock_activate:
                count = await plugin_manager.discover_and_load_plugins()
                
                assert count == 1
                assert mock_discovery.discovery_count == 1
                mock_load.assert_called_once_with(plugin_info)
                mock_activate.assert_called_once_with(mock_plugin.metadata.name)
    
    @pytest.mark.asyncio
    async def test_load_plugin_version_compatibility(self, plugin_manager, mock_version_checker):
        """Test plugin loading with version compatibility checking."""
        plugin_info = {
            "metadata": {
                "name": "TestPlugin",
                "version": "1.0.0",
                "description": "Test plugin",
                "author": "Test Author",
                "requires_python": ">=3.8",
                "requires_shield": ">=0.1.0"
            },
            "path": "/fake/path",
            "type": "standalone"
        }
        
        # Mock incompatible Python version
        mock_version_checker.python_compatible = False
        
        with pytest.raises(PluginVersionError, match="requires Python"):
            await plugin_manager.load_plugin(plugin_info)
        
        # Mock incompatible Shield version
        mock_version_checker.python_compatible = True
        mock_version_checker.shield_compatible = False
        
        with pytest.raises(PluginVersionError, match="requires Shield"):
            await plugin_manager.load_plugin(plugin_info)
    
    @pytest.mark.asyncio
    async def test_activate_plugin(self, plugin_manager):
        """Test plugin activation."""
        mock_plugin = MockShieldPlugin()
        await plugin_manager.registry.register_plugin(mock_plugin)
        
        await plugin_manager.activate_plugin(mock_plugin.metadata.name)
        
        assert mock_plugin.metadata.name in plugin_manager._active_plugins
        assert mock_plugin.activation_count == 1
    
    @pytest.mark.asyncio
    async def test_activate_plugin_with_dependencies(self, plugin_manager):
        """Test plugin activation with dependencies."""
        # Create custom plugin class with specific name
        class DependencyPlugin(MockShieldPlugin):
            @property
            def metadata(self):
                meta = super().metadata
                return PluginMetadata(
                    name="Dependency",
                    version=meta.version,
                    description=meta.description,
                    author=meta.author,
                    plugin_type=meta.plugin_type,
                    priority=meta.priority
                )
        
        dependency = DependencyPlugin()
        dependent = MockProcessorPlugin()
        dependent.config.dependencies = ["Dependency"]
        
        await plugin_manager.registry.register_plugin(dependency)
        await plugin_manager.registry.register_plugin(dependent)
        
        # Mock registry methods
        plugin_manager.registry._dependencies = {
            "Dependency": [],
            "MockProcessorPlugin": ["Dependency"]
        }
        
        await plugin_manager.activate_plugin("MockProcessorPlugin")
        
        # Both plugins should be active
        assert "Dependency" in plugin_manager._active_plugins
        assert "MockProcessorPlugin" in plugin_manager._active_plugins
    
    @pytest.mark.asyncio
    async def test_deactivate_plugin(self, plugin_manager):
        """Test plugin deactivation."""
        mock_plugin = MockShieldPlugin()
        await plugin_manager.registry.register_plugin(mock_plugin)
        await plugin_manager.activate_plugin(mock_plugin.metadata.name)
        
        await plugin_manager.deactivate_plugin(mock_plugin.metadata.name)
        
        assert mock_plugin.metadata.name not in plugin_manager._active_plugins
        assert mock_plugin.deactivation_count == 1
    
    @pytest.mark.asyncio
    async def test_deactivate_plugin_with_dependents(self, plugin_manager):
        """Test plugin deactivation with dependent plugins."""
        dependency = MockShieldPlugin()
        dependent = MockProcessorPlugin()
        dependent.config.dependencies = ["MockShieldPlugin"]
        
        await plugin_manager.registry.register_plugin(dependency)
        await plugin_manager.registry.register_plugin(dependent)
        
        # Mock both as active
        plugin_manager._active_plugins.add("MockShieldPlugin")
        plugin_manager._active_plugins.add("MockProcessorPlugin")
        
        # Mock registry dependencies
        plugin_manager.registry._configurations = {
            "MockShieldPlugin": PluginConfiguration(),
            "MockProcessorPlugin": PluginConfiguration(dependencies=["MockShieldPlugin"])
        }
        
        with pytest.raises(PluginDependencyError, match="required by active plugins"):
            await plugin_manager.deactivate_plugin("MockShieldPlugin")
    
    @pytest.mark.asyncio
    async def test_reload_plugin(self, plugin_manager):
        """Test plugin reloading."""
        mock_plugin = MockShieldPlugin()
        await plugin_manager.registry.register_plugin(mock_plugin)
        await plugin_manager.activate_plugin(mock_plugin.metadata.name)
        
        # Mock rediscovery
        plugin_info = {
            "metadata": {
                "name": "MockShieldPlugin",
                "version": "2.0.0",
                "description": "Updated mock plugin",
                "author": "Test Author"
            },
            "path": "/fake/path",
            "type": "standalone"
        }
        plugin_manager.discovery.plugins_to_discover = [plugin_info]
        
        with patch.object(plugin_manager, 'load_plugin', new_callable=AsyncMock) as mock_load:
            new_plugin = MockShieldPlugin()
            mock_load.return_value = new_plugin
            
            # Mock the load_plugin to also register the plugin
            async def mock_load_and_register(plugin_info):
                await plugin_manager.registry.register_plugin(new_plugin)
                return new_plugin
            
            mock_load.side_effect = mock_load_and_register
            
            await plugin_manager.reload_plugin("MockShieldPlugin")
            
            assert mock_plugin.cleanup_count == 1
            mock_load.assert_called_once_with(plugin_info)
    
    @pytest.mark.asyncio
    async def test_unload_plugin(self, plugin_manager):
        """Test plugin unloading."""
        mock_plugin = MockShieldPlugin()
        await plugin_manager.registry.register_plugin(mock_plugin)
        await plugin_manager.activate_plugin(mock_plugin.metadata.name)
        
        await plugin_manager.unload_plugin(mock_plugin.metadata.name)
        
        assert mock_plugin.metadata.name not in plugin_manager._active_plugins
        assert mock_plugin.cleanup_count == 1
        assert plugin_manager.registry.unregistration_count == 1
    
    @pytest.mark.asyncio
    async def test_get_active_plugins(self, plugin_manager):
        """Test getting active plugins."""
        shield_plugin = MockShieldPlugin()
        processor_plugin = MockProcessorPlugin()
        
        await plugin_manager.registry.register_plugin(shield_plugin)
        await plugin_manager.registry.register_plugin(processor_plugin)
        plugin_manager.registry.set_plugin_state("MockShieldPlugin", PluginState.ACTIVE)
        plugin_manager.registry.set_plugin_state("MockProcessorPlugin", PluginState.ACTIVE)
        
        active_plugins = plugin_manager.get_active_plugins()
        shield_plugins = plugin_manager.get_active_plugins(PluginType.SHIELD)
        
        assert len(active_plugins) == 2
        assert len(shield_plugins) == 1
    
    @pytest.mark.asyncio
    async def test_get_plugin_health(self, plugin_manager):
        """Test getting plugin health status."""
        mock_plugin = MockShieldPlugin()
        await plugin_manager.registry.register_plugin(mock_plugin)
        
        health = plugin_manager.get_plugin_health()
        
        assert "MockShieldPlugin" in health
        assert health["MockShieldPlugin"]["name"] == "MockShieldPlugin"
        assert "healthy" in health["MockShieldPlugin"]
    
    @pytest.mark.asyncio
    async def test_get_plugin_metrics(self, plugin_manager):
        """Test getting plugin metrics."""
        mock_plugin = MockShieldPlugin()
        await plugin_manager.registry.register_plugin(mock_plugin)
        
        metrics = plugin_manager.get_plugin_metrics()
        
        assert "MockShieldPlugin" in metrics
        assert metrics["MockShieldPlugin"]["name"] == "MockShieldPlugin"
    
    @pytest.mark.asyncio
    async def test_shutdown(self, plugin_manager):
        """Test plugin manager shutdown."""
        mock_plugin1 = MockShieldPlugin()
        mock_plugin2 = MockProcessorPlugin()
        
        await plugin_manager.registry.register_plugin(mock_plugin1)
        await plugin_manager.registry.register_plugin(mock_plugin2)
        plugin_manager._active_plugins.add("MockShieldPlugin")
        plugin_manager._active_plugins.add("MockProcessorPlugin")
        
        with patch.object(plugin_manager, 'deactivate_plugin', new_callable=AsyncMock) as mock_deactivate:
            await plugin_manager.shutdown()
            
            assert mock_deactivate.call_count == 2
            assert mock_plugin1.cleanup_count == 1
            assert mock_plugin2.cleanup_count == 1


class TestErrorHandling:
    """Test plugin system error handling."""
    
    @pytest.fixture
    def failing_plugin(self):
        """Create a plugin that fails during operations."""
        return MockFailingPlugin(fail_on=["initialize", "activate"])
    
    @pytest.fixture
    def registry(self):
        """Create a plugin registry for testing."""
        return PluginRegistry()
    
    @pytest.mark.asyncio
    async def test_plugin_registration_validation_failure(self, registry):
        """Test plugin registration with validation failure."""
        failing_plugin = MockFailingPlugin(fail_on=["validate_configuration"])
        
        with pytest.raises(PluginConfigurationError):
            await registry.register_plugin(failing_plugin)
    
    @pytest.mark.asyncio
    async def test_plugin_initialization_failure(self, failing_plugin):
        """Test plugin initialization failure."""
        with pytest.raises(RuntimeError, match="Mock initialization failure"):
            await failing_plugin.initialize()
        
        assert failing_plugin.operation_counts["initialize"] == 1
    
    @pytest.mark.asyncio
    async def test_plugin_activation_failure(self, failing_plugin):
        """Test plugin activation failure."""
        with pytest.raises(RuntimeError, match="Mock activation failure"):
            await failing_plugin.activate()
        
        assert failing_plugin.operation_counts["activate"] == 1
    
    @pytest.mark.asyncio
    async def test_plugin_manager_error_handling(self):
        """Test plugin manager error handling during operations."""
        plugin_manager = PluginManager()
        
        # Test activating non-existent plugin
        with pytest.raises(PluginNotFoundError):
            await plugin_manager.activate_plugin("NonExistentPlugin")
        
        # Test deactivating non-existent plugin
        with pytest.raises(PluginNotFoundError):
            await plugin_manager.deactivate_plugin("NonExistentPlugin")
        
        # Test unloading non-existent plugin
        with pytest.raises(PluginNotFoundError):
            await plugin_manager.unload_plugin("NonExistentPlugin")


class TestConcurrency:
    """Test plugin system concurrency and thread safety."""
    
    @pytest.mark.asyncio
    async def test_concurrent_plugin_registration(self):
        """Test concurrent plugin registration."""
        registry = PluginRegistry()
        
        # Create plugins with unique names
        class NamedMockShieldPlugin(MockShieldPlugin):
            def __init__(self, name: str):
                super().__init__()
                self._custom_name = name
            
            @property
            def metadata(self) -> PluginMetadata:
                meta = super().metadata
                return PluginMetadata(
                    name=self._custom_name,
                    version=meta.version,
                    description=meta.description,
                    author=meta.author,
                    plugin_type=meta.plugin_type,
                    priority=meta.priority
                )
        
        plugins = [NamedMockShieldPlugin(f"Plugin{i}") for i in range(10)]
        
        async def register_plugin(plugin):
            await registry.register_plugin(plugin)
        
        # Register plugins concurrently
        await asyncio.gather(*[register_plugin(plugin) for plugin in plugins])
        
        assert len(registry._plugins) == 10
    
    @pytest.mark.asyncio
    async def test_concurrent_plugin_activation(self):
        """Test concurrent plugin activation."""
        plugin_manager = PluginManager()
        
        # Create plugins with unique names
        class NamedMockShieldPlugin(MockShieldPlugin):
            def __init__(self, name: str):
                super().__init__()
                self._custom_name = name
            
            @property
            def metadata(self) -> PluginMetadata:
                meta = super().metadata
                return PluginMetadata(
                    name=self._custom_name,
                    version=meta.version,
                    description=meta.description,
                    author=meta.author,
                    plugin_type=meta.plugin_type,
                    priority=meta.priority
                )
        
        plugins = [NamedMockShieldPlugin(f"Plugin{i}") for i in range(5)]
        
        # Register plugins
        for plugin in plugins:
            await plugin_manager.registry.register_plugin(plugin)
        
        # Activate plugins concurrently
        await asyncio.gather(*[
            plugin_manager.activate_plugin(f"Plugin{i}")
            for i in range(5)
        ])
        
        assert len(plugin_manager._active_plugins) == 5


class TestGlobalPluginManager:
    """Test global plugin manager functionality."""
    
    def test_get_plugin_manager_singleton(self):
        """Test global plugin manager singleton behavior."""
        manager1 = get_plugin_manager()
        manager2 = get_plugin_manager()
        
        assert manager1 is manager2
    
    def test_set_plugin_manager(self):
        """Test setting custom global plugin manager."""
        custom_manager = PluginManager()
        set_plugin_manager(custom_manager)
        
        retrieved_manager = get_plugin_manager()
        assert retrieved_manager is custom_manager
        
        # Reset for other tests
        set_plugin_manager(PluginManager())
    
    @pytest.mark.asyncio
    async def test_discover_plugins_convenience_function(self):
        """Test convenience function for discovering plugins."""
        with patch('fastapi_shield.plugin_system.get_plugin_manager') as mock_get_manager:
            mock_manager = Mock()
            mock_manager.discover_and_load_plugins = AsyncMock(return_value=5)
            mock_get_manager.return_value = mock_manager
            
            count = await discover_plugins()
            
            assert count == 5
            mock_manager.discover_and_load_plugins.assert_called_once()
    
    def test_get_active_shield_plugins_convenience_function(self):
        """Test convenience function for getting active shield plugins."""
        with patch('fastapi_shield.plugin_system.get_plugin_manager') as mock_get_manager:
            mock_manager = Mock()
            shield_plugin = MockShieldPlugin()
            processor_plugin = MockProcessorPlugin()
            mock_manager.get_active_plugins.return_value = [shield_plugin, processor_plugin]
            mock_get_manager.return_value = mock_manager
            
            shield_plugins = get_active_shield_plugins()
            
            assert len(shield_plugins) == 1
            assert shield_plugins[0] is shield_plugin
    
    def test_get_shields_from_plugins_convenience_function(self):
        """Test convenience function for getting shields from plugins."""
        with patch('fastapi_shield.plugin_system.get_active_shield_plugins') as mock_get_shield_plugins:
            shield_plugin = MockShieldPlugin()
            shield_plugin._shield_instances = [Mock(), Mock()]  # Mock shields
            mock_get_shield_plugins.return_value = [shield_plugin]
            
            shields = get_shields_from_plugins()
            
            assert len(shields) == 2


class TestPluginSystemIntegration:
    """Test plugin system integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_full_plugin_lifecycle(self):
        """Test complete plugin lifecycle from discovery to cleanup."""
        plugin_manager = PluginManager()
        
        # Create mock plugin
        mock_plugin = MockShieldPlugin()
        await plugin_manager.registry.register_plugin(mock_plugin)
        
        # Test activation
        await plugin_manager.activate_plugin("MockShieldPlugin")
        assert mock_plugin.metadata.name in plugin_manager._active_plugins
        assert mock_plugin.activation_count == 1
        
        # Test health check
        health = plugin_manager.get_plugin_health()
        assert "MockShieldPlugin" in health
        assert health["MockShieldPlugin"]["healthy"]
        
        # Test metrics
        metrics = plugin_manager.get_plugin_metrics()
        assert "MockShieldPlugin" in metrics
        
        # Test deactivation
        await plugin_manager.deactivate_plugin("MockShieldPlugin")
        assert mock_plugin.metadata.name not in plugin_manager._active_plugins
        assert mock_plugin.deactivation_count == 1
        
        # Test cleanup
        await plugin_manager.unload_plugin("MockShieldPlugin")
        assert mock_plugin.cleanup_count == 1
    
    @pytest.mark.asyncio
    async def test_plugin_dependency_resolution(self):
        """Test plugin dependency resolution."""
        plugin_manager = PluginManager()
        
        # Create plugins with dependencies using custom classes
        class BasePlugin(MockShieldPlugin):
            @property
            def metadata(self):
                meta = super().metadata
                return PluginMetadata(
                    name="BasePlugin",
                    version=meta.version,
                    description=meta.description,
                    author=meta.author,
                    plugin_type=meta.plugin_type,
                    priority=meta.priority
                )
        
        class DependentPlugin(MockProcessorPlugin):
            def __init__(self):
                super().__init__()
                self.config.dependencies = ["BasePlugin"]
                
            @property
            def metadata(self):
                meta = super().metadata
                return PluginMetadata(
                    name="DependentPlugin",
                    version=meta.version,
                    description=meta.description,
                    author=meta.author,
                    plugin_type=meta.plugin_type,
                    priority=meta.priority
                )
        
        base_plugin = BasePlugin()
        dependent_plugin = DependentPlugin()
        
        await plugin_manager.registry.register_plugin(base_plugin)
        await plugin_manager.registry.register_plugin(dependent_plugin)
        
        # Mock registry dependencies
        plugin_manager.registry._dependencies = {
            "BasePlugin": [],
            "DependentPlugin": ["BasePlugin"]
        }
        
        # Activate dependent plugin (should activate base plugin first)
        await plugin_manager.activate_plugin("DependentPlugin")
        
        # Both plugins should be active
        assert "BasePlugin" in plugin_manager._active_plugins
        assert "DependentPlugin" in plugin_manager._active_plugins
    
    @pytest.mark.asyncio
    async def test_plugin_type_filtering(self):
        """Test filtering plugins by type."""
        registry = PluginRegistry()
        
        # Register different types of plugins
        shield_plugin = MockShieldPlugin()
        processor_plugin = MockProcessorPlugin() 
        validator_plugin = MockValidatorPlugin()
        transformer_plugin = MockTransformerPlugin()
        extension_plugin = MockExtensionPlugin()
        
        await registry.register_plugin(shield_plugin)
        await registry.register_plugin(processor_plugin)
        await registry.register_plugin(validator_plugin)
        await registry.register_plugin(transformer_plugin)
        await registry.register_plugin(extension_plugin)
        
        # Test filtering by type
        shield_plugins = registry.get_plugins(plugin_type=PluginType.SHIELD)
        processor_plugins = registry.get_plugins(plugin_type=PluginType.PROCESSOR)
        validator_plugins = registry.get_plugins(plugin_type=PluginType.VALIDATOR)
        transformer_plugins = registry.get_plugins(plugin_type=PluginType.TRANSFORMER)
        extension_plugins = registry.get_plugins(plugin_type=PluginType.EXTENSION)
        
        assert len(shield_plugins) == 1
        assert len(processor_plugins) == 1
        assert len(validator_plugins) == 1
        assert len(transformer_plugins) == 1
        assert len(extension_plugins) == 1
        
        assert isinstance(shield_plugins[0], MockShieldPlugin)
        assert isinstance(processor_plugins[0], MockProcessorPlugin)
        assert isinstance(validator_plugins[0], MockValidatorPlugin)
        assert isinstance(transformer_plugins[0], MockTransformerPlugin)
        assert isinstance(extension_plugins[0], MockExtensionPlugin)
    
    @pytest.mark.asyncio
    async def test_plugin_error_recovery(self):
        """Test plugin system error recovery."""
        plugin_manager = PluginManager()
        
        # Create plugin that fails during activation
        failing_plugin = MockFailingPlugin(fail_on=["activate"])
        await plugin_manager.registry.register_plugin(failing_plugin)
        
        # Try to activate failing plugin
        with pytest.raises(PluginError):
            await plugin_manager.activate_plugin("MockFailingPlugin")
        
        # Plugin should be in error state
        assert plugin_manager.registry.get_plugin_state("MockFailingPlugin") == PluginState.ERROR
        
        # Create successful plugin using custom class
        class SuccessPlugin(MockShieldPlugin):
            @property
            def metadata(self):
                meta = super().metadata
                return PluginMetadata(
                    name="SuccessPlugin",
                    version=meta.version,
                    description=meta.description,
                    author=meta.author,
                    plugin_type=meta.plugin_type,
                    priority=meta.priority
                )
        
        success_plugin = SuccessPlugin()
        await plugin_manager.registry.register_plugin(success_plugin)
        
        # Should be able to activate successful plugin despite previous failure
        await plugin_manager.activate_plugin("SuccessPlugin")
        assert "SuccessPlugin" in plugin_manager._active_plugins