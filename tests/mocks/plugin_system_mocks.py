"""Mock classes for plugin system testing."""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import Mock, MagicMock

from fastapi import Request, Response
from fastapi_shield.shield import Shield
from fastapi_shield.plugin_system import (
    PluginInterface, ShieldPlugin, ProcessorPlugin, ValidatorPlugin,
    TransformerPlugin, ExtensionPlugin, PluginMetadata, PluginConfiguration,
    PluginType, PluginPriority, PluginState
)


class MockShield(Shield):
    """Mock shield for testing."""
    
    def __init__(self, name: str = "MockShield", should_block: bool = False):
        self.name = name
        self.should_block = should_block
        self.call_count = 0
        
        async def mock_guard_func(request: Request) -> Optional[Dict[str, Any]]:
            self.call_count += 1
            if self.should_block:
                return None
            return {"mock_data": f"from_{self.name}"}
        
        super().__init__(mock_guard_func, name=name)


class MockShieldPlugin(ShieldPlugin):
    """Mock shield plugin for testing."""
    
    def __init__(self, config: Optional[PluginConfiguration] = None, 
                 num_shields: int = 1, shield_names: Optional[List[str]] = None):
        super().__init__(config)
        self.num_shields = num_shields
        self.shield_names = shield_names or [f"MockShield{i}" for i in range(num_shields)]
        self.initialization_count = 0
        self.activation_count = 0
        self.deactivation_count = 0
        self.cleanup_count = 0
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="MockShieldPlugin",
            version="1.0.0",
            description="Mock shield plugin for testing",
            author="Test Author",
            author_email="test@example.com",
            plugin_type=PluginType.SHIELD,
            priority=PluginPriority.NORMAL,
            config_schema={
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "max_requests": {"type": "integer", "minimum": 1}
                }
            }
        )
    
    def create_shields(self) -> List[Shield]:
        """Create mock shields."""
        return [MockShield(name=name) for name in self.shield_names]
    
    async def initialize(self) -> None:
        """Initialize mock plugin."""
        self.initialization_count += 1
        await super().initialize()
    
    async def activate(self) -> None:
        """Activate mock plugin."""
        self.activation_count += 1
        await super().activate()
    
    async def deactivate(self) -> None:
        """Deactivate mock plugin."""
        self.deactivation_count += 1
        await super().deactivate()
    
    async def cleanup(self) -> None:
        """Cleanup mock plugin."""
        self.cleanup_count += 1
        await super().cleanup()


class MockProcessorPlugin(ProcessorPlugin):
    """Mock processor plugin for testing."""
    
    def __init__(self, config: Optional[PluginConfiguration] = None):
        super().__init__(config)
        self.request_processing_count = 0
        self.response_processing_count = 0
        self.initialization_count = 0
        self.activation_count = 0
        self.deactivation_count = 0
        self.cleanup_count = 0
        self.should_raise_error = False
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="MockProcessorPlugin",
            version="2.1.0",
            description="Mock processor plugin for testing",
            author="Test Author",
            plugin_type=PluginType.PROCESSOR,
            priority=PluginPriority.HIGH
        )
    
    async def initialize(self) -> None:
        """Initialize mock plugin."""
        self.initialization_count += 1
        if self.should_raise_error:
            raise RuntimeError("Mock initialization error")
    
    async def activate(self) -> None:
        """Activate mock plugin."""
        self.activation_count += 1
        if self.should_raise_error:
            raise RuntimeError("Mock activation error")
    
    async def deactivate(self) -> None:
        """Deactivate mock plugin."""
        self.deactivation_count += 1
    
    async def cleanup(self) -> None:
        """Cleanup mock plugin."""
        self.cleanup_count += 1
    
    async def process_request(self, request: Request) -> Request:
        """Process mock request."""
        self.request_processing_count += 1
        # Add mock processing header
        if hasattr(request, 'headers'):
            request.headers['X-Processed-By'] = 'MockProcessorPlugin'
        return request
    
    async def process_response(self, request: Request, response: Response) -> Response:
        """Process mock response."""
        self.response_processing_count += 1
        # Add mock processing header
        response.headers['X-Response-Processed-By'] = 'MockProcessorPlugin'
        return response


class MockValidatorPlugin(ValidatorPlugin):
    """Mock validator plugin for testing."""
    
    def __init__(self, config: Optional[PluginConfiguration] = None, 
                 validation_errors: Optional[List[str]] = None):
        super().__init__(config)
        self.validation_errors = validation_errors or []
        self.validation_count = 0
        self.initialization_count = 0
        self.activation_count = 0
        self.deactivation_count = 0
        self.cleanup_count = 0
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="MockValidatorPlugin",
            version="1.2.3",
            description="Mock validator plugin for testing",
            author="Test Author",
            plugin_type=PluginType.VALIDATOR,
            priority=PluginPriority.CRITICAL
        )
    
    async def initialize(self) -> None:
        """Initialize mock plugin."""
        self.initialization_count += 1
    
    async def activate(self) -> None:
        """Activate mock plugin."""
        self.activation_count += 1
    
    async def deactivate(self) -> None:
        """Deactivate mock plugin."""
        self.deactivation_count += 1
    
    async def cleanup(self) -> None:
        """Cleanup mock plugin."""
        self.cleanup_count += 1
    
    async def validate_request(self, request: Request) -> List[str]:
        """Validate mock request."""
        self.validation_count += 1
        return self.validation_errors.copy()


class MockTransformerPlugin(TransformerPlugin):
    """Mock transformer plugin for testing."""
    
    def __init__(self, config: Optional[PluginConfiguration] = None):
        super().__init__(config)
        self.transformation_count = 0
        self.initialization_count = 0
        self.activation_count = 0
        self.deactivation_count = 0
        self.cleanup_count = 0
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="MockTransformerPlugin",
            version="0.5.0",
            description="Mock transformer plugin for testing",
            author="Test Author",
            plugin_type=PluginType.TRANSFORMER,
            priority=PluginPriority.LOW
        )
    
    async def initialize(self) -> None:
        """Initialize mock plugin."""
        self.initialization_count += 1
    
    async def activate(self) -> None:
        """Activate mock plugin."""
        self.activation_count += 1
    
    async def deactivate(self) -> None:
        """Deactivate mock plugin."""
        self.deactivation_count += 1
    
    async def cleanup(self) -> None:
        """Cleanup mock plugin."""
        self.cleanup_count += 1
    
    async def transform_data(self, data: Any, transformation_type: str) -> Any:
        """Transform mock data."""
        self.transformation_count += 1
        
        if transformation_type == "uppercase":
            if isinstance(data, str):
                return data.upper()
        elif transformation_type == "reverse":
            if isinstance(data, (str, list)):
                return data[::-1]
        elif transformation_type == "multiply":
            if isinstance(data, (int, float)):
                return data * 2
        
        return data


class MockExtensionPlugin(ExtensionPlugin):
    """Mock extension plugin for testing."""
    
    def __init__(self, config: Optional[PluginConfiguration] = None):
        super().__init__(config)
        self.extension_count = 0
        self.initialization_count = 0
        self.activation_count = 0
        self.deactivation_count = 0
        self.cleanup_count = 0
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="MockExtensionPlugin",
            version="3.0.0",
            description="Mock extension plugin for testing",
            author="Test Author",
            plugin_type=PluginType.EXTENSION,
            priority=PluginPriority.BACKGROUND
        )
    
    async def initialize(self) -> None:
        """Initialize mock plugin."""
        self.initialization_count += 1
    
    async def activate(self) -> None:
        """Activate mock plugin."""
        self.activation_count += 1
    
    async def deactivate(self) -> None:
        """Deactivate mock plugin."""
        self.deactivation_count += 1
    
    async def cleanup(self) -> None:
        """Cleanup mock plugin."""
        self.cleanup_count += 1
    
    async def extend_functionality(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Extend mock functionality."""
        self.extension_count += 1
        context["mock_extension"] = "added_by_mock_extension_plugin"
        context["extension_count"] = self.extension_count
        return context


class MockFailingPlugin(PluginInterface):
    """Mock plugin that fails during various operations."""
    
    def __init__(self, config: Optional[PluginConfiguration] = None,
                 fail_on: Optional[List[str]] = None):
        super().__init__(config)
        self.fail_on = fail_on or []
        self.operation_counts = {
            "initialize": 0,
            "activate": 0,
            "deactivate": 0,
            "cleanup": 0,
            "validate_configuration": 0
        }
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="MockFailingPlugin",
            version="1.0.0",
            description="Mock plugin that fails for testing error handling",
            author="Test Author",
            plugin_type=PluginType.EXTENSION
        )
    
    async def initialize(self) -> None:
        """Initialize with potential failure."""
        self.operation_counts["initialize"] += 1
        if "initialize" in self.fail_on:
            raise RuntimeError("Mock initialization failure")
    
    async def activate(self) -> None:
        """Activate with potential failure."""
        self.operation_counts["activate"] += 1
        if "activate" in self.fail_on:
            raise RuntimeError("Mock activation failure")
    
    async def deactivate(self) -> None:
        """Deactivate with potential failure."""
        self.operation_counts["deactivate"] += 1
        if "deactivate" in self.fail_on:
            raise RuntimeError("Mock deactivation failure")
    
    async def cleanup(self) -> None:
        """Cleanup with potential failure."""
        self.operation_counts["cleanup"] += 1
        if "cleanup" in self.fail_on:
            raise RuntimeError("Mock cleanup failure")
    
    async def validate_configuration(self) -> List[str]:
        """Validate configuration with potential failure."""
        self.operation_counts["validate_configuration"] += 1
        if "validate_configuration" in self.fail_on:
            raise RuntimeError("Mock validation failure")
        return []


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(self, headers: Optional[Dict[str, str]] = None,
                 query_params: Optional[Dict[str, str]] = None,
                 path_params: Optional[Dict[str, str]] = None,
                 body: Optional[bytes] = None):
        self.headers = headers or {}
        self.query_params = query_params or {}
        self.path_params = path_params or {}
        self._body = body or b""
        self.method = "GET"
        self.url = "http://example.com/test"
    
    async def body(self) -> bytes:
        """Get request body."""
        return self._body
    
    async def json(self) -> Any:
        """Get request JSON."""
        return json.loads(self._body.decode())


class MockResponse:
    """Mock FastAPI response for testing."""
    
    def __init__(self, status_code: int = 200, 
                 headers: Optional[Dict[str, str]] = None,
                 content: Any = None):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content


class MockPluginDiscovery:
    """Mock plugin discovery for testing."""
    
    def __init__(self, plugins_to_discover: Optional[List[Dict[str, Any]]] = None):
        self.plugins_to_discover = plugins_to_discover or []
        self.search_paths = []
        self.discovery_count = 0
    
    def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover mock plugins."""
        self.discovery_count += 1
        return self.plugins_to_discover.copy()


class MockPluginRegistry:
    """Mock plugin registry for testing."""
    
    def __init__(self):
        self._plugins: Dict[str, PluginInterface] = {}
        self._metadata: Dict[str, PluginMetadata] = {}
        self._configurations: Dict[str, PluginConfiguration] = {}
        self._states: Dict[str, PluginState] = {}
        self.registration_count = 0
        self.unregistration_count = 0
    
    async def register_plugin(self, plugin: PluginInterface, 
                       configuration: Optional[PluginConfiguration] = None) -> None:
        """Register mock plugin."""
        self.registration_count += 1
        name = plugin.metadata.name
        self._plugins[name] = plugin
        self._metadata[name] = plugin.metadata
        self._configurations[name] = configuration or plugin.config
        self._states[name] = PluginState.REGISTERED
    
    def unregister_plugin(self, name: str) -> None:
        """Unregister mock plugin."""
        self.unregistration_count += 1
        if name in self._plugins:
            del self._plugins[name]
            del self._metadata[name]
            del self._configurations[name]
            del self._states[name]
    
    def get_plugin(self, name: str) -> Optional[PluginInterface]:
        """Get mock plugin."""
        return self._plugins.get(name)
    
    def get_plugins(self, plugin_type: Optional[PluginType] = None,
                   state: Optional[PluginState] = None) -> List[PluginInterface]:
        """Get mock plugins."""
        plugins = []
        for name, plugin in self._plugins.items():
            metadata = self._metadata[name]
            plugin_state = self._states[name]
            
            if plugin_type and metadata.plugin_type != plugin_type:
                continue
            if state and plugin_state != state:
                continue
            
            plugins.append(plugin)
        return plugins
    
    def get_plugin_state(self, name: str) -> Optional[PluginState]:
        """Get mock plugin state."""
        return self._states.get(name)
    
    def set_plugin_state(self, name: str, state: PluginState) -> None:
        """Set mock plugin state."""
        if name in self._plugins:
            self._states[name] = state
            self._plugins[name].state = state
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List mock plugins."""
        plugins_info = []
        for name, plugin in self._plugins.items():
            metadata = self._metadata[name]
            config = self._configurations[name]
            state = self._states[name]
            
            plugins_info.append({
                "name": name,
                "version": metadata.version,
                "description": metadata.description,
                "author": metadata.author,
                "type": metadata.plugin_type.value,
                "priority": metadata.priority.value,
                "state": state.value,
                "enabled": config.enabled
            })
        return plugins_info


class MockVersionChecker:
    """Mock version checker for testing."""
    
    def __init__(self, python_compatible: bool = True,
                 shield_compatible: bool = True,
                 plugin_compatible: bool = True):
        self.python_compatible = python_compatible
        self.shield_compatible = shield_compatible
        self.plugin_compatible = plugin_compatible
        self.python_check_count = 0
        self.shield_check_count = 0
        self.plugin_check_count = 0
    
    def check_python_version(self, required: str) -> bool:
        """Check mock Python version."""
        self.python_check_count += 1
        return self.python_compatible
    
    def check_shield_version(self, required: str, current: str = "0.1.0") -> bool:
        """Check mock Shield version."""
        self.shield_check_count += 1
        return self.shield_compatible
    
    def check_plugin_version(self, required: str, current: str) -> bool:
        """Check mock plugin version."""
        self.plugin_check_count += 1
        return self.plugin_compatible


def create_temporary_plugin_file(plugin_content: str, 
                                plugin_metadata: Optional[Dict[str, Any]] = None,
                                file_type: str = "py") -> Path:
    """Create temporary plugin file for testing.
    
    Args:
        plugin_content: Python code content
        plugin_metadata: Optional metadata dictionary
        file_type: File type (py, yaml, json, toml)
        
    Returns:
        Path to temporary file
    """
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', suffix=f'.{file_type}', delete=False
    )
    
    if file_type == "py":
        content = plugin_content
        if plugin_metadata:
            content = f"PLUGIN_METADATA = {plugin_metadata!r}\n\n{content}"
        temp_file.write(content)
    elif file_type == "yaml":
        import yaml
        temp_file.write(yaml.dump(plugin_metadata or {}))
    elif file_type == "json":
        temp_file.write(json.dumps(plugin_metadata or {}, indent=2))
    elif file_type == "toml":
        try:
            import toml
            temp_file.write(toml.dumps({"tool": {"fastapi-shield-plugin": plugin_metadata or {}}}))
        except ImportError:
            # Fallback to manual TOML format
            content = "[tool.fastapi-shield-plugin]\n"
            for key, value in (plugin_metadata or {}).items():
                if isinstance(value, str):
                    content += f'{key} = "{value}"\n'
                elif isinstance(value, list):
                    content += f'{key} = {value!r}\n'
                else:
                    content += f'{key} = {value}\n'
            temp_file.write(content)
    
    temp_file.close()
    return Path(temp_file.name)


def create_temporary_plugin_package(plugin_code: str,
                                   metadata: Dict[str, Any],
                                   metadata_file: str = "plugin.yaml") -> Path:
    """Create temporary plugin package directory for testing.
    
    Args:
        plugin_code: Python code for __init__.py
        metadata: Plugin metadata
        metadata_file: Name of metadata file
        
    Returns:
        Path to temporary package directory
    """
    temp_dir = Path(tempfile.mkdtemp())
    package_dir = temp_dir / "test_plugin"
    package_dir.mkdir()
    
    # Create __init__.py
    init_file = package_dir / "__init__.py"
    with open(init_file, 'w') as f:
        f.write(plugin_code)
    
    # Create metadata file
    metadata_path = package_dir / metadata_file
    if metadata_file.endswith('.yaml'):
        import yaml
        with open(metadata_path, 'w') as f:
            yaml.dump(metadata, f)
    elif metadata_file.endswith('.json'):
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    elif metadata_file.endswith('.toml'):
        try:
            import toml
            with open(metadata_path, 'w') as f:
                toml.dump({"tool": {"fastapi-shield-plugin": metadata}}, f)
        except ImportError:
            # Manual TOML format
            content = "[tool.fastapi-shield-plugin]\n"
            for key, value in metadata.items():
                if isinstance(value, str):
                    content += f'{key} = "{value}"\n'
                elif isinstance(value, list):
                    content += f'{key} = {value!r}\n'
                else:
                    content += f'{key} = {value}\n'
            with open(metadata_path, 'w') as f:
                f.write(content)
    
    return package_dir


def cleanup_temporary_files(*paths: Path) -> None:
    """Clean up temporary files and directories.
    
    Args:
        paths: Paths to clean up
    """
    import shutil
    
    for path in paths:
        try:
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
        except (FileNotFoundError, OSError):
            pass  # Ignore cleanup errors