"""Plugin system for FastAPI Shield.

This module provides a comprehensive plugin architecture that allows third-party
developers to extend shield functionality and create reusable shield components.
It includes plugin discovery, lifecycle management, version compatibility,
and configuration management.
"""

import ast
import asyncio
import importlib
import importlib.util
import inspect
import json
import logging
import sys
import threading
import warnings
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Any, Dict, List, Optional, Set, Type, Union, Callable, 
    TypeVar, Generic, get_type_hints, get_origin, get_args
)
import weakref
import yaml

try:
    import packaging.version
    import packaging.specifiers
    PACKAGING_AVAILABLE = True
except ImportError:
    PACKAGING_AVAILABLE = False
    
try:
    import toml
    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False

from fastapi import Request, Response, HTTPException
from fastapi_shield.shield import Shield

logger = logging.getLogger(__name__)

T = TypeVar('T')


class PluginState(str, Enum):
    """Plugin lifecycle states."""
    UNREGISTERED = "unregistered"
    REGISTERED = "registered"
    INITIALIZING = "initializing"
    INITIALIZED = "initialized"
    ACTIVATING = "activating"
    ACTIVE = "active"
    DEACTIVATING = "deactivating"
    INACTIVE = "inactive"
    ERROR = "error"
    REMOVED = "removed"


class PluginType(str, Enum):
    """Types of plugins supported by the system."""
    SHIELD = "shield"
    MIDDLEWARE = "middleware"
    PROCESSOR = "processor"
    VALIDATOR = "validator"
    TRANSFORMER = "transformer"
    EXTENSION = "extension"


class PluginPriority(int, Enum):
    """Plugin execution priorities."""
    CRITICAL = 100
    HIGH = 75
    NORMAL = 50
    LOW = 25
    BACKGROUND = 0


@dataclass
class PluginMetadata:
    """Metadata information for plugins."""
    name: str
    version: str
    description: str
    author: str
    author_email: Optional[str] = None
    homepage: Optional[str] = None
    license: Optional[str] = None
    keywords: List[str] = field(default_factory=list)
    requires_python: Optional[str] = None
    requires_shield: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    plugin_type: PluginType = PluginType.SHIELD
    priority: PluginPriority = PluginPriority.NORMAL
    config_schema: Dict[str, Any] = field(default_factory=dict)
    entry_points: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    
    def __post_init__(self):
        """Validate and normalize metadata after initialization."""
        if not self.name:
            raise ValueError("Plugin name is required")
        if not self.version:
            raise ValueError("Plugin version is required")
        if not self.author:
            raise ValueError("Plugin author is required")
            
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "author_email": self.author_email,
            "homepage": self.homepage,
            "license": self.license,
            "keywords": self.keywords,
            "requires_python": self.requires_python,
            "requires_shield": self.requires_shield,
            "dependencies": self.dependencies,
            "plugin_type": self.plugin_type.value,
            "priority": self.priority.value,
            "config_schema": self.config_schema,
            "entry_points": self.entry_points,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PluginMetadata':
        """Create metadata from dictionary."""
        plugin_type = PluginType(data.get("plugin_type", PluginType.SHIELD))
        priority = PluginPriority(data.get("priority", PluginPriority.NORMAL))
        
        return cls(
            name=data["name"],
            version=data["version"],
            description=data["description"],
            author=data["author"],
            author_email=data.get("author_email"),
            homepage=data.get("homepage"),
            license=data.get("license"),
            keywords=data.get("keywords", []),
            requires_python=data.get("requires_python"),
            requires_shield=data.get("requires_shield"),
            dependencies=data.get("dependencies", []),
            plugin_type=plugin_type,
            priority=priority,
            config_schema=data.get("config_schema", {}),
            entry_points=data.get("entry_points", {}),
            tags=data.get("tags", []),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at")
        )


@dataclass
class PluginConfiguration:
    """Configuration for a plugin instance."""
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    auto_activate: bool = True
    priority_override: Optional[PluginPriority] = None
    dependencies: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    feature_flags: Dict[str, bool] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "enabled": self.enabled,
            "config": self.config,
            "auto_activate": self.auto_activate,
            "priority_override": self.priority_override.value if self.priority_override else None,
            "dependencies": self.dependencies,
            "conflicts": self.conflicts,
            "environment_variables": self.environment_variables,
            "feature_flags": self.feature_flags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PluginConfiguration':
        """Create configuration from dictionary."""
        priority_override = None
        if data.get("priority_override") is not None:
            priority_override = PluginPriority(data["priority_override"])
            
        return cls(
            enabled=data.get("enabled", True),
            config=data.get("config", {}),
            auto_activate=data.get("auto_activate", True),
            priority_override=priority_override,
            dependencies=data.get("dependencies", []),
            conflicts=data.get("conflicts", []),
            environment_variables=data.get("environment_variables", {}),
            feature_flags=data.get("feature_flags", {})
        )


class PluginInterface(ABC):
    """Abstract base class for all plugins."""
    
    def __init__(self, config: Optional[PluginConfiguration] = None):
        """Initialize the plugin with configuration."""
        self.config = config or PluginConfiguration()
        self.state = PluginState.UNREGISTERED
        self._metadata: Optional[PluginMetadata] = None
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the plugin.
        
        This method is called once when the plugin is first loaded.
        Use this for one-time setup operations like establishing connections,
        loading configuration, initializing caches, etc.
        """
        pass
    
    @abstractmethod 
    async def activate(self) -> None:
        """Activate the plugin.
        
        This method is called when the plugin should become active and
        start processing requests. The plugin should be ready to handle
        requests after this method returns.
        """
        pass
    
    @abstractmethod
    async def deactivate(self) -> None:
        """Deactivate the plugin.
        
        This method is called when the plugin should stop processing
        requests but remain loaded. The plugin should gracefully stop
        all active operations.
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up plugin resources.
        
        This method is called when the plugin is being unloaded.
        Use this to close connections, release resources, save state, etc.
        """
        pass
    
    async def validate_configuration(self) -> List[str]:
        """Validate plugin configuration.
        
        Returns:
            List of validation error messages, empty if valid.
        """
        errors = []
        
        # Validate against schema if available
        if self.metadata.config_schema:
            try:
                self._validate_config_schema(errors)
            except Exception as e:
                errors.append(f"Schema validation failed: {e}")
        
        return errors
    
    def _validate_config_schema(self, errors: List[str]) -> None:
        """Validate configuration against JSON schema."""
        try:
            import jsonschema
            jsonschema.validate(
                instance=self.config.config,
                schema=self.metadata.config_schema
            )
        except ImportError:
            self._logger.warning("jsonschema not available for config validation")
        except Exception as e:
            errors.append(f"Configuration validation error: {e}")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get plugin health status.
        
        Returns:
            Dictionary containing health status information.
        """
        return {
            "name": self.metadata.name,
            "version": self.metadata.version,
            "state": self.state.value,
            "enabled": self.config.enabled,
            "healthy": self.state in [PluginState.ACTIVE, PluginState.INACTIVE]
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get plugin metrics.
        
        Returns:
            Dictionary containing plugin metrics.
        """
        return {
            "name": self.metadata.name,
            "state": self.state.value,
            "uptime": 0,  # Subclasses should override
            "requests_processed": 0,  # Subclasses should override
            "errors": 0  # Subclasses should override
        }


class ShieldPlugin(PluginInterface):
    """Base class for shield plugins."""
    
    def __init__(self, config: Optional[PluginConfiguration] = None):
        super().__init__(config)
        self._shield_instances: List[Shield] = []
    
    @abstractmethod
    def create_shields(self) -> List[Shield]:
        """Create shield instances provided by this plugin.
        
        Returns:
            List of shield instances.
        """
        pass
    
    async def initialize(self) -> None:
        """Initialize shield plugin."""
        self._shield_instances = self.create_shields()
        self._logger.info(f"Initialized plugin {self.metadata.name} with {len(self._shield_instances)} shields")
    
    async def activate(self) -> None:
        """Activate shield plugin."""
        # Shield plugins don't need special activation logic
        # The shields are registered with the system separately
        self._logger.info(f"Activated shield plugin {self.metadata.name}")
    
    async def deactivate(self) -> None:
        """Deactivate shield plugin."""
        self._logger.info(f"Deactivated shield plugin {self.metadata.name}")
    
    async def cleanup(self) -> None:
        """Cleanup shield plugin resources."""
        self._shield_instances.clear()
        self._logger.info(f"Cleaned up shield plugin {self.metadata.name}")
    
    def get_shields(self) -> List[Shield]:
        """Get shield instances from this plugin."""
        return self._shield_instances.copy()


class ProcessorPlugin(PluginInterface):
    """Base class for request/response processor plugins."""
    
    @abstractmethod
    async def process_request(self, request: Request) -> Request:
        """Process incoming request.
        
        Args:
            request: The incoming request
            
        Returns:
            Modified request or original request
        """
        pass
    
    @abstractmethod
    async def process_response(self, request: Request, response: Response) -> Response:
        """Process outgoing response.
        
        Args:
            request: The original request
            response: The outgoing response
            
        Returns:
            Modified response or original response
        """
        pass


class ValidatorPlugin(PluginInterface):
    """Base class for validator plugins."""
    
    @abstractmethod
    async def validate_request(self, request: Request) -> List[str]:
        """Validate request and return errors.
        
        Args:
            request: The request to validate
            
        Returns:
            List of validation error messages, empty if valid
        """
        pass


class TransformerPlugin(PluginInterface):
    """Base class for data transformer plugins."""
    
    @abstractmethod
    async def transform_data(self, data: Any, transformation_type: str) -> Any:
        """Transform data based on type.
        
        Args:
            data: The data to transform
            transformation_type: Type of transformation to apply
            
        Returns:
            Transformed data
        """
        pass


class ExtensionPlugin(PluginInterface):
    """Base class for general extension plugins."""
    
    @abstractmethod
    async def extend_functionality(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Extend system functionality.
        
        Args:
            context: Current execution context
            
        Returns:
            Extended context with additional functionality
        """
        pass


class PluginError(Exception):
    """Base exception for plugin-related errors."""
    pass


class PluginNotFoundError(PluginError):
    """Raised when a requested plugin is not found."""
    pass


class PluginVersionError(PluginError):
    """Raised when plugin version requirements are not met."""
    pass


class PluginDependencyError(PluginError):
    """Raised when plugin dependencies cannot be resolved."""
    pass


class PluginConflictError(PluginError):
    """Raised when plugin conflicts are detected."""
    pass


class PluginConfigurationError(PluginError):
    """Raised when plugin configuration is invalid."""
    pass


class VersionChecker:
    """Utility class for version compatibility checking."""
    
    def __init__(self):
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def check_python_version(self, required: str) -> bool:
        """Check if current Python version meets requirements.
        
        Args:
            required: Version requirement string (e.g., ">=3.8,<4.0")
            
        Returns:
            True if version is compatible, False otherwise
        """
        if not PACKAGING_AVAILABLE:
            self._logger.warning("packaging library not available, skipping version check")
            return True
            
        try:
            current_version = packaging.version.Version(
                f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            )
            spec = packaging.specifiers.SpecifierSet(required)
            return current_version in spec
        except Exception as e:
            self._logger.error(f"Error checking Python version: {e}")
            return False
    
    def check_shield_version(self, required: str, current: str = "0.1.0") -> bool:
        """Check if FastAPI Shield version meets requirements.
        
        Args:
            required: Version requirement string
            current: Current shield version
            
        Returns:
            True if version is compatible, False otherwise
        """
        if not PACKAGING_AVAILABLE:
            self._logger.warning("packaging library not available, skipping version check")
            return True
            
        try:
            current_version = packaging.version.Version(current)
            spec = packaging.specifiers.SpecifierSet(required)
            return current_version in spec
        except Exception as e:
            self._logger.error(f"Error checking Shield version: {e}")
            return False
    
    def check_plugin_version(self, required: str, current: str) -> bool:
        """Check if plugin version meets requirements.
        
        Args:
            required: Version requirement string
            current: Current plugin version
            
        Returns:
            True if version is compatible, False otherwise
        """
        if not PACKAGING_AVAILABLE:
            self._logger.warning("packaging library not available, skipping version check")
            return True
            
        try:
            current_version = packaging.version.Version(current)
            spec = packaging.specifiers.SpecifierSet(required)
            return current_version in spec
        except Exception as e:
            self._logger.error(f"Error checking plugin version: {e}")
            return False


class PluginDiscovery:
    """Plugin discovery mechanism for finding and loading plugins."""
    
    def __init__(self, search_paths: List[Path] = None):
        """Initialize plugin discovery.
        
        Args:
            search_paths: List of paths to search for plugins
        """
        self.search_paths = search_paths or [
            Path.cwd() / "plugins",
            Path.home() / ".fastapi-shield" / "plugins",
            Path("/usr/local/lib/fastapi-shield/plugins"),
            Path("/etc/fastapi-shield/plugins")
        ]
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover all available plugins.
        
        Returns:
            List of plugin information dictionaries
        """
        plugins = []
        
        for search_path in self.search_paths:
            if not search_path.exists():
                continue
                
            self._logger.debug(f"Searching for plugins in {search_path}")
            
            # Look for Python packages
            plugins.extend(self._discover_python_packages(search_path))
            
            # Look for standalone plugin files
            plugins.extend(self._discover_standalone_plugins(search_path))
        
        # Remove duplicates based on plugin name
        unique_plugins = {}
        for plugin in plugins:
            name = plugin.get("metadata", {}).get("name")
            if name and name not in unique_plugins:
                unique_plugins[name] = plugin
        
        return list(unique_plugins.values())
    
    def _discover_python_packages(self, search_path: Path) -> List[Dict[str, Any]]:
        """Discover Python package plugins.
        
        Args:
            search_path: Path to search in
            
        Returns:
            List of discovered plugin information
        """
        plugins = []
        
        for package_dir in search_path.iterdir():
            if not package_dir.is_dir() or package_dir.name.startswith('.'):
                continue
            
            # Look for __init__.py to identify packages
            init_file = package_dir / "__init__.py"
            if not init_file.exists():
                continue
            
            # Look for plugin metadata
            metadata_files = [
                package_dir / "plugin.yaml",
                package_dir / "plugin.json", 
                package_dir / "plugin.toml",
                package_dir / "pyproject.toml"
            ]
            
            for metadata_file in metadata_files:
                if metadata_file.exists():
                    try:
                        plugin_info = self._load_plugin_metadata(metadata_file, package_dir)
                        if plugin_info:
                            plugins.append(plugin_info)
                            break
                    except Exception as e:
                        self._logger.error(f"Error loading plugin metadata from {metadata_file}: {e}")
        
        return plugins
    
    def _discover_standalone_plugins(self, search_path: Path) -> List[Dict[str, Any]]:
        """Discover standalone plugin files.
        
        Args:
            search_path: Path to search in
            
        Returns:
            List of discovered plugin information
        """
        plugins = []
        
        # Look for .py files with plugin metadata
        for plugin_file in search_path.glob("*.py"):
            try:
                plugin_info = self._analyze_python_file(plugin_file)
                if plugin_info:
                    plugins.append(plugin_info)
            except Exception as e:
                self._logger.error(f"Error analyzing plugin file {plugin_file}: {e}")
        
        return plugins
    
    def _load_plugin_metadata(self, metadata_file: Path, plugin_path: Path) -> Optional[Dict[str, Any]]:
        """Load plugin metadata from file.
        
        Args:
            metadata_file: Path to metadata file
            plugin_path: Path to plugin directory
            
        Returns:
            Plugin information dictionary or None
        """
        try:
            if metadata_file.name.endswith('.yaml'):
                with open(metadata_file) as f:
                    data = yaml.safe_load(f)
            elif metadata_file.name.endswith('.json'):
                with open(metadata_file) as f:
                    data = json.load(f)
            elif metadata_file.name.endswith('.toml'):
                if not TOML_AVAILABLE:
                    self._logger.warning("toml library not available, skipping TOML file")
                    return None
                with open(metadata_file) as f:
                    data = toml.load(f)
                    # Extract plugin info from pyproject.toml structure
                    if 'tool' in data and 'fastapi-shield-plugin' in data['tool']:
                        data = data['tool']['fastapi-shield-plugin']
            else:
                return None
            
            # Validate required fields
            if not all(key in data for key in ['name', 'version', 'description', 'author']):
                self._logger.warning(f"Missing required fields in {metadata_file}")
                return None
            
            return {
                "metadata": data,
                "path": str(plugin_path),
                "metadata_file": str(metadata_file),
                "type": "package" if plugin_path.is_dir() else "standalone"
            }
            
        except Exception as e:
            self._logger.error(f"Error loading metadata from {metadata_file}: {e}")
            return None
    
    def _analyze_python_file(self, plugin_file: Path) -> Optional[Dict[str, Any]]:
        """Analyze Python file for plugin information.
        
        Args:
            plugin_file: Path to Python file
            
        Returns:
            Plugin information dictionary or None
        """
        try:
            with open(plugin_file) as f:
                tree = ast.parse(f.read())
            
            # Look for plugin metadata in module docstring or variables
            metadata = self._extract_metadata_from_ast(tree)
            if metadata:
                return {
                    "metadata": metadata,
                    "path": str(plugin_file),
                    "type": "standalone"
                }
            
        except Exception as e:
            self._logger.debug(f"Could not analyze {plugin_file}: {e}")
        
        return None
    
    def _extract_metadata_from_ast(self, tree: ast.AST) -> Optional[Dict[str, Any]]:
        """Extract plugin metadata from AST.
        
        Args:
            tree: AST tree to analyze
            
        Returns:
            Metadata dictionary or None
        """
        metadata = {}
        
        # Look for module-level variables
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id == 'PLUGIN_METADATA' and isinstance(node.value, ast.Dict):
                            # Extract dictionary values
                            for key, value in zip(node.value.keys, node.value.values):
                                if isinstance(key, ast.Str) and isinstance(value, ast.Str):
                                    metadata[key.s] = value.s
        
        # Validate required fields
        if all(key in metadata for key in ['name', 'version', 'description', 'author']):
            return metadata
        
        return None


class PluginRegistry:
    """Registry for managing loaded plugins."""
    
    def __init__(self):
        """Initialize the plugin registry."""
        self._plugins: Dict[str, PluginInterface] = {}
        self._metadata: Dict[str, PluginMetadata] = {}
        self._configurations: Dict[str, PluginConfiguration] = {}
        self._states: Dict[str, PluginState] = {}
        self._dependencies: Dict[str, List[str]] = {}
        self._conflicts: Dict[str, List[str]] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def register_plugin(self, plugin: PluginInterface, 
                       configuration: Optional[PluginConfiguration] = None) -> None:
        """Register a plugin with the registry.
        
        Args:
            plugin: Plugin instance to register
            configuration: Optional configuration override
            
        Raises:
            PluginError: If plugin registration fails
        """
        with self._lock:
            metadata = plugin.metadata
            name = metadata.name
            
            if name in self._plugins:
                raise PluginError(f"Plugin {name} is already registered")
            
            # Update plugin configuration if provided
            if configuration:
                plugin.config = configuration
            
            # Validate plugin
            validation_errors = []
            try:
                validation_result = plugin.validate_configuration()
                if asyncio.iscoroutine(validation_result):
                    validation_errors.extend(await validation_result)
                else:
                    validation_errors.extend(validation_result)
            except Exception as e:
                validation_errors.append(f"Validation failed: {e}")
            
            if validation_errors:
                raise PluginConfigurationError(f"Plugin {name} validation failed: {validation_errors}")
            
            # Check dependencies and conflicts
            self._check_dependencies(name, plugin.config.dependencies)
            self._check_conflicts(name, plugin.config.conflicts)
            
            # Register the plugin
            self._plugins[name] = plugin
            self._metadata[name] = metadata
            self._configurations[name] = plugin.config
            self._states[name] = PluginState.REGISTERED
            self._dependencies[name] = plugin.config.dependencies
            self._conflicts[name] = plugin.config.conflicts
            
            plugin.state = PluginState.REGISTERED
            
            self._logger.info(f"Registered plugin {name} v{metadata.version}")
    
    def unregister_plugin(self, name: str) -> None:
        """Unregister a plugin from the registry.
        
        Args:
            name: Name of plugin to unregister
            
        Raises:
            PluginNotFoundError: If plugin is not found
        """
        with self._lock:
            if name not in self._plugins:
                raise PluginNotFoundError(f"Plugin {name} not found")
            
            plugin = self._plugins[name]
            
            # Check if other plugins depend on this one
            dependents = self._find_dependents(name)
            if dependents:
                raise PluginDependencyError(
                    f"Cannot unregister plugin {name}, required by: {dependents}"
                )
            
            # Clean up plugin
            try:
                if plugin.state in [PluginState.ACTIVE, PluginState.INACTIVE]:
                    # Plugin manager should deactivate first
                    self._logger.warning(f"Unregistering active plugin {name}")
            except Exception as e:
                self._logger.error(f"Error during plugin {name} cleanup: {e}")
            
            # Remove from registry
            del self._plugins[name]
            del self._metadata[name]
            del self._configurations[name]
            del self._states[name]
            del self._dependencies[name]
            del self._conflicts[name]
            
            plugin.state = PluginState.REMOVED
            
            self._logger.info(f"Unregistered plugin {name}")
    
    def get_plugin(self, name: str) -> Optional[PluginInterface]:
        """Get a plugin by name.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin instance or None if not found
        """
        with self._lock:
            return self._plugins.get(name)
    
    def get_plugins(self, plugin_type: Optional[PluginType] = None,
                   state: Optional[PluginState] = None) -> List[PluginInterface]:
        """Get plugins by type and/or state.
        
        Args:
            plugin_type: Filter by plugin type
            state: Filter by plugin state
            
        Returns:
            List of matching plugins
        """
        with self._lock:
            plugins = []
            
            for name, plugin in self._plugins.items():
                metadata = self._metadata[name]
                plugin_state = self._states[name]
                
                # Filter by type
                if plugin_type and metadata.plugin_type != plugin_type:
                    continue
                
                # Filter by state  
                if state and plugin_state != state:
                    continue
                
                plugins.append(plugin)
            
            # Sort by priority
            return sorted(plugins, key=lambda p: self._metadata[p.metadata.name].priority, reverse=True)
    
    def get_plugin_metadata(self, name: str) -> Optional[PluginMetadata]:
        """Get plugin metadata.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin metadata or None if not found
        """
        with self._lock:
            return self._metadata.get(name)
    
    def get_plugin_state(self, name: str) -> Optional[PluginState]:
        """Get plugin state.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin state or None if not found
        """
        with self._lock:
            return self._states.get(name)
    
    def set_plugin_state(self, name: str, state: PluginState) -> None:
        """Set plugin state.
        
        Args:
            name: Plugin name
            state: New state
            
        Raises:
            PluginNotFoundError: If plugin is not found
        """
        with self._lock:
            if name not in self._plugins:
                raise PluginNotFoundError(f"Plugin {name} not found")
            
            self._states[name] = state
            self._plugins[name].state = state
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all registered plugins with their information.
        
        Returns:
            List of plugin information dictionaries
        """
        with self._lock:
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
                    "enabled": config.enabled,
                    "dependencies": self._dependencies[name],
                    "conflicts": self._conflicts[name]
                })
            
            return plugins_info
    
    def _check_dependencies(self, plugin_name: str, dependencies: List[str]) -> None:
        """Check if plugin dependencies are satisfied.
        
        Args:
            plugin_name: Name of the plugin
            dependencies: List of dependency names
            
        Raises:
            PluginDependencyError: If dependencies are not satisfied
        """
        for dependency in dependencies:
            if dependency not in self._plugins:
                raise PluginDependencyError(
                    f"Plugin {plugin_name} requires {dependency} which is not registered"
                )
    
    def _check_conflicts(self, plugin_name: str, conflicts: List[str]) -> None:
        """Check if plugin has conflicts with registered plugins.
        
        Args:
            plugin_name: Name of the plugin
            conflicts: List of conflicting plugin names
            
        Raises:
            PluginConflictError: If conflicts are detected
        """
        for conflict in conflicts:
            if conflict in self._plugins:
                raise PluginConflictError(
                    f"Plugin {plugin_name} conflicts with {conflict}"
                )
    
    def _find_dependents(self, plugin_name: str) -> List[str]:
        """Find plugins that depend on the given plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            List of dependent plugin names
        """
        dependents = []
        for name, dependencies in self._dependencies.items():
            if plugin_name in dependencies:
                dependents.append(name)
        return dependents


class PluginManager:
    """Main plugin manager for the FastAPI Shield plugin system."""
    
    def __init__(self, discovery: Optional[PluginDiscovery] = None,
                 registry: Optional[PluginRegistry] = None,
                 version_checker: Optional[VersionChecker] = None):
        """Initialize the plugin manager.
        
        Args:
            discovery: Plugin discovery instance
            registry: Plugin registry instance
            version_checker: Version checker instance
        """
        self.discovery = discovery or PluginDiscovery()
        self.registry = registry or PluginRegistry()
        self.version_checker = version_checker or VersionChecker()
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._initialization_lock = threading.RLock()
        self._active_plugins: Set[str] = set()
    
    async def discover_and_load_plugins(self, auto_activate: bool = True) -> int:
        """Discover and load all available plugins.
        
        Args:
            auto_activate: Whether to automatically activate loaded plugins
            
        Returns:
            Number of plugins loaded
        """
        discovered = self.discovery.discover_plugins()
        loaded_count = 0
        
        self._logger.info(f"Discovered {len(discovered)} plugins")
        
        for plugin_info in discovered:
            try:
                plugin = await self.load_plugin(plugin_info)
                if plugin and auto_activate:
                    await self.activate_plugin(plugin.metadata.name)
                loaded_count += 1
            except Exception as e:
                self._logger.error(f"Failed to load plugin {plugin_info.get('metadata', {}).get('name', 'unknown')}: {e}")
        
        self._logger.info(f"Loaded {loaded_count} plugins successfully")
        return loaded_count
    
    async def load_plugin(self, plugin_info: Dict[str, Any]) -> Optional[PluginInterface]:
        """Load a single plugin.
        
        Args:
            plugin_info: Plugin information dictionary
            
        Returns:
            Loaded plugin instance or None if loading failed
        """
        metadata_dict = plugin_info.get("metadata", {})
        plugin_path = plugin_info.get("path")
        plugin_type = plugin_info.get("type", "standalone")
        
        if not all([metadata_dict, plugin_path]):
            raise PluginError("Invalid plugin information")
        
        # Create metadata
        metadata = PluginMetadata.from_dict(metadata_dict)
        
        # Check version compatibility
        if metadata.requires_python and not self.version_checker.check_python_version(metadata.requires_python):
            raise PluginVersionError(f"Plugin {metadata.name} requires Python {metadata.requires_python}")
        
        if metadata.requires_shield and not self.version_checker.check_shield_version(metadata.requires_shield):
            raise PluginVersionError(f"Plugin {metadata.name} requires Shield {metadata.requires_shield}")
        
        # Load the plugin module
        plugin_module = self._load_plugin_module(plugin_path, plugin_type)
        
        # Find plugin class
        plugin_class = self._find_plugin_class(plugin_module, metadata)
        if not plugin_class:
            raise PluginError(f"Plugin class not found in {plugin_path}")
        
        # Create plugin instance
        configuration = PluginConfiguration()  # Default configuration
        plugin = plugin_class(configuration)
        
        # Initialize plugin
        with self._initialization_lock:
            try:
                plugin.state = PluginState.INITIALIZING
                await plugin.initialize()
                plugin.state = PluginState.INITIALIZED
                
                # Register plugin
                self.registry.register_plugin(plugin, configuration)
                
                self._logger.info(f"Loaded plugin {metadata.name} v{metadata.version}")
                return plugin
                
            except Exception as e:
                plugin.state = PluginState.ERROR
                self._logger.error(f"Failed to initialize plugin {metadata.name}: {e}")
                raise
    
    def _load_plugin_module(self, plugin_path: str, plugin_type: str):
        """Load plugin module from path.
        
        Args:
            plugin_path: Path to plugin
            plugin_type: Type of plugin (package or standalone)
            
        Returns:
            Loaded module
        """
        path = Path(plugin_path)
        
        if plugin_type == "package":
            # Load as package
            spec = importlib.util.spec_from_file_location(
                path.name, 
                path / "__init__.py"
            )
        else:
            # Load as standalone module
            spec = importlib.util.spec_from_file_location(
                path.stem,
                path
            )
        
        if not spec or not spec.loader:
            raise PluginError(f"Cannot create module spec for {plugin_path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        
        return module
    
    def _find_plugin_class(self, module, metadata: PluginMetadata) -> Optional[Type[PluginInterface]]:
        """Find plugin class in module.
        
        Args:
            module: Plugin module
            metadata: Plugin metadata
            
        Returns:
            Plugin class or None if not found
        """
        # Look for entry point first
        if metadata.entry_points and "main" in metadata.entry_points:
            entry_point = metadata.entry_points["main"]
            if hasattr(module, entry_point):
                cls = getattr(module, entry_point)
                if inspect.isclass(cls) and issubclass(cls, PluginInterface):
                    return cls
        
        # Search for plugin classes
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, PluginInterface) and 
                obj != PluginInterface and
                not obj.__name__.startswith('_')):
                return obj
        
        return None
    
    async def activate_plugin(self, name: str) -> None:
        """Activate a plugin.
        
        Args:
            name: Plugin name
            
        Raises:
            PluginNotFoundError: If plugin is not found
            PluginError: If activation fails
        """
        plugin = self.registry.get_plugin(name)
        if not plugin:
            raise PluginNotFoundError(f"Plugin {name} not found")
        
        if name in self._active_plugins:
            self._logger.warning(f"Plugin {name} is already active")
            return
        
        # Check dependencies
        config = self.registry._configurations[name]
        for dependency in config.dependencies:
            if dependency not in self._active_plugins:
                self._logger.info(f"Activating dependency {dependency} for {name}")
                await self.activate_plugin(dependency)
        
        try:
            self.registry.set_plugin_state(name, PluginState.ACTIVATING)
            await plugin.activate()
            self.registry.set_plugin_state(name, PluginState.ACTIVE)
            self._active_plugins.add(name)
            
            self._logger.info(f"Activated plugin {name}")
            
        except Exception as e:
            self.registry.set_plugin_state(name, PluginState.ERROR)
            self._logger.error(f"Failed to activate plugin {name}: {e}")
            raise PluginError(f"Plugin activation failed: {e}")
    
    async def deactivate_plugin(self, name: str) -> None:
        """Deactivate a plugin.
        
        Args:
            name: Plugin name
            
        Raises:
            PluginNotFoundError: If plugin is not found
        """
        plugin = self.registry.get_plugin(name)
        if not plugin:
            raise PluginNotFoundError(f"Plugin {name} not found")
        
        if name not in self._active_plugins:
            self._logger.warning(f"Plugin {name} is not active")
            return
        
        # Check if other plugins depend on this one
        dependents = []
        for active_name in self._active_plugins:
            config = self.registry._configurations[active_name]
            if name in config.dependencies:
                dependents.append(active_name)
        
        if dependents:
            raise PluginDependencyError(
                f"Cannot deactivate plugin {name}, required by active plugins: {dependents}"
            )
        
        try:
            self.registry.set_plugin_state(name, PluginState.DEACTIVATING)
            await plugin.deactivate()
            self.registry.set_plugin_state(name, PluginState.INACTIVE)
            self._active_plugins.remove(name)
            
            self._logger.info(f"Deactivated plugin {name}")
            
        except Exception as e:
            self.registry.set_plugin_state(name, PluginState.ERROR)
            self._logger.error(f"Failed to deactivate plugin {name}: {e}")
            raise PluginError(f"Plugin deactivation failed: {e}")
    
    async def reload_plugin(self, name: str) -> None:
        """Reload a plugin.
        
        Args:
            name: Plugin name
            
        Raises:
            PluginNotFoundError: If plugin is not found
        """
        plugin = self.registry.get_plugin(name)
        if not plugin:
            raise PluginNotFoundError(f"Plugin {name} not found")
        
        was_active = name in self._active_plugins
        
        # Deactivate if active
        if was_active:
            await self.deactivate_plugin(name)
        
        # Cleanup and unregister
        try:
            await plugin.cleanup()
        except Exception as e:
            self._logger.error(f"Error during plugin {name} cleanup: {e}")
        
        self.registry.unregister_plugin(name)
        
        # Rediscover and reload
        discovered = self.discovery.discover_plugins()
        for plugin_info in discovered:
            metadata_dict = plugin_info.get("metadata", {})
            if metadata_dict.get("name") == name:
                new_plugin = await self.load_plugin(plugin_info)
                if new_plugin and was_active:
                    await self.activate_plugin(name)
                break
        else:
            raise PluginNotFoundError(f"Plugin {name} not found during reload")
        
        self._logger.info(f"Reloaded plugin {name}")
    
    async def unload_plugin(self, name: str) -> None:
        """Unload a plugin completely.
        
        Args:
            name: Plugin name
            
        Raises:
            PluginNotFoundError: If plugin is not found
        """
        plugin = self.registry.get_plugin(name)
        if not plugin:
            raise PluginNotFoundError(f"Plugin {name} not found")
        
        # Deactivate if active
        if name in self._active_plugins:
            await self.deactivate_plugin(name)
        
        # Cleanup and unregister
        try:
            await plugin.cleanup()
        except Exception as e:
            self._logger.error(f"Error during plugin {name} cleanup: {e}")
        
        self.registry.unregister_plugin(name)
        
        self._logger.info(f"Unloaded plugin {name}")
    
    def get_active_plugins(self, plugin_type: Optional[PluginType] = None) -> List[PluginInterface]:
        """Get list of active plugins.
        
        Args:
            plugin_type: Optional type filter
            
        Returns:
            List of active plugin instances
        """
        return self.registry.get_plugins(
            plugin_type=plugin_type,
            state=PluginState.ACTIVE
        )
    
    def get_plugin_health(self) -> Dict[str, Dict[str, Any]]:
        """Get health status of all plugins.
        
        Returns:
            Dictionary mapping plugin names to health status
        """
        health_status = {}
        
        for plugin in self.registry.get_plugins():
            name = plugin.metadata.name
            try:
                health_status[name] = plugin.get_health_status()
            except Exception as e:
                health_status[name] = {
                    "name": name,
                    "healthy": False,
                    "error": str(e)
                }
        
        return health_status
    
    def get_plugin_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics from all plugins.
        
        Returns:
            Dictionary mapping plugin names to metrics
        """
        metrics = {}
        
        for plugin in self.registry.get_plugins():
            name = plugin.metadata.name
            try:
                metrics[name] = plugin.get_metrics()
            except Exception as e:
                metrics[name] = {
                    "name": name,
                    "error": str(e)
                }
        
        return metrics
    
    async def shutdown(self) -> None:
        """Shutdown the plugin manager and cleanup all plugins."""
        self._logger.info("Shutting down plugin manager")
        
        # Deactivate all active plugins
        active_plugins = list(self._active_plugins)
        for name in active_plugins:
            try:
                await self.deactivate_plugin(name)
            except Exception as e:
                self._logger.error(f"Error deactivating plugin {name}: {e}")
        
        # Cleanup all plugins
        for plugin in self.registry.get_plugins():
            try:
                await plugin.cleanup()
            except Exception as e:
                self._logger.error(f"Error cleaning up plugin {plugin.metadata.name}: {e}")
        
        self._logger.info("Plugin manager shutdown complete")


# Global plugin manager instance
_plugin_manager: Optional[PluginManager] = None
_plugin_manager_lock = threading.Lock()


def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance.
    
    Returns:
        Global plugin manager instance
    """
    global _plugin_manager
    
    if _plugin_manager is None:
        with _plugin_manager_lock:
            if _plugin_manager is None:
                _plugin_manager = PluginManager()
    
    return _plugin_manager


def set_plugin_manager(manager: PluginManager) -> None:
    """Set the global plugin manager instance.
    
    Args:
        manager: Plugin manager instance to set as global
    """
    global _plugin_manager
    
    with _plugin_manager_lock:
        _plugin_manager = manager


# Convenience functions
async def discover_plugins() -> int:
    """Discover and load all plugins.
    
    Returns:
        Number of plugins loaded
    """
    manager = get_plugin_manager()
    return await manager.discover_and_load_plugins()


def get_active_shield_plugins() -> List[ShieldPlugin]:
    """Get all active shield plugins.
    
    Returns:
        List of active shield plugin instances
    """
    manager = get_plugin_manager()
    return [p for p in manager.get_active_plugins(PluginType.SHIELD) if isinstance(p, ShieldPlugin)]


def get_shields_from_plugins() -> List[Shield]:
    """Get all shield instances from active plugins.
    
    Returns:
        List of shield instances from all active plugins
    """
    shields = []
    for plugin in get_active_shield_plugins():
        shields.extend(plugin.get_shields())
    return shields