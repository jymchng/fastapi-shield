"""Shield Documentation Generator for FastAPI Shield.

This module provides comprehensive documentation generation capabilities including
shield introspection, configuration schema documentation, example code generation,
and integration with popular documentation tools.
"""

import ast
import inspect
import json
import logging
import re
import textwrap
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple, Type
import warnings
import yaml

try:
    import markdown
    import markdown.extensions.codehilite
    import markdown.extensions.fenced_code
    import markdown.extensions.tables
    import markdown.extensions.toc
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False

try:
    import jinja2
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

from fastapi_shield.shield import Shield
from fastapi_shield.config import ConfigValidator, ConfigValidationRule

try:
    import pygments
    import pygments.lexers
    import pygments.formatters
    PYGMENTS_AVAILABLE = True
except ImportError:
    PYGMENTS_AVAILABLE = False

try:
    from jsonschema import validate, ValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False


class DocFormat(str, Enum):
    """Documentation format enumeration."""
    MARKDOWN = "markdown"
    HTML = "html"
    RST = "rst"
    JSON = "json"
    YAML = "yaml"
    OPENAPI = "openapi"


class DocSection(str, Enum):
    """Documentation section types."""
    OVERVIEW = "overview"
    CONFIGURATION = "configuration"
    EXAMPLES = "examples"
    API_REFERENCE = "api_reference"
    INSTALLATION = "installation"
    QUICKSTART = "quickstart"
    ADVANCED = "advanced"
    TROUBLESHOOTING = "troubleshooting"


class ExampleType(str, Enum):
    """Example code type enumeration."""
    BASIC_USAGE = "basic_usage"
    CONFIGURATION = "configuration"
    INTEGRATION = "integration"
    TESTING = "testing"
    ADVANCED = "advanced"
    ERROR_HANDLING = "error_handling"


@dataclass
class ParameterInfo:
    """Parameter information for documentation."""
    name: str
    type: str
    description: str
    default: Any = None
    required: bool = True
    constraints: Dict[str, Any] = field(default_factory=dict)
    examples: List[Any] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "default": str(self.default) if self.default is not None else None,
            "required": self.required,
            "constraints": self.constraints,
            "examples": self.examples
        }


@dataclass
class ShieldDocumentation:
    """Complete shield documentation."""
    name: str
    description: str
    version: str = "1.0.0"
    author: str = ""
    category: str = "general"
    tags: List[str] = field(default_factory=list)
    parameters: List[ParameterInfo] = field(default_factory=list)
    configuration: Dict[str, Any] = field(default_factory=dict)
    examples: List[Dict[str, Any]] = field(default_factory=list)
    methods: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    see_also: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "category": self.category,
            "tags": self.tags,
            "parameters": [p.to_dict() for p in self.parameters],
            "configuration": self.configuration,
            "examples": self.examples,
            "methods": self.methods,
            "dependencies": self.dependencies,
            "notes": self.notes,
            "warnings": self.warnings,
            "see_also": self.see_also,
            "created_at": self.created_at.isoformat()
        }


@dataclass
class ExampleCode:
    """Example code documentation."""
    title: str
    description: str
    code: str
    language: str = "python"
    type: ExampleType = ExampleType.BASIC_USAGE
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "code": self.code,
            "language": self.language,
            "type": self.type.value,
            "tags": self.tags,
            "dependencies": self.dependencies,
            "notes": self.notes
        }


@dataclass
class DocumentationConfig:
    """Documentation generation configuration."""
    title: str = "FastAPI Shield Documentation"
    version: str = "1.0.0"
    description: str = "Comprehensive documentation for FastAPI Shield"
    author: str = ""
    output_dir: Path = Path("docs")
    template_dir: Optional[Path] = None
    include_private: bool = False
    include_tests: bool = True
    generate_examples: bool = True
    generate_openapi: bool = True
    formats: List[DocFormat] = field(default_factory=lambda: [DocFormat.MARKDOWN, DocFormat.HTML])
    sections: List[DocSection] = field(default_factory=lambda: list(DocSection))
    theme: str = "default"
    custom_css: Optional[str] = None
    logo_path: Optional[Path] = None
    
    # Quality and validation settings
    validate_links: bool = True
    check_spelling: bool = False
    min_description_length: int = 10
    require_examples: bool = True
    syntax_highlighting: bool = True
    generate_search_index: bool = True
    auto_cross_references: bool = True
    
    # Advanced features
    include_performance_metrics: bool = False
    include_security_notes: bool = True
    include_migration_guides: bool = False
    generate_diagrams: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "output_dir": str(self.output_dir),
            "template_dir": str(self.template_dir) if self.template_dir else None,
            "include_private": self.include_private,
            "include_tests": self.include_tests,
            "generate_examples": self.generate_examples,
            "generate_openapi": self.generate_openapi,
            "formats": [f.value for f in self.formats],
            "sections": [s.value for s in self.sections],
            "theme": self.theme,
            "custom_css": self.custom_css,
            "logo_path": str(self.logo_path) if self.logo_path else None
        }


class ShieldIntrospector:
    """Shield introspection and analysis."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def analyze_shield(self, shield_class: Type[Shield]) -> ShieldDocumentation:
        """Analyze a shield class and extract documentation."""
        try:
            # Basic information
            name = shield_class.__name__
            description = self._extract_description(shield_class)
            version = getattr(shield_class, "__version__", "1.0.0")
            author = getattr(shield_class, "__author__", "")
            category = getattr(shield_class, "_category", "general")
            tags = getattr(shield_class, "_tags", [])
            
            # Parameters from __init__ method
            parameters = self._extract_parameters(shield_class)
            
            # Configuration schema
            configuration = self._extract_configuration(shield_class)
            
            # Methods documentation
            methods = self._extract_methods(shield_class)
            
            # Dependencies
            dependencies = self._extract_dependencies(shield_class)
            
            # Additional metadata
            notes = getattr(shield_class, "_notes", [])
            warnings_list = getattr(shield_class, "_warnings", [])
            see_also = getattr(shield_class, "_see_also", [])
            
            return ShieldDocumentation(
                name=name,
                description=description,
                version=version,
                author=author,
                category=category,
                tags=tags,
                parameters=parameters,
                configuration=configuration,
                methods=methods,
                dependencies=dependencies,
                notes=notes,
                warnings=warnings_list,
                see_also=see_also
            )
        
        except Exception as e:
            self.logger.error(f"Failed to analyze shield {shield_class.__name__}: {e}")
            # Return minimal documentation
            return ShieldDocumentation(
                name=shield_class.__name__,
                description="Shield documentation could not be automatically generated."
            )
    
    def _extract_description(self, shield_class: Type[Shield]) -> str:
        """Extract description from docstring."""
        doc = inspect.getdoc(shield_class)
        if doc:
            # Take the first paragraph as description
            lines = doc.split('\n\n')
            return lines[0].strip()
        return f"Shield: {shield_class.__name__}"
    
    def _extract_parameters(self, shield_class: Type[Shield]) -> List[ParameterInfo]:
        """Extract parameters from __init__ method."""
        parameters = []
        
        try:
            init_signature = inspect.signature(shield_class.__init__)
            init_doc = inspect.getdoc(shield_class.__init__)
            
            # Parse docstring for parameter descriptions
            param_docs = self._parse_parameter_docs(init_doc) if init_doc else {}
            
            for param_name, param in init_signature.parameters.items():
                if param_name == 'self':
                    continue
                
                # Determine type
                param_type = self._get_type_string(param.annotation)
                
                # Determine if required
                required = param.default == param.empty
                
                # Get description from docstring
                description = param_docs.get(param_name, f"Parameter: {param_name}")
                
                # Extract constraints and examples
                constraints = {}
                examples = []
                
                # Add type constraints
                if param.annotation != param.empty:
                    constraints["type"] = param_type
                
                parameters.append(ParameterInfo(
                    name=param_name,
                    type=param_type,
                    description=description,
                    default=param.default if param.default != param.empty else None,
                    required=required,
                    constraints=constraints,
                    examples=examples
                ))
        
        except Exception as e:
            self.logger.warning(f"Failed to extract parameters for {shield_class.__name__}: {e}")
        
        return parameters
    
    def _extract_configuration(self, shield_class: Type[Shield]) -> Dict[str, Any]:
        """Extract configuration schema."""
        config_schema = {}
        
        try:
            # Look for configuration class or schema
            if hasattr(shield_class, '_config_schema'):
                config_schema = shield_class._config_schema
            elif hasattr(shield_class, 'Config'):
                config_schema = self._analyze_config_class(shield_class.Config)
            
            # Look for validator if available
            if hasattr(shield_class, '_validator'):
                validator = shield_class._validator
                if isinstance(validator, ConfigValidator):
                    config_schema["validation_rules"] = [
                        {
                            "path": rule.path,
                            "type": rule.rule_type,
                            "constraint": str(rule.constraint) if rule.constraint else None,
                            "message": rule.message
                        }
                        for rule in validator.rules
                    ]
        
        except Exception as e:
            self.logger.warning(f"Failed to extract configuration for {shield_class.__name__}: {e}")
        
        return config_schema
    
    def _extract_methods(self, shield_class: Type[Shield]) -> List[Dict[str, Any]]:
        """Extract method documentation."""
        methods = []
        
        try:
            for name, method in inspect.getmembers(shield_class, inspect.isfunction):
                if name.startswith('_') and not name.startswith('__'):
                    continue  # Skip private methods unless they're magic methods
                
                # Get method signature
                try:
                    signature = inspect.signature(method)
                    doc = inspect.getdoc(method)
                    
                    methods.append({
                        "name": name,
                        "signature": str(signature),
                        "description": doc or f"Method: {name}",
                        "async": inspect.iscoroutinefunction(method),
                        "parameters": [
                            {
                                "name": param_name,
                                "type": self._get_type_string(param.annotation),
                                "required": param.default == param.empty,
                                "default": str(param.default) if param.default != param.empty else None
                            }
                            for param_name, param in signature.parameters.items()
                            if param_name != 'self'
                        ]
                    })
                except Exception as e:
                    self.logger.debug(f"Failed to document method {name}: {e}")
        
        except Exception as e:
            self.logger.warning(f"Failed to extract methods for {shield_class.__name__}: {e}")
        
        return methods
    
    def _extract_dependencies(self, shield_class: Type[Shield]) -> List[str]:
        """Extract dependencies from imports and requirements."""
        dependencies = []
        
        try:
            # Get the module where the shield is defined
            module = inspect.getmodule(shield_class)
            if module:
                source_file = inspect.getfile(module)
                
                # Parse the source file for imports
                with open(source_file, 'r', encoding='utf-8') as f:
                    tree = ast.parse(f.read())
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            dependencies.append(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            dependencies.append(node.module)
            
            # Remove standard library and common imports
            filtered_deps = []
            for dep in dependencies:
                if not self._is_stdlib_module(dep):
                    filtered_deps.append(dep)
            
            # Remove duplicates and sort
            dependencies = sorted(list(set(filtered_deps)))
        
        except Exception as e:
            self.logger.debug(f"Failed to extract dependencies for {shield_class.__name__}: {e}")
        
        return dependencies
    
    def _parse_parameter_docs(self, docstring: str) -> Dict[str, str]:
        """Parse parameter documentation from docstring."""
        param_docs = {}
        
        if not docstring:
            return param_docs
        
        # Look for various docstring formats
        lines = docstring.split('\n')
        current_param = None
        
        for line in lines:
            line = line.strip()
            
            # Google-style docstring parameters
            if line.startswith('Args:') or line.startswith('Parameters:'):
                continue
            
            # Parameter line (starts with parameter name followed by colon)
            param_match = re.match(r'^(\w+)(?:\s*\([^)]+\))?\s*:\s*(.+)', line)
            if param_match:
                param_name, description = param_match.groups()
                param_docs[param_name] = description
                current_param = param_name
            elif current_param and line and not line.startswith(('Returns:', 'Raises:', 'Example:')):
                # Continuation of parameter description
                param_docs[current_param] += ' ' + line
        
        return param_docs
    
    def _get_type_string(self, annotation) -> str:
        """Get string representation of type annotation."""
        if annotation == inspect.Parameter.empty:
            return "Any"
        
        # Handle special typing constructs
        if hasattr(annotation, '_name') and annotation._name:
            # This handles Union, Optional, etc.
            if annotation._name == 'Union':
                args = getattr(annotation, '__args__', ())
                if len(args) == 2 and type(None) in args:
                    # This is Optional[T]
                    non_none_type = next(arg for arg in args if arg is not type(None))
                    return f"Optional[{self._get_type_string(non_none_type)}]"
                else:
                    args_str = ', '.join(self._get_type_string(arg) for arg in args)
                    return f"Union[{args_str}]"
            return annotation._name
        
        if hasattr(annotation, '__name__'):
            return annotation.__name__
        elif hasattr(annotation, '__origin__'):
            # Handle generic types like List[str], Dict[str, int]
            origin = annotation.__origin__
            args = getattr(annotation, '__args__', ())
            if args:
                args_str = ', '.join(self._get_type_string(arg) for arg in args)
                if hasattr(origin, '__name__'):
                    return f"{origin.__name__}[{args_str}]"
                else:
                    return f"{str(origin)}[{args_str}]"
            if hasattr(origin, '__name__'):
                return origin.__name__
            else:
                return str(origin)
        else:
            return str(annotation)
    
    def _analyze_config_class(self, config_class) -> Dict[str, Any]:
        """Analyze a configuration class."""
        config_info = {}
        
        try:
            # Get class attributes
            for name, value in inspect.getmembers(config_class):
                if not name.startswith('_'):
                    config_info[name] = {
                        "value": value,
                        "type": type(value).__name__,
                        "description": f"Configuration parameter: {name}"
                    }
        
        except Exception as e:
            self.logger.debug(f"Failed to analyze config class: {e}")
        
        return config_info
    
    def _is_stdlib_module(self, module_name: str) -> bool:
        """Check if module is part of standard library."""
        stdlib_modules = {
            'os', 'sys', 'json', 'logging', 're', 'datetime', 'pathlib',
            'typing', 'abc', 'asyncio', 'collections', 'dataclasses',
            'enum', 'inspect', 'ast', 'textwrap', 'warnings'
        }
        
        return module_name.split('.')[0] in stdlib_modules


class ExampleExtractor:
    """Extract examples from tests and code."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def extract_from_tests(self, test_files: List[Path]) -> List[ExampleCode]:
        """Extract examples from test files."""
        examples = []
        
        for test_file in test_files:
            try:
                file_examples = self._parse_test_file(test_file)
                examples.extend(file_examples)
            except Exception as e:
                self.logger.warning(f"Failed to parse test file {test_file}: {e}")
        
        return examples
    
    def generate_basic_examples(self, shield_doc: ShieldDocumentation) -> List[ExampleCode]:
        """Generate basic usage examples."""
        examples = []
        
        # Basic instantiation example
        basic_code = self._generate_basic_usage_example(shield_doc)
        if basic_code:
            examples.append(ExampleCode(
                title=f"Basic {shield_doc.name} Usage",
                description=f"Basic example of how to use {shield_doc.name}",
                code=basic_code,
                type=ExampleType.BASIC_USAGE,
                tags=["basic", "usage"]
            ))
        
        # Configuration example
        config_code = self._generate_configuration_example(shield_doc)
        if config_code:
            examples.append(ExampleCode(
                title=f"{shield_doc.name} Configuration",
                description=f"Example configuration for {shield_doc.name}",
                code=config_code,
                type=ExampleType.CONFIGURATION,
                tags=["configuration", "setup"]
            ))
        
        # Integration example
        integration_code = self._generate_integration_example(shield_doc)
        if integration_code:
            examples.append(ExampleCode(
                title=f"{shield_doc.name} Integration",
                description=f"Example of integrating {shield_doc.name} with FastAPI",
                code=integration_code,
                type=ExampleType.INTEGRATION,
                tags=["integration", "fastapi"]
            ))
        
        return examples
    
    def _parse_test_file(self, test_file: Path) -> List[ExampleCode]:
        """Parse a test file for examples."""
        examples = []
        
        try:
            with open(test_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST to find test functions
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
                    example = self._extract_test_example(node, content)
                    if example:
                        examples.append(example)
        
        except Exception as e:
            self.logger.debug(f"Failed to parse test file {test_file}: {e}")
        
        return examples
    
    def _extract_test_example(self, test_func: ast.FunctionDef, source_code: str) -> Optional[ExampleCode]:
        """Extract example from a test function."""
        try:
            # Get the source code of the test function
            lines = source_code.split('\n')
            start_line = test_func.lineno - 1
            
            # Find the end of the function
            end_line = start_line
            indent_level = None
            
            for i in range(start_line + 1, len(lines)):
                line = lines[i]
                if line.strip() == '':
                    continue
                
                if indent_level is None and line.strip():
                    indent_level = len(line) - len(line.lstrip())
                
                if line.strip() and (len(line) - len(line.lstrip())) <= indent_level - 4:
                    end_line = i
                    break
            else:
                end_line = len(lines)
            
            # Extract function code
            func_lines = lines[start_line:end_line]
            func_code = '\n'.join(func_lines)
            
            # Clean up the code
            func_code = textwrap.dedent(func_code)
            
            # Extract docstring for description
            docstring = ast.get_docstring(test_func) or f"Test: {test_func.name}"
            
            # Determine example type based on test name
            example_type = self._determine_example_type(test_func.name)
            
            return ExampleCode(
                title=self._format_test_title(test_func.name),
                description=docstring,
                code=func_code,
                type=example_type,
                tags=["test", "example"]
            )
        
        except Exception as e:
            self.logger.debug(f"Failed to extract example from test {test_func.name}: {e}")
            return None
    
    def _generate_basic_usage_example(self, shield_doc: ShieldDocumentation) -> str:
        """Generate basic usage example code."""
        shield_name = shield_doc.name
        
        # Required parameters
        required_params = [p for p in shield_doc.parameters if p.required and p.name != 'self']
        
        # Build parameter list
        params = []
        for param in required_params:
            if param.examples:
                value = param.examples[0]
            elif param.type == "str":
                value = f'"{param.name}_value"'
            elif param.type == "int":
                value = "1"
            elif param.type == "float":
                value = "1.0"
            elif param.type == "bool":
                value = "True"
            else:
                value = f'"{param.name}_value"'
            
            params.append(f"{param.name}={value}")
        
        param_str = ", ".join(params)
        
        return f'''from fastapi import FastAPI
from fastapi_shield import {shield_name}

app = FastAPI()

# Create shield instance
shield = {shield_name}({param_str})

# Apply shield to your FastAPI app
@app.get("/protected")
@shield
async def protected_endpoint():
    return {{"message": "This endpoint is protected by {shield_name}"}}
'''
    
    def _generate_configuration_example(self, shield_doc: ShieldDocumentation) -> str:
        """Generate configuration example."""
        shield_name = shield_doc.name
        
        if not shield_doc.parameters:
            return ""
        
        # Build configuration dictionary
        config_items = []
        params_list = [p for p in shield_doc.parameters if p.name != 'self']
        
        for i, param in enumerate(params_list):
            if param.examples:
                value = repr(param.examples[0])
            elif param.default is not None:
                value = repr(param.default)
            elif param.type == "str":
                value = f'"{param.name}_value"'
            elif param.type == "int":
                value = "1"
            elif param.type == "float":
                value = "1.0"
            elif param.type == "bool":
                value = "True"
            else:
                value = f'"{param.name}_value"'
            
            # Add comma except for last item
            comma = "," if i < len(params_list) - 1 else ""
            config_items.append(f'    "{param.name}": {value}{comma}  # {param.description}')
        
        config_str = "\n".join(config_items)
        
        return f'''from fastapi_shield import {shield_name}

# Configuration dictionary
config = {{
{config_str}
}}

# Create shield with configuration
shield = {shield_name}(**config)

# You can also use YAML configuration
# config.yaml:
# {shield_name.lower()}:
{chr(10).join(f"#   {param.name}: {param.default if param.default is not None else 'value'}" for param in shield_doc.parameters if param.name != 'self')}
'''
    
    def _generate_integration_example(self, shield_doc: ShieldDocumentation) -> str:
        """Generate integration example."""
        shield_name = shield_doc.name
        
        return f'''from fastapi import FastAPI, Depends
from fastapi_shield import {shield_name}, ShieldManager

app = FastAPI()

# Create shield manager
shield_manager = ShieldManager()

# Create and register shield
shield = {shield_name}()
shield_manager.add_shield(shield)

# Apply to specific routes
@app.get("/api/users")
@shield
async def get_users():
    return {{"users": []}}

# Apply to multiple routes with middleware
app.add_middleware(shield_manager.middleware)

# Use with dependency injection
@app.get("/api/protected")
async def protected_route(request=Depends(shield.dependency)):
    return {{"status": "protected"}}

# Conditional application
@app.get("/api/conditional")
@shield.when(lambda request: request.method == "POST")
async def conditional_protection():
    return {{"status": "conditionally protected"}}
'''
    
    def _determine_example_type(self, test_name: str) -> ExampleType:
        """Determine example type from test name."""
        test_name_lower = test_name.lower()
        
        if 'config' in test_name_lower:
            return ExampleType.CONFIGURATION
        elif 'integration' in test_name_lower or 'fastapi' in test_name_lower:
            return ExampleType.INTEGRATION
        elif 'error' in test_name_lower or 'exception' in test_name_lower:
            return ExampleType.ERROR_HANDLING
        elif 'advanced' in test_name_lower:
            return ExampleType.ADVANCED
        else:
            return ExampleType.BASIC_USAGE
    
    def _format_test_title(self, test_name: str) -> str:
        """Format test name as a readable title."""
        # Remove 'test_' prefix
        title = test_name.replace('test_', '')
        
        # Replace underscores with spaces
        title = title.replace('_', ' ')
        
        # Capitalize words
        title = title.title()
        
        return title


class DocumentationRenderer:
    """Render documentation in various formats."""
    
    def __init__(self, config: DocumentationConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize Jinja2 environment if available
        if JINJA2_AVAILABLE:
            template_paths = [str(self.config.template_dir)] if self.config.template_dir else []
            template_paths.append(str(Path(__file__).parent / "templates"))
            
            self.jinja_env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(template_paths),
                autoescape=jinja2.select_autoescape(['html', 'xml'])
            )
        else:
            self.jinja_env = None
    
    def render_shield_documentation(
        self, 
        shield_doc: ShieldDocumentation, 
        examples: List[ExampleCode],
        format: DocFormat = DocFormat.MARKDOWN
    ) -> str:
        """Render shield documentation in specified format."""
        
        if format == DocFormat.MARKDOWN:
            return self._render_markdown(shield_doc, examples)
        elif format == DocFormat.HTML:
            return self._render_html(shield_doc, examples)
        elif format == DocFormat.RST:
            return self._render_rst(shield_doc, examples)
        elif format == DocFormat.JSON:
            return self._render_json(shield_doc, examples)
        elif format == DocFormat.YAML:
            return self._render_yaml(shield_doc, examples)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def render_api_documentation(
        self,
        shields: List[ShieldDocumentation],
        format: DocFormat = DocFormat.MARKDOWN
    ) -> str:
        """Render complete API documentation."""
        
        if format == DocFormat.MARKDOWN:
            return self._render_api_markdown(shields)
        elif format == DocFormat.HTML:
            return self._render_api_html(shields)
        elif format == DocFormat.OPENAPI:
            return self._render_openapi(shields)
        else:
            return self._render_api_markdown(shields)
    
    def _render_markdown(self, shield_doc: ShieldDocumentation, examples: List[ExampleCode]) -> str:
        """Render shield documentation as Markdown."""
        sections = []
        
        # Title and description
        sections.append(f"# {shield_doc.name}")
        sections.append(f"\n{shield_doc.description}\n")
        
        # Metadata
        if shield_doc.version or shield_doc.author or shield_doc.category:
            sections.append("## Information")
            if shield_doc.version:
                sections.append(f"- **Version**: {shield_doc.version}")
            if shield_doc.author:
                sections.append(f"- **Author**: {shield_doc.author}")
            if shield_doc.category:
                sections.append(f"- **Category**: {shield_doc.category}")
            if shield_doc.tags:
                sections.append(f"- **Tags**: {', '.join(shield_doc.tags)}")
            sections.append("")
        
        # Parameters
        if shield_doc.parameters:
            sections.append("## Parameters")
            sections.append("| Name | Type | Required | Default | Description |")
            sections.append("|------|------|----------|---------|-------------|")
            
            for param in shield_doc.parameters:
                required = "Yes" if param.required else "No"
                default = str(param.default) if param.default is not None else "None"
                sections.append(f"| {param.name} | {param.type} | {required} | {default} | {param.description} |")
            sections.append("")
        
        # Configuration
        if shield_doc.configuration:
            sections.append("## Configuration")
            sections.append("```yaml")
            sections.append(yaml.dump(shield_doc.configuration, default_flow_style=False))
            sections.append("```")
            sections.append("")
        
        # Examples
        if examples:
            sections.append("## Examples")
            for example in examples:
                sections.append(f"### {example.title}")
                sections.append(f"{example.description}\n")
                sections.append(f"```{example.language}")
                sections.append(example.code)
                sections.append("```")
                sections.append("")
        
        # Methods
        if shield_doc.methods:
            sections.append("## Methods")
            for method in shield_doc.methods:
                sections.append(f"### {method['name']}")
                sections.append(f"```python")
                sections.append(f"{method['name']}{method['signature']}")
                sections.append("```")
                sections.append(f"{method['description']}\n")
        
        # Dependencies
        if shield_doc.dependencies:
            sections.append("## Dependencies")
            for dep in shield_doc.dependencies:
                sections.append(f"- {dep}")
            sections.append("")
        
        # Notes and warnings
        if shield_doc.notes:
            sections.append("## Notes")
            for note in shield_doc.notes:
                sections.append(f"- {note}")
            sections.append("")
        
        if shield_doc.warnings:
            sections.append("## Warnings")
            for warning in shield_doc.warnings:
                sections.append(f"⚠️ {warning}")
            sections.append("")
        
        # See also
        if shield_doc.see_also:
            sections.append("## See Also")
            for see_also in shield_doc.see_also:
                sections.append(f"- {see_also}")
            sections.append("")
        
        return "\n".join(sections)
    
    def _render_html(self, shield_doc: ShieldDocumentation, examples: List[ExampleCode]) -> str:
        """Render shield documentation as HTML."""
        if self.jinja_env:
            try:
                template = self.jinja_env.get_template("shield.html")
                return template.render(shield=shield_doc, examples=examples, config=self.config)
            except Exception as e:
                self.logger.warning(f"Failed to use template: {e}")
        
        # Fallback: Convert markdown to HTML
        markdown_content = self._render_markdown(shield_doc, examples)
        
        if MARKDOWN_AVAILABLE:
            md = markdown.Markdown(extensions=[
                'codehilite',
                'fenced_code',
                'tables',
                'toc'
            ])
            html_content = md.convert(markdown_content)
            
            return f'''<!DOCTYPE html>
<html>
<head>
    <title>{shield_doc.name} - {self.config.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        code {{ background-color: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
        pre {{ background-color: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        {self.config.custom_css or ""}
    </style>
</head>
<body>
{html_content}
</body>
</html>'''
        else:
            # Simple HTML conversion
            html_content = markdown_content.replace('\n', '<br>\n')
            return f'''<!DOCTYPE html>
<html>
<head>
    <title>{shield_doc.name}</title>
</head>
<body>
<pre>{html_content}</pre>
</body>
</html>'''
    
    def _render_rst(self, shield_doc: ShieldDocumentation, examples: List[ExampleCode]) -> str:
        """Render shield documentation as reStructuredText."""
        sections = []
        
        # Title
        title = shield_doc.name
        sections.append(title)
        sections.append("=" * len(title))
        sections.append("")
        
        sections.append(shield_doc.description)
        sections.append("")
        
        # Parameters
        if shield_doc.parameters:
            sections.append("Parameters")
            sections.append("-" * 10)
            sections.append("")
            
            for param in shield_doc.parameters:
                sections.append(f"**{param.name}** : {param.type}")
                sections.append(f"    {param.description}")
                if not param.required:
                    sections.append(f"    Default: {param.default}")
                sections.append("")
        
        # Examples
        if examples:
            sections.append("Examples")
            sections.append("-" * 8)
            sections.append("")
            
            for example in examples:
                sections.append(example.title)
                sections.append("^" * len(example.title))
                sections.append("")
                sections.append(example.description)
                sections.append("")
                sections.append(".. code-block:: " + example.language)
                sections.append("")
                for line in example.code.split('\n'):
                    sections.append("    " + line)
                sections.append("")
        
        return "\n".join(sections)
    
    def _render_json(self, shield_doc: ShieldDocumentation, examples: List[ExampleCode]) -> str:
        """Render shield documentation as JSON."""
        doc_data = shield_doc.to_dict()
        doc_data["examples"] = [example.to_dict() for example in examples]
        
        return json.dumps(doc_data, indent=2, default=str)
    
    def _render_yaml(self, shield_doc: ShieldDocumentation, examples: List[ExampleCode]) -> str:
        """Render shield documentation as YAML."""
        doc_data = shield_doc.to_dict()
        doc_data["examples"] = [example.to_dict() for example in examples]
        
        return yaml.dump(doc_data, default_flow_style=False, allow_unicode=True)
    
    def _render_api_markdown(self, shields: List[ShieldDocumentation]) -> str:
        """Render complete API documentation as Markdown."""
        sections = []
        
        sections.append(f"# {self.config.title}")
        sections.append(f"\n{self.config.description}\n")
        
        # Table of contents
        sections.append("## Table of Contents")
        for shield in shields:
            sections.append(f"- [{shield.name}](#{shield.name.lower()})")
        sections.append("")
        
        # Shield documentation
        for shield in shields:
            sections.append(f"## {shield.name}")
            sections.append(f"{shield.description}\n")
            
            if shield.parameters:
                sections.append("### Parameters")
                sections.append("| Name | Type | Required | Description |")
                sections.append("|------|------|----------|-------------|")
                
                for param in shield.parameters:
                    required = "Yes" if param.required else "No"
                    sections.append(f"| {param.name} | {param.type} | {required} | {param.description} |")
                sections.append("")
        
        return "\n".join(sections)
    
    def _render_api_html(self, shields: List[ShieldDocumentation]) -> str:
        """Render complete API documentation as HTML."""
        markdown_content = self._render_api_markdown(shields)
        
        if MARKDOWN_AVAILABLE:
            md = markdown.Markdown(extensions=['codehilite', 'fenced_code', 'tables', 'toc'])
            html_content = md.convert(markdown_content)
            
            return f'''<!DOCTYPE html>
<html>
<head>
    <title>{self.config.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        {self.config.custom_css or ""}
    </style>
</head>
<body>
{html_content}
</body>
</html>'''
        else:
            return f"<html><body><pre>{markdown_content}</pre></body></html>"
    
    def _render_openapi(self, shields: List[ShieldDocumentation]) -> str:
        """Render OpenAPI schema with shield information."""
        openapi_schema = {
            "openapi": "3.0.0",
            "info": {
                "title": self.config.title,
                "version": self.config.version,
                "description": self.config.description
            },
            "components": {
                "schemas": {},
                "securitySchemes": {}
            },
            "paths": {},
            "x-shields": {}
        }
        
        # Add shield information
        for shield in shields:
            openapi_schema["x-shields"][shield.name] = {
                "description": shield.description,
                "parameters": [param.to_dict() for param in shield.parameters],
                "configuration": shield.configuration,
                "category": shield.category,
                "tags": shield.tags
            }
        
        return json.dumps(openapi_schema, indent=2)


@dataclass
class DocumentationQuality:
    """Documentation quality metrics."""
    completeness_score: float = 0.0  # 0-100 score
    readability_score: float = 0.0  # 0-100 score  
    example_coverage: float = 0.0  # Percentage of shields with examples
    parameter_coverage: float = 0.0  # Percentage of parameters documented
    validation_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    
    def overall_score(self) -> float:
        """Calculate overall quality score."""
        return (
            self.completeness_score * 0.3 +
            self.readability_score * 0.2 +
            self.example_coverage * 0.25 +
            self.parameter_coverage * 0.25
        )
    
    def grade(self) -> str:
        """Get quality grade."""
        score = self.overall_score()
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


class DocumentationValidator:
    """Advanced documentation validation and quality assurance."""
    
    def __init__(self, config: DocumentationConfig = None):
        self.config = config or DocumentationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def validate_documentation_quality(
        self, 
        shield_docs: List[ShieldDocumentation],
        generated_files: Dict[str, str] = None
    ) -> DocumentationQuality:
        """Comprehensive documentation quality assessment."""
        
        quality = DocumentationQuality()
        
        # Calculate completeness score
        quality.completeness_score = self._calculate_completeness(shield_docs)
        
        # Calculate readability score
        quality.readability_score = self._calculate_readability(shield_docs)
        
        # Calculate example coverage
        quality.example_coverage = self._calculate_example_coverage(shield_docs)
        
        # Calculate parameter coverage
        quality.parameter_coverage = self._calculate_parameter_coverage(shield_docs)
        
        # Validate generated files
        if generated_files:
            file_errors = self._validate_generated_files(generated_files)
            quality.validation_errors.extend(file_errors)
        
        # Generate suggestions
        quality.suggestions = self._generate_suggestions(shield_docs, quality)
        
        # Generate warnings
        quality.warnings = self._generate_warnings(shield_docs, quality)
        
        return quality
    
    def _calculate_completeness(self, shield_docs: List[ShieldDocumentation]) -> float:
        """Calculate documentation completeness score."""
        if not shield_docs:
            return 0.0
        
        total_score = 0.0
        for doc in shield_docs:
            score = 0.0
            
            # Check description
            if doc.description and len(doc.description) >= self.config.min_description_length:
                score += 25
            
            # Check parameters
            if doc.parameters:
                param_score = sum(
                    20 for param in doc.parameters 
                    if param.description and len(param.description) >= 5
                ) / len(doc.parameters)
                score += min(param_score, 25)
            else:
                score += 25  # No parameters needed
            
            # Check examples
            if doc.examples:
                score += 25
            
            # Check configuration
            if doc.configuration:
                score += 25
            
            total_score += min(score, 100)
        
        return total_score / len(shield_docs)
    
    def _calculate_readability(self, shield_docs: List[ShieldDocumentation]) -> float:
        """Calculate readability score using various metrics."""
        total_score = 0.0
        
        for doc in shield_docs:
            score = 0.0
            
            # Check description readability
            if doc.description:
                # Simple readability heuristics
                sentences = doc.description.split('.')
                avg_sentence_length = sum(len(s.split()) for s in sentences) / max(len(sentences), 1)
                
                # Prefer moderate sentence lengths (8-20 words)
                if 8 <= avg_sentence_length <= 20:
                    score += 30
                elif 5 <= avg_sentence_length <= 25:
                    score += 20
                else:
                    score += 10
                
                # Check for clear structure
                if any(word in doc.description.lower() for word in ['this', 'will', 'should', 'can']):
                    score += 20
                
                # Check for technical clarity
                if any(word in doc.description.lower() for word in ['validate', 'protect', 'secure', 'ensure']):
                    score += 20
            
            # Check parameter descriptions
            if doc.parameters:
                clear_params = sum(
                    1 for param in doc.parameters
                    if param.description and len(param.description.split()) >= 3
                )
                score += (clear_params / len(doc.parameters)) * 30
            
            total_score += min(score, 100)
        
        return total_score / max(len(shield_docs), 1)
    
    def _calculate_example_coverage(self, shield_docs: List[ShieldDocumentation]) -> float:
        """Calculate example coverage percentage."""
        if not shield_docs:
            return 0.0
        
        docs_with_examples = sum(1 for doc in shield_docs if doc.examples)
        return (docs_with_examples / len(shield_docs)) * 100
    
    def _calculate_parameter_coverage(self, shield_docs: List[ShieldDocumentation]) -> float:
        """Calculate parameter documentation coverage."""
        total_params = 0
        documented_params = 0
        
        for doc in shield_docs:
            total_params += len(doc.parameters)
            documented_params += sum(
                1 for param in doc.parameters
                if param.description and len(param.description) >= 5
            )
        
        if total_params == 0:
            return 100.0
        
        return (documented_params / total_params) * 100
    
    def _validate_generated_files(self, generated_files: Dict[str, str]) -> List[str]:
        """Validate generated documentation files."""
        errors = []
        
        for filename, filepath in generated_files.items():
            try:
                file_path = Path(filepath)
                
                if not file_path.exists():
                    errors.append(f"Generated file does not exist: {filepath}")
                    continue
                
                content = file_path.read_text(encoding='utf-8')
                
                # Check file size
                if len(content.strip()) == 0:
                    errors.append(f"Empty generated file: {filename}")
                
                # Format-specific validation
                if filename.endswith('.json'):
                    try:
                        json.loads(content)
                    except json.JSONDecodeError as e:
                        errors.append(f"Invalid JSON in {filename}: {e}")
                
                elif filename.endswith('.yaml') or filename.endswith('.yml'):
                    try:
                        yaml.safe_load(content)
                    except yaml.YAMLError as e:
                        errors.append(f"Invalid YAML in {filename}: {e}")
                
                elif filename.endswith('.md'):
                    # Markdown validation
                    if not content.startswith('#'):
                        errors.append(f"Markdown file missing main header: {filename}")
                    
                    # Check for broken links
                    if self.config.validate_links:
                        broken_links = self._check_markdown_links(content, file_path.parent)
                        for link in broken_links:
                            errors.append(f"Broken link in {filename}: {link}")
                
            except Exception as e:
                errors.append(f"Error validating {filename}: {e}")
        
        return errors
    
    def _check_markdown_links(self, content: str, base_path: Path) -> List[str]:
        """Check for broken links in markdown content."""
        import re
        
        broken_links = []
        
        # Find markdown links [text](url)
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        links = re.findall(link_pattern, content)
        
        for text, url in links:
            if url.startswith('http'):
                # Skip external link validation for now
                continue
            elif url.startswith('#'):
                # Internal anchor link - would need more complex validation
                continue
            else:
                # Relative file link
                link_path = base_path / url
                if not link_path.exists():
                    broken_links.append(url)
        
        return broken_links
    
    def _generate_suggestions(
        self, 
        shield_docs: List[ShieldDocumentation], 
        quality: DocumentationQuality
    ) -> List[str]:
        """Generate improvement suggestions."""
        suggestions = []
        
        # General suggestions based on quality scores
        if quality.completeness_score < 80:
            suggestions.append("Consider adding more detailed descriptions and configuration examples")
        
        if quality.example_coverage < 90:
            suggestions.append("Add usage examples for shields that are missing them")
        
        if quality.parameter_coverage < 85:
            suggestions.append("Document all shield parameters with clear descriptions")
        
        if quality.readability_score < 75:
            suggestions.append("Improve readability with clearer, more structured descriptions")
        
        # Specific suggestions for individual shields
        for doc in shield_docs:
            if not doc.examples and self.config.require_examples:
                suggestions.append(f"Add usage examples for {doc.name}")
            
            if len(doc.description) < self.config.min_description_length:
                suggestions.append(f"Expand description for {doc.name} (minimum {self.config.min_description_length} characters)")
            
            undocumented_params = [
                param.name for param in doc.parameters
                if not param.description or len(param.description) < 5
            ]
            if undocumented_params:
                suggestions.append(f"Document parameters in {doc.name}: {', '.join(undocumented_params)}")
        
        return suggestions
    
    def _generate_warnings(
        self, 
        shield_docs: List[ShieldDocumentation], 
        quality: DocumentationQuality
    ) -> List[str]:
        """Generate warnings for potential issues."""
        warnings = []
        
        # Check for duplicate shield names
        names = [doc.name for doc in shield_docs]
        duplicates = set([name for name in names if names.count(name) > 1])
        if duplicates:
            warnings.append(f"Duplicate shield names found: {', '.join(duplicates)}")
        
        # Check for missing categories
        uncategorized = [doc.name for doc in shield_docs if not doc.category]
        if uncategorized:
            warnings.append(f"Shields without categories: {', '.join(uncategorized)}")
        
        # Check for very long descriptions
        long_descriptions = [
            doc.name for doc in shield_docs
            if doc.description and len(doc.description) > 1000
        ]
        if long_descriptions:
            warnings.append(f"Consider breaking up long descriptions: {', '.join(long_descriptions)}")
        
        return warnings


class DocumentationEnhancer:
    """Enhance documentation with advanced features."""
    
    def __init__(self, config: DocumentationConfig = None):
        self.config = config or DocumentationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def enhance_with_syntax_highlighting(self, content: str, language: str = "python") -> str:
        """Add syntax highlighting to code blocks."""
        if not PYGMENTS_AVAILABLE:
            return content
        
        try:
            lexer = pygments.lexers.get_lexer_by_name(language)
            formatter = pygments.formatters.HtmlFormatter()
            return pygments.highlight(content, lexer, formatter)
        except Exception as e:
            self.logger.warning(f"Failed to apply syntax highlighting: {e}")
            return content
    
    def add_cross_references(self, content: str, shield_docs: List[ShieldDocumentation]) -> str:
        """Add automatic cross-references between shields."""
        if not self.config.auto_cross_references:
            return content
        
        enhanced_content = content
        shield_names = [doc.name for doc in shield_docs]
        
        # Simple cross-reference replacement
        for name in shield_names:
            if name in content and f"[{name}]" not in content:
                enhanced_content = enhanced_content.replace(
                    name, 
                    f"[{name}](#{name.lower().replace(' ', '-')})",
                    1  # Only replace first occurrence to avoid over-linking
                )
        
        return enhanced_content
    
    def generate_search_index(self, shield_docs: List[ShieldDocumentation]) -> Dict[str, Any]:
        """Generate search index for documentation."""
        if not self.config.generate_search_index:
            return {}
        
        index = {
            "version": "1.0",
            "documents": [],
            "index": {}
        }
        
        # Add documents to index
        for i, doc in enumerate(shield_docs):
            document = {
                "id": i,
                "title": doc.name,
                "content": doc.description,
                "url": f"#{doc.name.lower().replace(' ', '-')}",
                "tags": doc.tags
            }
            index["documents"].append(document)
            
            # Simple keyword indexing
            words = (doc.name + " " + doc.description).lower().split()
            for word in words:
                if len(word) > 2:  # Skip very short words
                    if word not in index["index"]:
                        index["index"][word] = []
                    index["index"][word].append(i)
        
        return index
    
    def add_performance_metrics(self, shield_doc: ShieldDocumentation) -> ShieldDocumentation:
        """Add performance metrics to shield documentation."""
        if not self.config.include_performance_metrics:
            return shield_doc
        
        # This would integrate with benchmarking data
        # For now, add placeholder performance section
        performance_note = """
## Performance Metrics

| Metric | Value |
|--------|--------|
| Average Latency | < 1ms |
| Memory Usage | < 10MB |
| CPU Impact | < 5% |

*Metrics based on standard benchmark scenarios*
"""
        
        shield_doc.notes.append(performance_note)
        return shield_doc
    
    def add_security_notes(self, shield_doc: ShieldDocumentation) -> ShieldDocumentation:
        """Add security considerations to shield documentation."""
        if not self.config.include_security_notes:
            return shield_doc
        
        # Add security section based on shield type/category
        security_templates = {
            "authentication": "⚠️ **Security Note**: This shield handles authentication data. Ensure sensitive information is properly encrypted and logged securely.",
            "authorization": "🔒 **Security Note**: Authorization decisions should be logged for audit purposes. Consider implementing fail-secure defaults.",
            "input_validation": "🛡️ **Security Note**: Input validation is critical for security. Ensure all edge cases are covered and validation errors don't leak sensitive information.",
            "rate_limiting": "⚡ **Security Note**: Rate limiting helps prevent abuse. Consider implementing distributed rate limiting for multi-instance deployments."
        }
        
        category = shield_doc.category.lower() if shield_doc.category else ""
        for security_category, note in security_templates.items():
            if security_category in category or security_category in shield_doc.name.lower():
                if note not in shield_doc.notes:
                    shield_doc.notes.append(note)
                break
        
        return shield_doc


class DocumentationGenerator:
    """Main documentation generator with advanced features."""
    
    def __init__(self, config: DocumentationConfig = None):
        self.config = config or DocumentationConfig()
        self.introspector = ShieldIntrospector()
        self.example_extractor = ExampleExtractor()
        self.renderer = DocumentationRenderer(self.config)
        self.validator = DocumentationValidator(self.config)
        self.enhancer = DocumentationEnhancer(self.config)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def generate_shield_docs(
        self, 
        shield_classes: List[Type[Shield]],
        test_directories: List[Path] = None
    ) -> Dict[str, str]:
        """Generate documentation for multiple shields."""
        
        self.logger.info(f"Generating documentation for {len(shield_classes)} shields")
        
        # Create output directory
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        
        generated_docs = {}
        shield_docs = []
        
        for shield_class in shield_classes:
            try:
                self.logger.info(f"Processing shield: {shield_class.__name__}")
                
                # Analyze shield
                shield_doc = self.introspector.analyze_shield(shield_class)
                shield_docs.append(shield_doc)
                
                # Extract examples
                examples = []
                
                # Generate basic examples
                basic_examples = self.example_extractor.generate_basic_examples(shield_doc)
                examples.extend(basic_examples)
                
                # Extract from tests if provided
                if test_directories:
                    test_files = []
                    for test_dir in test_directories:
                        if test_dir.exists():
                            test_files.extend(test_dir.glob("**/test_*.py"))
                    
                    if test_files:
                        test_examples = self.example_extractor.extract_from_tests(test_files)
                        examples.extend(test_examples)
                
                # Render documentation in all requested formats
                for doc_format in self.config.formats:
                    try:
                        content = self.renderer.render_shield_documentation(
                            shield_doc, examples, doc_format
                        )
                        
                        # Save to file
                        filename = f"{shield_class.__name__.lower()}.{doc_format.value}"
                        output_path = self.config.output_dir / filename
                        
                        with open(output_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        generated_docs[f"{shield_class.__name__}.{doc_format.value}"] = str(output_path)
                        
                    except Exception as e:
                        self.logger.error(f"Failed to render {shield_class.__name__} as {doc_format}: {e}")
            
            except Exception as e:
                self.logger.error(f"Failed to process shield {shield_class.__name__}: {e}")
        
        # Generate API overview
        try:
            for doc_format in self.config.formats:
                if doc_format in [DocFormat.MARKDOWN, DocFormat.HTML, DocFormat.OPENAPI]:
                    content = self.renderer.render_api_documentation(shield_docs, doc_format)
                    
                    filename = f"api.{doc_format.value}"
                    output_path = self.config.output_dir / filename
                    
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    generated_docs[f"api.{doc_format.value}"] = str(output_path)
        
        except Exception as e:
            self.logger.error(f"Failed to generate API overview: {e}")
        
        # Generate quality report
        self.logger.info("Assessing documentation quality...")
        quality = self.validator.validate_documentation_quality(shield_docs, generated_docs)
        
        self.logger.info(f"Documentation Quality Assessment:")
        self.logger.info(f"  Overall Score: {quality.overall_score():.1f}/100 (Grade: {quality.grade()})")
        self.logger.info(f"  Completeness: {quality.completeness_score:.1f}%")
        self.logger.info(f"  Readability: {quality.readability_score:.1f}%")
        self.logger.info(f"  Example Coverage: {quality.example_coverage:.1f}%")
        self.logger.info(f"  Parameter Coverage: {quality.parameter_coverage:.1f}%")
        
        if quality.validation_errors:
            self.logger.warning(f"Validation Errors ({len(quality.validation_errors)}):")
            for error in quality.validation_errors:
                self.logger.warning(f"  - {error}")
        
        if quality.suggestions:
            self.logger.info(f"Improvement Suggestions ({len(quality.suggestions)}):")
            for suggestion in quality.suggestions[:5]:  # Show first 5
                self.logger.info(f"  - {suggestion}")
        
        # Generate search index if enabled
        if self.config.generate_search_index:
            search_index = self.enhancer.generate_search_index(shield_docs)
            if search_index:
                search_index_path = self.config.output_dir / "search_index.json"
                with open(search_index_path, 'w') as f:
                    json.dump(search_index, f, indent=2)
                generated_docs["search_index.json"] = str(search_index_path)
        
        # Save quality report
        quality_report_path = self.config.output_dir / "quality_report.json"
        with open(quality_report_path, 'w') as f:
            json.dump({
                "overall_score": quality.overall_score(),
                "grade": quality.grade(),
                "completeness_score": quality.completeness_score,
                "readability_score": quality.readability_score,
                "example_coverage": quality.example_coverage,
                "parameter_coverage": quality.parameter_coverage,
                "validation_errors": quality.validation_errors,
                "warnings": quality.warnings,
                "suggestions": quality.suggestions,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }, f, indent=2)
        generated_docs["quality_report.json"] = str(quality_report_path)
        
        self.logger.info(f"Documentation generation complete. Generated {len(generated_docs)} files.")
        return generated_docs
    
    def generate_mkdocs_config(self, shield_classes: List[Type[Shield]]) -> str:
        """Generate MkDocs configuration."""
        config = {
            "site_name": self.config.title,
            "site_description": self.config.description,
            "site_author": self.config.author,
            "docs_dir": str(self.config.output_dir),
            "theme": {
                "name": "material" if self.config.theme == "material" else "readthedocs",
                "palette": {
                    "primary": "blue",
                    "accent": "blue"
                }
            },
            "nav": [
                {"Home": "api.md"},
                {"Shields": [
                    {shield_class.__name__: f"{shield_class.__name__.lower()}.md"}
                    for shield_class in shield_classes
                ]}
            ],
            "markdown_extensions": [
                "codehilite",
                "admonition",
                "toc",
                "tables"
            ],
            "plugins": [
                "search"
            ]
        }
        
        mkdocs_path = self.config.output_dir / "mkdocs.yml"
        with open(mkdocs_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        return str(mkdocs_path)
    
    def generate_sphinx_config(self, shield_classes: List[Type[Shield]]) -> str:
        """Generate Sphinx configuration."""
        config_content = f'''
# Configuration file for the Sphinx documentation builder.

project = '{self.config.title}'
copyright = '2024, {self.config.author}'
author = '{self.config.author}'
version = '{self.config.version}'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx_markdown_tables',
]

templates_path = ['_templates']
exclude_patterns = []

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Add custom CSS
html_css_files = ['custom.css']
'''
        
        sphinx_path = self.config.output_dir / "conf.py"
        with open(sphinx_path, 'w') as f:
            f.write(config_content)
        
        return str(sphinx_path)


# Convenience functions

def generate_shield_documentation(
    shield_classes: List[Type[Shield]], 
    output_dir: str = "docs",
    formats: List[DocFormat] = None,
    include_tests: bool = True
) -> Dict[str, str]:
    """Generate documentation for shield classes."""
    
    config = DocumentationConfig(
        output_dir=Path(output_dir),
        formats=formats or [DocFormat.MARKDOWN, DocFormat.HTML],
        include_tests=include_tests
    )
    
    generator = DocumentationGenerator(config)
    
    test_dirs = []
    if include_tests:
        # Look for test directories
        current_dir = Path.cwd()
        for test_dir in ["tests", "test", "../tests", "../test"]:
            test_path = current_dir / test_dir
            if test_path.exists():
                test_dirs.append(test_path)
    
    return generator.generate_shield_docs(shield_classes, test_dirs)


def create_mkdocs_site(
    shield_classes: List[Type[Shield]],
    output_dir: str = "docs",
    site_name: str = "Shield Documentation"
) -> str:
    """Create a complete MkDocs site for shields."""
    
    config = DocumentationConfig(
        title=site_name,
        output_dir=Path(output_dir),
        formats=[DocFormat.MARKDOWN]
    )
    
    generator = DocumentationGenerator(config)
    generator.generate_shield_docs(shield_classes)
    
    return generator.generate_mkdocs_config(shield_classes)


def create_sphinx_site(
    shield_classes: List[Type[Shield]],
    output_dir: str = "docs", 
    project_name: str = "Shield Documentation"
) -> str:
    """Create a complete Sphinx site for shields."""
    
    config = DocumentationConfig(
        title=project_name,
        output_dir=Path(output_dir),
        formats=[DocFormat.RST]
    )
    
    generator = DocumentationGenerator(config)
    generator.generate_shield_docs(shield_classes)
    
    return generator.generate_sphinx_config(shield_classes)