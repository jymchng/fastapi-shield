"""Mock classes and utilities for testing the Shield Documentation Generator system."""

import ast
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union
from unittest.mock import Mock, MagicMock

from fastapi_shield.shield import Shield
from fastapi_shield.documentation import (
    DocumentationConfig, ShieldDocumentation, ParameterInfo, ExampleCode,
    DocFormat, DocSection, ExampleType
)


class MockShield(Shield):
    """Mock shield for testing documentation generation."""
    
    __version__ = "2.0.0"
    __author__ = "Test Author"
    _category = "security"
    _tags = ["test", "mock", "security"]
    _notes = ["This is a test shield", "Used for documentation testing"]
    _warnings = ["This is a mock implementation", "Do not use in production"]
    _see_also = ["RealShield", "AnotherShield"]
    
    def __init__(self, 
                 enabled: bool = True, 
                 threshold: int = 100, 
                 message: str = "Access denied",
                 config: Optional[Dict[str, Any]] = None):
        """Initialize the mock shield.
        
        Args:
            enabled: Whether the shield is enabled
            threshold: The threshold value for triggering
            message: The message to return when triggered
            config: Additional configuration dictionary
        """
        self.enabled = enabled
        self.threshold = threshold
        self.message = message
        self.config = config or {}
    
    async def __call__(self, request):
        """Process the request through the shield.
        
        Args:
            request: The incoming request to process
            
        Returns:
            The request if allowed, or raises an exception if blocked
        """
        if not self.enabled:
            return request
        
        # Mock processing logic
        if hasattr(request, 'headers') and len(request.headers) > self.threshold:
            raise ValueError(self.message)
        
        return request
    
    def configure(self, **kwargs):
        """Configure the shield with new parameters.
        
        Args:
            **kwargs: Configuration parameters
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the shield.
        
        Returns:
            Dictionary containing shield status information
        """
        return {
            "enabled": self.enabled,
            "threshold": self.threshold,
            "message": self.message,
            "config": self.config
        }


class MockComplexShield(Shield):
    """Mock shield with complex parameters for testing."""
    
    def __init__(self, 
                 rate_limit: int = 100,
                 time_window: float = 60.0,
                 block_list: List[str] = None,
                 allow_list: List[str] = None,
                 custom_headers: Dict[str, str] = None,
                 enable_logging: bool = True,
                 log_level: str = "INFO",
                 retry_after: Optional[int] = None):
        """Initialize complex shield with various parameter types.
        
        Args:
            rate_limit: Maximum requests per time window
            time_window: Time window in seconds
            block_list: List of blocked IPs or patterns
            allow_list: List of allowed IPs or patterns
            custom_headers: Custom headers to add to responses
            enable_logging: Whether to enable logging
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
            retry_after: Retry-After header value in seconds
        """
        self.rate_limit = rate_limit
        self.time_window = time_window
        self.block_list = block_list or []
        self.allow_list = allow_list or []
        self.custom_headers = custom_headers or {}
        self.enable_logging = enable_logging
        self.log_level = log_level
        self.retry_after = retry_after
    
    async def __call__(self, request):
        """Process request with complex logic."""
        # Mock implementation
        return request


class MockMinimalShield(Shield):
    """Minimal shield for testing basic documentation."""
    
    def __init__(self):
        """Initialize minimal shield."""
        pass
    
    async def __call__(self, request):
        """Simple pass-through."""
        return request


class DocumentationTestHelper:
    """Helper for creating test documentation scenarios."""
    
    @staticmethod
    def create_sample_shield_doc() -> ShieldDocumentation:
        """Create a sample shield documentation."""
        parameters = [
            ParameterInfo(
                name="enabled",
                type="bool",
                description="Whether the shield is enabled",
                default=True,
                required=False,
                examples=[True, False]
            ),
            ParameterInfo(
                name="threshold",
                type="int", 
                description="Threshold value for triggering",
                default=100,
                required=False,
                constraints={"min": 1, "max": 1000},
                examples=[50, 100, 200]
            ),
            ParameterInfo(
                name="message",
                type="str",
                description="Message to return when triggered",
                default="Access denied",
                required=False,
                examples=["Access denied", "Rate limit exceeded"]
            )
        ]
        
        return ShieldDocumentation(
            name="TestShield",
            description="A test shield for documentation generation",
            version="1.0.0",
            author="Test Author",
            category="security",
            tags=["test", "security"],
            parameters=parameters,
            configuration={
                "validation_rules": [
                    {"path": "enabled", "type": "required"},
                    {"path": "threshold", "type": "range", "constraint": [1, 1000]}
                ]
            },
            methods=[
                {
                    "name": "__call__",
                    "signature": "(self, request)",
                    "description": "Process the request",
                    "async": True,
                    "parameters": [
                        {"name": "request", "type": "Request", "required": True}
                    ]
                }
            ],
            dependencies=["fastapi", "pydantic"],
            notes=["This is a test shield"],
            warnings=["Test implementation only"],
            see_also=["RealShield"]
        )
    
    @staticmethod
    def create_sample_examples() -> List[ExampleCode]:
        """Create sample example codes."""
        return [
            ExampleCode(
                title="Basic Usage",
                description="Simple example of using the shield",
                code='''from fastapi_shield import TestShield

shield = TestShield(enabled=True, threshold=100)

@app.get("/protected")
@shield
async def protected_endpoint():
    return {"message": "Success"}''',
                type=ExampleType.BASIC_USAGE,
                tags=["basic", "usage"]
            ),
            ExampleCode(
                title="Configuration Example",
                description="Example of configuring the shield",
                code='''config = {
    "enabled": True,
    "threshold": 50,
    "message": "Custom message"
}

shield = TestShield(**config)''',
                type=ExampleType.CONFIGURATION,
                tags=["configuration"]
            ),
            ExampleCode(
                title="Integration with FastAPI",
                description="Complete integration example",
                code='''from fastapi import FastAPI
from fastapi_shield import TestShield

app = FastAPI()
shield = TestShield()

app.add_middleware(shield.middleware)

@app.get("/api/data")
async def get_data():
    return {"data": "protected"}''',
                type=ExampleType.INTEGRATION,
                tags=["integration", "fastapi"]
            )
        ]
    
    @staticmethod
    def create_test_config() -> DocumentationConfig:
        """Create test documentation configuration."""
        return DocumentationConfig(
            title="Test Documentation",
            version="1.0.0",
            description="Test documentation for shields",
            author="Test Author",
            output_dir=Path("test_docs"),
            include_private=False,
            include_tests=True,
            generate_examples=True,
            formats=[DocFormat.MARKDOWN, DocFormat.HTML, DocFormat.JSON],
            sections=[DocSection.OVERVIEW, DocSection.CONFIGURATION, DocSection.EXAMPLES],
            theme="default"
        )
    
    @staticmethod
    def create_mock_test_file_content() -> str:
        """Create mock test file content."""
        return '''
import pytest
from fastapi_shield import TestShield

class TestShieldTests:
    """Test cases for TestShield."""
    
    def test_basic_usage(self):
        """Test basic shield usage."""
        shield = TestShield(enabled=True)
        assert shield.enabled is True
    
    def test_configuration(self):
        """Test shield configuration."""
        config = {"threshold": 50, "message": "Custom"}
        shield = TestShield(**config)
        assert shield.threshold == 50
        assert shield.message == "Custom"
    
    def test_integration_example(self):
        """Test integration with FastAPI application."""
        from fastapi import FastAPI
        app = FastAPI()
        shield = TestShield()
        
        @app.get("/test")
        @shield
        async def test_endpoint():
            return {"success": True}
        
        # Test would continue here
        assert True
    
    def test_error_handling(self):
        """Test error handling scenarios."""
        shield = TestShield(enabled=True, threshold=0)
        # Mock request with many headers
        mock_request = type('MockRequest', (), {
            'headers': {f'header_{i}': f'value_{i}' for i in range(10)}
        })()
        
        # Should raise error due to threshold
        with pytest.raises(ValueError):
            await shield(mock_request)
    
    def test_advanced_configuration(self):
        """Test advanced configuration options."""
        config = {
            "enabled": True,
            "threshold": 100,
            "message": "Advanced blocking",
            "config": {"feature_flag": True}
        }
        shield = TestShield(**config)
        
        status = shield.get_status()
        assert status["enabled"] is True
        assert status["config"]["feature_flag"] is True
'''


class TempTestFile:
    """Temporary test file for testing example extraction."""
    
    def __init__(self, content: str, filename: str = "test_mock.py"):
        self.content = content
        self.filename = filename
        self.temp_file = None
        self.file_path = None
    
    def __enter__(self) -> Path:
        """Create temporary test file."""
        self.temp_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.py',
            prefix='test_',
            delete=False,
            encoding='utf-8'
        )
        self.temp_file.write(self.content)
        self.temp_file.close()
        self.file_path = Path(self.temp_file.name)
        return self.file_path
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up temporary file."""
        if self.file_path and self.file_path.exists():
            self.file_path.unlink()


class TempDocumentationDir:
    """Temporary directory for documentation output."""
    
    def __init__(self):
        self.temp_dir = None
        self.dir_path = None
    
    def __enter__(self) -> Path:
        """Create temporary documentation directory."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        return self.dir_path
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up temporary directory."""
        if self.temp_dir:
            self.temp_dir.cleanup()


class MockIntrospector:
    """Mock introspector for testing."""
    
    def __init__(self):
        self.analyze_calls = 0
        self.last_analyzed_shield = None
        self.should_fail = False
        self.return_doc = None
    
    def analyze_shield(self, shield_class: Type[Shield]) -> ShieldDocumentation:
        """Mock analyze shield method."""
        self.analyze_calls += 1
        self.last_analyzed_shield = shield_class
        
        if self.should_fail:
            raise Exception("Mock introspector failure")
        
        if self.return_doc:
            return self.return_doc
        
        return DocumentationTestHelper.create_sample_shield_doc()


class MockExampleExtractor:
    """Mock example extractor for testing."""
    
    def __init__(self):
        self.extract_calls = 0
        self.generate_calls = 0
        self.should_fail = False
        self.return_examples = None
    
    def extract_from_tests(self, test_files: List[Path]) -> List[ExampleCode]:
        """Mock extract from tests method."""
        self.extract_calls += 1
        
        if self.should_fail:
            raise Exception("Mock extractor failure")
        
        if self.return_examples:
            return self.return_examples
        
        return DocumentationTestHelper.create_sample_examples()
    
    def generate_basic_examples(self, shield_doc: ShieldDocumentation) -> List[ExampleCode]:
        """Mock generate basic examples method."""
        self.generate_calls += 1
        
        if self.should_fail:
            raise Exception("Mock generator failure")
        
        if self.return_examples:
            return self.return_examples
        
        return DocumentationTestHelper.create_sample_examples()


class MockRenderer:
    """Mock renderer for testing."""
    
    def __init__(self):
        self.render_shield_calls = 0
        self.render_api_calls = 0
        self.should_fail = False
        self.return_content = None
    
    def render_shield_documentation(
        self, 
        shield_doc: ShieldDocumentation,
        examples: List[ExampleCode],
        format: DocFormat = DocFormat.MARKDOWN
    ) -> str:
        """Mock render shield documentation method."""
        self.render_shield_calls += 1
        
        if self.should_fail:
            raise Exception("Mock renderer failure")
        
        if self.return_content:
            return self.return_content
        
        return f"# {shield_doc.name}\n\n{shield_doc.description}\n\n{len(examples)} examples"
    
    def render_api_documentation(
        self,
        shields: List[ShieldDocumentation],
        format: DocFormat = DocFormat.MARKDOWN
    ) -> str:
        """Mock render API documentation method."""
        self.render_api_calls += 1
        
        if self.should_fail:
            raise Exception("Mock API renderer failure")
        
        if self.return_content:
            return self.return_content
        
        return f"# API Documentation\n\n{len(shields)} shields documented"


class DocumentationValidationHelper:
    """Helper for validating generated documentation."""
    
    @staticmethod
    def validate_markdown_content(content: str) -> Dict[str, bool]:
        """Validate markdown content structure."""
        validation = {
            "has_title": False,
            "has_headers": False,
            "has_code_blocks": False,
            "has_tables": False,
            "has_links": False
        }
        
        lines = content.split('\n')
        
        for line in lines:
            # Check for title (H1)
            if line.startswith('# '):
                validation["has_title"] = True
            
            # Check for headers (H2, H3, etc.)
            if line.startswith('## ') or line.startswith('### '):
                validation["has_headers"] = True
            
            # Check for code blocks
            if line.startswith('```'):
                validation["has_code_blocks"] = True
            
            # Check for tables
            if '|' in line and '---' not in line:
                validation["has_tables"] = True
            
            # Check for links
            if '[' in line and '](' in line:
                validation["has_links"] = True
        
        return validation
    
    @staticmethod
    def validate_html_content(content: str) -> Dict[str, bool]:
        """Validate HTML content structure."""
        validation = {
            "has_doctype": "<!DOCTYPE html>" in content,
            "has_title": "<title>" in content,
            "has_headers": "<h1>" in content or "<h2>" in content,
            "has_code": "<code>" in content or "<pre>" in content,
            "has_tables": "<table>" in content,
            "has_body": "<body>" in content and "</body>" in content
        }
        
        return validation
    
    @staticmethod
    def validate_json_content(content: str) -> Dict[str, bool]:
        """Validate JSON content structure."""
        validation = {
            "is_valid_json": False,
            "has_name": False,
            "has_description": False,
            "has_parameters": False,
            "has_examples": False
        }
        
        try:
            import json
            data = json.loads(content)
            validation["is_valid_json"] = True
            
            validation["has_name"] = "name" in data
            validation["has_description"] = "description" in data
            validation["has_parameters"] = "parameters" in data and isinstance(data["parameters"], list)
            validation["has_examples"] = "examples" in data and isinstance(data["examples"], list)
            
        except json.JSONDecodeError:
            pass
        
        return validation
    
    @staticmethod
    def validate_yaml_content(content: str) -> Dict[str, bool]:
        """Validate YAML content structure."""
        validation = {
            "is_valid_yaml": False,
            "has_name": False,
            "has_description": False,
            "has_parameters": False,
            "has_examples": False
        }
        
        try:
            import yaml
            data = yaml.safe_load(content)
            validation["is_valid_yaml"] = True
            
            if isinstance(data, dict):
                validation["has_name"] = "name" in data
                validation["has_description"] = "description" in data
                validation["has_parameters"] = "parameters" in data and isinstance(data["parameters"], list)
                validation["has_examples"] = "examples" in data and isinstance(data["examples"], list)
            
        except yaml.YAMLError:
            pass
        
        return validation
    
    @staticmethod
    def count_sections(content: str, format: DocFormat) -> int:
        """Count sections in documentation."""
        if format == DocFormat.MARKDOWN:
            return len([line for line in content.split('\n') if line.startswith('## ')])
        elif format == DocFormat.HTML:
            import re
            return len(re.findall(r'<h[2-6]>', content))
        elif format == DocFormat.RST:
            lines = content.split('\n')
            return len([i for i, line in enumerate(lines) if i < len(lines) - 1 and 
                       lines[i + 1] and all(c in '-=^"' for c in lines[i + 1])])
        else:
            return 0
    
    @staticmethod
    def extract_code_examples(content: str, format: DocFormat) -> List[str]:
        """Extract code examples from documentation."""
        examples = []
        
        if format == DocFormat.MARKDOWN:
            lines = content.split('\n')
            in_code_block = False
            current_example = []
            
            for line in lines:
                if line.startswith('```'):
                    if in_code_block:
                        if current_example:
                            examples.append('\n'.join(current_example))
                            current_example = []
                        in_code_block = False
                    else:
                        in_code_block = True
                elif in_code_block:
                    current_example.append(line)
        
        return examples


class ShieldDocumentationBuilder:
    """Builder for creating complex shield documentation in tests."""
    
    def __init__(self):
        self.doc = ShieldDocumentation(
            name="TestShield",
            description="Test shield"
        )
    
    def with_name(self, name: str) -> 'ShieldDocumentationBuilder':
        """Set shield name."""
        self.doc.name = name
        return self
    
    def with_description(self, description: str) -> 'ShieldDocumentationBuilder':
        """Set shield description."""
        self.doc.description = description
        return self
    
    def with_version(self, version: str) -> 'ShieldDocumentationBuilder':
        """Set shield version."""
        self.doc.version = version
        return self
    
    def with_author(self, author: str) -> 'ShieldDocumentationBuilder':
        """Set shield author."""
        self.doc.author = author
        return self
    
    def with_category(self, category: str) -> 'ShieldDocumentationBuilder':
        """Set shield category."""
        self.doc.category = category
        return self
    
    def with_tags(self, tags: List[str]) -> 'ShieldDocumentationBuilder':
        """Set shield tags."""
        self.doc.tags = tags
        return self
    
    def with_parameter(self, param: ParameterInfo) -> 'ShieldDocumentationBuilder':
        """Add parameter."""
        self.doc.parameters.append(param)
        return self
    
    def with_simple_parameter(self, name: str, type_: str, description: str, 
                            required: bool = True) -> 'ShieldDocumentationBuilder':
        """Add simple parameter."""
        param = ParameterInfo(
            name=name,
            type=type_,
            description=description,
            required=required
        )
        self.doc.parameters.append(param)
        return self
    
    def with_method(self, name: str, description: str, 
                   async_: bool = False) -> 'ShieldDocumentationBuilder':
        """Add method."""
        method = {
            "name": name,
            "signature": f"({name})",
            "description": description,
            "async": async_,
            "parameters": []
        }
        self.doc.methods.append(method)
        return self
    
    def with_dependency(self, dependency: str) -> 'ShieldDocumentationBuilder':
        """Add dependency."""
        self.doc.dependencies.append(dependency)
        return self
    
    def with_note(self, note: str) -> 'ShieldDocumentationBuilder':
        """Add note."""
        self.doc.notes.append(note)
        return self
    
    def with_warning(self, warning: str) -> 'ShieldDocumentationBuilder':
        """Add warning."""
        self.doc.warnings.append(warning)
        return self
    
    def build(self) -> ShieldDocumentation:
        """Build the documentation."""
        return self.doc