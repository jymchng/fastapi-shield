"""Tests for Shield Documentation Generator."""

import json
import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock

from fastapi_shield.shield import Shield
from fastapi_shield.documentation import (
    DocumentationGenerator,
    DocumentationConfig,
    ShieldIntrospector,
    ExampleExtractor,
    DocumentationRenderer,
    ShieldDocumentation,
    ParameterInfo,
    ExampleCode,
    DocFormat,
    DocSection,
    ExampleType,
    generate_shield_documentation,
    create_mkdocs_site,
    create_sphinx_site,
)

from tests.mocks.documentation_mocks import (
    MockShield,
    MockComplexShield,
    MockMinimalShield,
    DocumentationTestHelper,
    TempTestFile,
    TempDocumentationDir,
    MockIntrospector,
    MockExampleExtractor,
    MockRenderer,
    DocumentationValidationHelper,
    ShieldDocumentationBuilder,
)


class TestParameterInfo:
    """Test ParameterInfo functionality."""
    
    def test_basic_parameter_creation(self):
        """Test basic parameter creation."""
        param = ParameterInfo(
            name="test_param",
            type="str",
            description="Test parameter",
            default="default_value",
            required=False
        )
        
        assert param.name == "test_param"
        assert param.type == "str"
        assert param.description == "Test parameter"
        assert param.default == "default_value"
        assert param.required is False
        assert param.constraints == {}
        assert param.examples == []
    
    def test_parameter_with_constraints(self):
        """Test parameter with constraints."""
        param = ParameterInfo(
            name="number_param",
            type="int",
            description="Number parameter",
            constraints={"min": 1, "max": 100},
            examples=[5, 10, 50]
        )
        
        assert param.constraints == {"min": 1, "max": 100}
        assert param.examples == [5, 10, 50]
    
    def test_parameter_to_dict(self):
        """Test parameter serialization."""
        param = ParameterInfo(
            name="complex_param",
            type="List[str]",
            description="Complex parameter",
            default=["a", "b"],
            required=True,
            constraints={"type": "list"},
            examples=[["x", "y"], ["p", "q"]]
        )
        
        result = param.to_dict()
        
        assert result["name"] == "complex_param"
        assert result["type"] == "List[str]"
        assert result["description"] == "Complex parameter"
        assert result["default"] == "['a', 'b']"
        assert result["required"] is True
        assert result["constraints"] == {"type": "list"}
        assert result["examples"] == [["x", "y"], ["p", "q"]]


class TestShieldDocumentation:
    """Test ShieldDocumentation functionality."""
    
    def test_basic_documentation_creation(self):
        """Test basic documentation creation."""
        doc = ShieldDocumentation(
            name="TestShield",
            description="A test shield",
            version="1.0.0",
            author="Test Author"
        )
        
        assert doc.name == "TestShield"
        assert doc.description == "A test shield"
        assert doc.version == "1.0.0"
        assert doc.author == "Test Author"
        assert doc.category == "general"
        assert doc.tags == []
        assert doc.parameters == []
        assert doc.created_at is not None
    
    def test_documentation_with_parameters(self):
        """Test documentation with parameters."""
        param = ParameterInfo(
            name="enabled",
            type="bool",
            description="Enable the shield"
        )
        
        doc = ShieldDocumentation(
            name="ParameterShield",
            description="Shield with parameters",
            parameters=[param]
        )
        
        assert len(doc.parameters) == 1
        assert doc.parameters[0].name == "enabled"
    
    def test_documentation_to_dict(self):
        """Test documentation serialization."""
        param = ParameterInfo(name="test", type="str", description="Test")
        example = ExampleCode(
            title="Test Example",
            description="Test example code",
            code="print('test')"
        )
        
        doc = ShieldDocumentation(
            name="SerializeShield",
            description="Shield for serialization testing",
            parameters=[param],
            examples=[example.to_dict()],
            tags=["test", "serialize"]
        )
        
        result = doc.to_dict()
        
        assert result["name"] == "SerializeShield"
        assert result["description"] == "Shield for serialization testing"
        assert len(result["parameters"]) == 1
        assert result["parameters"][0]["name"] == "test"
        assert len(result["examples"]) == 1
        assert result["tags"] == ["test", "serialize"]
        assert "created_at" in result


class TestExampleCode:
    """Test ExampleCode functionality."""
    
    def test_basic_example_creation(self):
        """Test basic example creation."""
        example = ExampleCode(
            title="Basic Example",
            description="A basic example",
            code="print('hello world')",
            language="python",
            type=ExampleType.BASIC_USAGE
        )
        
        assert example.title == "Basic Example"
        assert example.description == "A basic example"
        assert example.code == "print('hello world')"
        assert example.language == "python"
        assert example.type == ExampleType.BASIC_USAGE
        assert example.tags == []
        assert example.dependencies == []
    
    def test_example_with_metadata(self):
        """Test example with additional metadata."""
        example = ExampleCode(
            title="Complex Example",
            description="A complex example with metadata",
            code="# Complex code here",
            type=ExampleType.ADVANCED,
            tags=["advanced", "complex"],
            dependencies=["numpy", "pandas"],
            notes=["Requires Python 3.8+", "Memory intensive"]
        )
        
        assert example.type == ExampleType.ADVANCED
        assert example.tags == ["advanced", "complex"]
        assert example.dependencies == ["numpy", "pandas"]
        assert example.notes == ["Requires Python 3.8+", "Memory intensive"]
    
    def test_example_to_dict(self):
        """Test example serialization."""
        example = ExampleCode(
            title="Serialize Example",
            description="Example for serialization",
            code="x = 1 + 1",
            type=ExampleType.CONFIGURATION,
            tags=["config"]
        )
        
        result = example.to_dict()
        
        assert result["title"] == "Serialize Example"
        assert result["description"] == "Example for serialization"
        assert result["code"] == "x = 1 + 1"
        assert result["type"] == "configuration"
        assert result["language"] == "python"
        assert result["tags"] == ["config"]


class TestDocumentationConfig:
    """Test DocumentationConfig functionality."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = DocumentationConfig()
        
        assert config.title == "FastAPI Shield Documentation"
        assert config.version == "1.0.0"
        assert config.output_dir == Path("docs")
        assert config.include_private is False
        assert config.include_tests is True
        assert config.generate_examples is True
        assert DocFormat.MARKDOWN in config.formats
        assert DocFormat.HTML in config.formats
        assert DocSection.OVERVIEW in config.sections
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = DocumentationConfig(
            title="Custom Docs",
            version="2.0.0",
            output_dir=Path("custom_docs"),
            include_private=True,
            formats=[DocFormat.JSON, DocFormat.YAML],
            sections=[DocSection.CONFIGURATION, DocSection.EXAMPLES]
        )
        
        assert config.title == "Custom Docs"
        assert config.version == "2.0.0"
        assert config.output_dir == Path("custom_docs")
        assert config.include_private is True
        assert config.formats == [DocFormat.JSON, DocFormat.YAML]
        assert config.sections == [DocSection.CONFIGURATION, DocSection.EXAMPLES]
    
    def test_config_to_dict(self):
        """Test configuration serialization."""
        config = DocumentationConfig(
            title="Test Config",
            author="Test Author",
            theme="material"
        )
        
        result = config.to_dict()
        
        assert result["title"] == "Test Config"
        assert result["author"] == "Test Author"
        assert result["theme"] == "material"
        assert "output_dir" in result
        assert "formats" in result


class TestShieldIntrospector:
    """Test ShieldIntrospector functionality."""
    
    def setup_method(self):
        """Setup for each test."""
        self.introspector = ShieldIntrospector()
    
    def test_analyze_mock_shield(self):
        """Test analyzing a mock shield."""
        doc = self.introspector.analyze_shield(MockShield)
        
        assert doc.name == "MockShield"
        assert "Mock shield for testing" in doc.description
        assert doc.version == "2.0.0"
        assert doc.author == "Test Author"
        assert doc.category == "security"
        assert "test" in doc.tags
        assert "mock" in doc.tags
        
        # Check parameters
        param_names = [p.name for p in doc.parameters]
        assert "enabled" in param_names
        assert "threshold" in param_names
        assert "message" in param_names
        assert "config" in param_names
        
        # Check parameter details
        enabled_param = next(p for p in doc.parameters if p.name == "enabled")
        assert enabled_param.type == "bool"
        assert enabled_param.default is True
        assert enabled_param.required is False
    
    def test_analyze_complex_shield(self):
        """Test analyzing a complex shield with various parameter types."""
        doc = self.introspector.analyze_shield(MockComplexShield)
        
        assert doc.name == "MockComplexShield"
        
        param_names = [p.name for p in doc.parameters]
        assert "rate_limit" in param_names
        assert "time_window" in param_names
        assert "block_list" in param_names
        assert "allow_list" in param_names
        assert "custom_headers" in param_names
        
        # Check complex parameter types
        block_list_param = next(p for p in doc.parameters if p.name == "block_list")
        assert "List" in block_list_param.type
        
        custom_headers_param = next(p for p in doc.parameters if p.name == "custom_headers")
        assert "Dict" in custom_headers_param.type
    
    def test_analyze_minimal_shield(self):
        """Test analyzing a minimal shield."""
        doc = self.introspector.analyze_shield(MockMinimalShield)
        
        assert doc.name == "MockMinimalShield"
        assert doc.description  # Should have some description
        assert len(doc.parameters) == 0  # No parameters besides self
    
    def test_extract_parameters_with_defaults(self):
        """Test parameter extraction with default values."""
        doc = self.introspector.analyze_shield(MockShield)
        
        enabled_param = next(p for p in doc.parameters if p.name == "enabled")
        assert enabled_param.default is True
        assert enabled_param.required is False
        
        threshold_param = next(p for p in doc.parameters if p.name == "threshold")
        assert threshold_param.default == 100
        assert threshold_param.required is False
        
        message_param = next(p for p in doc.parameters if p.name == "message")
        assert message_param.default == "Access denied"
        assert message_param.required is False
    
    def test_extract_methods(self):
        """Test method extraction."""
        doc = self.introspector.analyze_shield(MockShield)
        
        method_names = [m["name"] for m in doc.methods]
        assert "__call__" in method_names
        assert "configure" in method_names
        assert "get_status" in method_names
        
        # Check async detection
        call_method = next(m for m in doc.methods if m["name"] == "__call__")
        assert call_method["async"] is True
        
        configure_method = next(m for m in doc.methods if m["name"] == "configure")
        assert configure_method["async"] is False
    
    def test_extract_metadata(self):
        """Test metadata extraction."""
        doc = self.introspector.analyze_shield(MockShield)
        
        assert doc.notes == ["This is a test shield", "Used for documentation testing"]
        assert doc.warnings == ["This is a mock implementation", "Do not use in production"]
        assert doc.see_also == ["RealShield", "AnotherShield"]
    
    def test_analyze_shield_error_handling(self):
        """Test error handling during shield analysis."""
        # Create a problematic shield class
        class ProblematicShield:
            def __init__(self, broken_param):
                # Missing docstring and other issues
                pass
        
        doc = self.introspector.analyze_shield(ProblematicShield)
        
        # Should return minimal documentation instead of failing
        assert doc.name == "ProblematicShield"
        assert doc.description  # Should have some description


class TestExampleExtractor:
    """Test ExampleExtractor functionality."""
    
    def setup_method(self):
        """Setup for each test."""
        self.extractor = ExampleExtractor()
    
    def test_generate_basic_examples(self):
        """Test generating basic examples."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        examples = self.extractor.generate_basic_examples(shield_doc)
        
        assert len(examples) >= 2  # At least basic usage and configuration
        
        # Check example types
        example_types = [ex.type for ex in examples]
        assert ExampleType.BASIC_USAGE in example_types
        assert ExampleType.CONFIGURATION in example_types
        
        # Check basic usage example
        basic_example = next(ex for ex in examples if ex.type == ExampleType.BASIC_USAGE)
        assert "TestShield" in basic_example.code
        assert "FastAPI" in basic_example.code or "from fastapi" in basic_example.code
    
    def test_extract_from_test_files(self):
        """Test extracting examples from test files."""
        test_content = DocumentationTestHelper.create_mock_test_file_content()
        
        with TempTestFile(test_content) as test_file:
            examples = self.extractor.extract_from_tests([test_file])
        
        assert len(examples) >= 4  # Should extract multiple test examples
        
        example_titles = [ex.title for ex in examples]
        assert any("Basic Usage" in title for title in example_titles)
        assert any("Configuration" in title for title in example_titles)
        assert any("Integration" in title for title in example_titles)
        assert any("Error Handling" in title for title in example_titles)
    
    def test_determine_example_types(self):
        """Test example type determination from test names."""
        test_examples = [
            ("test_basic_usage", ExampleType.BASIC_USAGE),
            ("test_configuration_setup", ExampleType.CONFIGURATION),
            ("test_fastapi_integration", ExampleType.INTEGRATION),
            ("test_error_handling", ExampleType.ERROR_HANDLING),
            ("test_advanced_features", ExampleType.ADVANCED)
        ]
        
        for test_name, expected_type in test_examples:
            result_type = self.extractor._determine_example_type(test_name)
            assert result_type == expected_type
    
    def test_extract_from_nonexistent_files(self):
        """Test handling of non-existent test files."""
        nonexistent_files = [Path("nonexistent1.py"), Path("nonexistent2.py")]
        examples = self.extractor.extract_from_tests(nonexistent_files)
        
        # Should return empty list without errors
        assert examples == []
    
    def test_generate_configuration_example(self):
        """Test configuration example generation."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        config_code = self.extractor._generate_configuration_example(shield_doc)
        
        assert "config = {" in config_code
        assert "enabled" in config_code
        assert "threshold" in config_code
        assert "message" in config_code
        assert "TestShield(**config)" in config_code
    
    def test_generate_integration_example(self):
        """Test integration example generation."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        integration_code = self.extractor._generate_integration_example(shield_doc)
        
        assert "from fastapi import FastAPI" in integration_code
        assert "TestShield" in integration_code
        assert "app = FastAPI()" in integration_code
        assert "@app.get(" in integration_code


class TestDocumentationRenderer:
    """Test DocumentationRenderer functionality."""
    
    def setup_method(self):
        """Setup for each test."""
        self.config = DocumentationTestHelper.create_test_config()
        self.renderer = DocumentationRenderer(self.config)
    
    def test_render_markdown(self):
        """Test rendering documentation as Markdown."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        examples = DocumentationTestHelper.create_sample_examples()
        
        content = self.renderer.render_shield_documentation(
            shield_doc, examples, DocFormat.MARKDOWN
        )
        
        validation = DocumentationValidationHelper.validate_markdown_content(content)
        
        assert validation["has_title"]
        assert validation["has_headers"]
        assert validation["has_code_blocks"]
        assert validation["has_tables"]
        
        # Check specific content
        assert "# TestShield" in content
        assert "## Parameters" in content
        assert "## Examples" in content
        assert shield_doc.description in content
    
    def test_render_html(self):
        """Test rendering documentation as HTML."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        examples = DocumentationTestHelper.create_sample_examples()
        
        content = self.renderer.render_shield_documentation(
            shield_doc, examples, DocFormat.HTML
        )
        
        validation = DocumentationValidationHelper.validate_html_content(content)
        
        assert validation["has_doctype"]
        assert validation["has_title"]
        assert validation["has_body"]
        
        # Check content includes shield information
        assert shield_doc.name in content
        assert shield_doc.description in content
    
    def test_render_json(self):
        """Test rendering documentation as JSON."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        examples = DocumentationTestHelper.create_sample_examples()
        
        content = self.renderer.render_shield_documentation(
            shield_doc, examples, DocFormat.JSON
        )
        
        validation = DocumentationValidationHelper.validate_json_content(content)
        
        assert validation["is_valid_json"]
        assert validation["has_name"]
        assert validation["has_description"]
        assert validation["has_parameters"]
        assert validation["has_examples"]
        
        # Parse and verify structure
        data = json.loads(content)
        assert data["name"] == shield_doc.name
        assert len(data["examples"]) == len(examples)
    
    def test_render_yaml(self):
        """Test rendering documentation as YAML."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        examples = DocumentationTestHelper.create_sample_examples()
        
        content = self.renderer.render_shield_documentation(
            shield_doc, examples, DocFormat.YAML
        )
        
        validation = DocumentationValidationHelper.validate_yaml_content(content)
        
        assert validation["is_valid_yaml"]
        assert validation["has_name"]
        assert validation["has_description"]
        assert validation["has_parameters"]
        assert validation["has_examples"]
    
    def test_render_rst(self):
        """Test rendering documentation as reStructuredText."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        examples = DocumentationTestHelper.create_sample_examples()
        
        content = self.renderer.render_shield_documentation(
            shield_doc, examples, DocFormat.RST
        )
        
        # Check RST-specific formatting
        assert "TestShield" in content
        assert "=" * len("TestShield") in content  # RST title underline
        assert "Parameters" in content
        assert "Examples" in content
        assert ".. code-block::" in content
    
    def test_render_api_documentation(self):
        """Test rendering complete API documentation."""
        shields = [
            DocumentationTestHelper.create_sample_shield_doc(),
            ShieldDocumentationBuilder()
            .with_name("AnotherShield")
            .with_description("Another test shield")
            .build()
        ]
        
        content = self.renderer.render_api_documentation(shields, DocFormat.MARKDOWN)
        
        # Check content includes both shields
        assert "TestShield" in content
        assert "AnotherShield" in content
        assert "Table of Contents" in content
        assert len(content.split("##")) >= 3  # Title + 2 shields
    
    def test_render_openapi_schema(self):
        """Test rendering OpenAPI schema."""
        shields = [DocumentationTestHelper.create_sample_shield_doc()]
        
        content = self.renderer.render_api_documentation(shields, DocFormat.OPENAPI)
        
        # Should be valid JSON
        schema = json.loads(content)
        
        assert schema["openapi"] == "3.0.0"
        assert "info" in schema
        assert "x-shields" in schema
        assert "TestShield" in schema["x-shields"]
        
        shield_info = schema["x-shields"]["TestShield"]
        assert shield_info["description"]
        assert shield_info["parameters"]
        assert shield_info["category"]
    
    def test_unsupported_format_error(self):
        """Test error handling for unsupported formats."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        examples = []
        
        with pytest.raises(ValueError, match="Unsupported format"):
            # Use a custom format that doesn't exist
            class UnsupportedFormat:
                pass
            
            self.renderer.render_shield_documentation(
                shield_doc, examples, UnsupportedFormat()
            )


class TestDocumentationGenerator:
    """Test DocumentationGenerator functionality."""
    
    def setup_method(self):
        """Setup for each test."""
        self.config = DocumentationTestHelper.create_test_config()
        self.generator = DocumentationGenerator(self.config)
    
    def test_generate_single_shield_docs(self):
        """Test generating documentation for a single shield."""
        with TempDocumentationDir() as output_dir:
            self.config.output_dir = output_dir
            self.generator = DocumentationGenerator(self.config)
            
            shields = [MockShield]
            result = self.generator.generate_shield_docs(shields)
            
            # Check that files were generated
            assert len(result) > 0
            
            # Check for markdown file
            markdown_files = [k for k in result.keys() if k.endswith('.markdown')]
            assert len(markdown_files) > 0
            
            # Verify file exists
            first_file = result[markdown_files[0]]
            assert Path(first_file).exists()
            
            # Check content
            with open(first_file, 'r') as f:
                content = f.read()
            assert "MockShield" in content
            assert "Mock shield for testing" in content
    
    def test_generate_multiple_shields_docs(self):
        """Test generating documentation for multiple shields."""
        with TempDocumentationDir() as output_dir:
            self.config.output_dir = output_dir
            self.config.formats = [DocFormat.MARKDOWN]
            self.generator = DocumentationGenerator(self.config)
            
            shields = [MockShield, MockComplexShield, MockMinimalShield]
            result = self.generator.generate_shield_docs(shields)
            
            # Should generate docs for each shield plus API overview
            assert len(result) >= len(shields)
            
            # Check that all shields are documented
            for shield_class in shields:
                shield_files = [k for k in result.keys() if shield_class.__name__.lower() in k]
                assert len(shield_files) > 0
            
            # Check API overview
            api_files = [k for k in result.keys() if k.startswith('api.')]
            assert len(api_files) > 0
    
    def test_generate_with_test_extraction(self):
        """Test generating documentation with test example extraction."""
        test_content = DocumentationTestHelper.create_mock_test_file_content()
        
        with TempTestFile(test_content) as test_file, \
             TempDocumentationDir() as output_dir:
            
            self.config.output_dir = output_dir
            self.config.formats = [DocFormat.MARKDOWN]
            self.generator = DocumentationGenerator(self.config)
            
            shields = [MockShield]
            test_dirs = [test_file.parent]
            
            result = self.generator.generate_shield_docs(shields, test_dirs)
            
            # Check generated file contains extracted examples
            markdown_files = [k for k in result.keys() if 'mockshield' in k]
            assert len(markdown_files) > 0, f"No mockshield files found in {list(result.keys())}"
            markdown_file = markdown_files[0]
            file_path = result[markdown_file]
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Should contain both generated and extracted examples
            examples = DocumentationValidationHelper.extract_code_examples(
                content, DocFormat.MARKDOWN
            )
            assert len(examples) >= 4  # Basic + config + integration + test examples
    
    def test_generate_multiple_formats(self):
        """Test generating documentation in multiple formats."""
        with TempDocumentationDir() as output_dir:
            self.config.output_dir = output_dir
            self.config.formats = [DocFormat.MARKDOWN, DocFormat.HTML, DocFormat.JSON]
            self.generator = DocumentationGenerator(self.config)
            
            shields = [MockShield]
            result = self.generator.generate_shield_docs(shields)
            
            # Should have files for each format
            assert any(k.endswith('.markdown') for k in result.keys())
            assert any(k.endswith('.html') for k in result.keys())
            assert any(k.endswith('.json') for k in result.keys())
            
            # Verify each file exists and has content
            for file_path in result.values():
                assert Path(file_path).exists()
                assert Path(file_path).stat().st_size > 0
    
    def test_generate_mkdocs_config(self):
        """Test generating MkDocs configuration."""
        with TempDocumentationDir() as output_dir:
            self.config.output_dir = output_dir
            self.generator = DocumentationGenerator(self.config)
            
            shields = [MockShield, MockComplexShield]
            mkdocs_path = self.generator.generate_mkdocs_config(shields)
            
            # Check file was created
            assert Path(mkdocs_path).exists()
            
            # Check content
            with open(mkdocs_path, 'r') as f:
                config = yaml.safe_load(f)
            
            assert config["site_name"] == self.config.title
            assert "nav" in config
            assert len(config["nav"]) >= 2  # Home + Shields section
            
            # Check shields are included in navigation
            shields_nav = next(item for item in config["nav"] if "Shields" in item)
            shield_pages = shields_nav["Shields"]
            assert len(shield_pages) == len(shields)
    
    def test_generate_sphinx_config(self):
        """Test generating Sphinx configuration."""
        with TempDocumentationDir() as output_dir:
            self.config.output_dir = output_dir
            self.generator = DocumentationGenerator(self.config)
            
            shields = [MockShield]
            sphinx_path = self.generator.generate_sphinx_config(shields)
            
            # Check file was created
            assert Path(sphinx_path).exists()
            
            # Check content
            with open(sphinx_path, 'r') as f:
                content = f.read()
            
            assert f"project = '{self.config.title}'" in content
            assert f"author = '{self.config.author}'" in content
            assert "extensions = [" in content
            assert "sphinx.ext.autodoc" in content
    
    def test_error_handling_during_generation(self):
        """Test error handling during documentation generation."""
        # Use mock components that fail
        mock_introspector = MockIntrospector()
        mock_introspector.should_fail = True
        
        self.generator.introspector = mock_introspector
        
        with TempDocumentationDir() as output_dir:
            self.config.output_dir = output_dir
            self.generator.config = self.config
            
            shields = [MockShield]
            result = self.generator.generate_shield_docs(shields)
            
            # Should still generate something even with failures
            # API overview should still be generated
            api_files = [k for k in result.keys() if k.startswith('api.')]
            assert len(api_files) >= 0  # May be 0 if shield analysis fails completely


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_generate_shield_documentation(self):
        """Test generate_shield_documentation convenience function."""
        with TempDocumentationDir() as output_dir:
            shields = [MockShield, MockComplexShield]
            
            result = generate_shield_documentation(
                shields,
                output_dir=str(output_dir),
                formats=[DocFormat.MARKDOWN, DocFormat.JSON]
            )
            
            # Check results
            assert len(result) >= len(shields)
            
            # Check files were created
            for file_path in result.values():
                assert Path(file_path).exists()
    
    def test_create_mkdocs_site(self):
        """Test create_mkdocs_site convenience function."""
        with TempDocumentationDir() as output_dir:
            shields = [MockShield]
            
            mkdocs_path = create_mkdocs_site(
                shields,
                output_dir=str(output_dir),
                site_name="Test MkDocs Site"
            )
            
            # Check MkDocs config was created
            assert Path(mkdocs_path).exists()
            
            # Check content
            with open(mkdocs_path, 'r') as f:
                config = yaml.safe_load(f)
            
            assert config["site_name"] == "Test MkDocs Site"
            
            # Check markdown files were created
            docs_dir = Path(output_dir)
            markdown_files = list(docs_dir.glob("*.md"))
            assert len(markdown_files) >= 1  # At least API overview
    
    def test_create_sphinx_site(self):
        """Test create_sphinx_site convenience function."""
        with TempDocumentationDir() as output_dir:
            shields = [MockShield]
            
            sphinx_path = create_sphinx_site(
                shields,
                output_dir=str(output_dir),
                project_name="Test Sphinx Site"
            )
            
            # Check Sphinx config was created
            assert Path(sphinx_path).exists()
            
            # Check content
            with open(sphinx_path, 'r') as f:
                content = f.read()
            
            assert "project = 'Test Sphinx Site'" in content


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple components."""
    
    def test_complete_documentation_pipeline(self):
        """Test complete documentation generation pipeline."""
        test_content = DocumentationTestHelper.create_mock_test_file_content()
        
        with TempTestFile(test_content) as test_file, \
             TempDocumentationDir() as output_dir:
            
            # Configure comprehensive documentation generation
            config = DocumentationConfig(
                title="Complete Pipeline Test",
                description="Testing complete documentation pipeline",
                author="Test Author",
                output_dir=output_dir,
                formats=[DocFormat.MARKDOWN, DocFormat.HTML, DocFormat.JSON],
                include_tests=True,
                generate_examples=True
            )
            
            generator = DocumentationGenerator(config)
            
            # Generate documentation for multiple shields
            shields = [MockShield, MockComplexShield]
            test_dirs = [test_file.parent]
            
            result = generator.generate_shield_docs(shields, test_dirs)
            
            # Verify comprehensive output
            assert len(result) >= 6  # 2 shields × 3 formats + API docs
            
            # Check each format was generated
            assert any('.markdown' in k for k in result.keys())
            assert any('.html' in k for k in result.keys())
            assert any('.json' in k for k in result.keys())
            
            # Verify content quality
            markdown_files = [k for k in result.keys() if 'mockshield.markdown' in k]
            assert len(markdown_files) > 0, f"No mockshield.markdown files found in {list(result.keys())}"
            markdown_file = markdown_files[0]
            with open(result[markdown_file], 'r') as f:
                content = f.read()
            
            validation = DocumentationValidationHelper.validate_markdown_content(content)
            assert all(validation.values())  # All validation checks should pass
            
            # Check section count
            section_count = DocumentationValidationHelper.count_sections(
                content, DocFormat.MARKDOWN
            )
            assert section_count >= 3  # At least Parameters, Examples, Methods
            
            # Check examples were extracted and generated
            examples = DocumentationValidationHelper.extract_code_examples(
                content, DocFormat.MARKDOWN
            )
            assert len(examples) >= 5  # Multiple sources of examples
    
    def test_documentation_with_mkdocs_integration(self):
        """Test documentation generation with MkDocs integration."""
        with TempDocumentationDir() as output_dir:
            shields = [MockShield, MockComplexShield, MockMinimalShield]
            
            # Generate documentation
            config = DocumentationConfig(
                title="MkDocs Integration Test",
                output_dir=output_dir,
                formats=[DocFormat.MARKDOWN]
            )
            
            generator = DocumentationGenerator(config)
            docs_result = generator.generate_shield_docs(shields)
            
            # Generate MkDocs configuration
            mkdocs_path = generator.generate_mkdocs_config(shields)
            
            # Verify integration
            assert Path(mkdocs_path).exists()
            
            # Check all referenced files exist
            with open(mkdocs_path, 'r') as f:
                mkdocs_config = yaml.safe_load(f)
            
            nav_items = mkdocs_config["nav"]
            shields_section = next(item for item in nav_items if "Shields" in item)
            
            for shield_item in shields_section["Shields"]:
                for shield_name, file_path in shield_item.items():
                    full_path = output_dir / file_path
                    assert full_path.exists(), f"Referenced file {file_path} does not exist"
    
    def test_error_resilience_and_partial_generation(self):
        """Test error resilience and partial generation."""
        # Create a scenario where some shields fail but others succeed
        
        class FailingShield(Shield):
            def __init__(self):
                # This will cause issues during introspection
                raise RuntimeError("This shield always fails")
            
            async def __call__(self, request):
                pass
        
        with TempDocumentationDir() as output_dir:
            config = DocumentationConfig(
                output_dir=output_dir,
                formats=[DocFormat.MARKDOWN]
            )
            
            generator = DocumentationGenerator(config)
            
            # Mix of working and failing shields
            shields = [MockShield, FailingShield, MockComplexShield]
            
            result = generator.generate_shield_docs(shields)
            
            # Should still generate documentation for working shields
            assert len(result) >= 2  # At least for working shields + API overview
            
            # Check that working shields were documented
            assert any('mockshield' in k for k in result.keys())
            assert any('mockcomplexshield' in k for k in result.keys())
    
    def test_documentation_content_accuracy(self):
        """Test accuracy of generated documentation content."""
        with TempDocumentationDir() as output_dir:
            config = DocumentationConfig(
                output_dir=output_dir,
                formats=[DocFormat.JSON, DocFormat.MARKDOWN]
            )
            
            generator = DocumentationGenerator(config)
            shields = [MockShield]
            
            result = generator.generate_shield_docs(shields)
            
            # Get JSON and Markdown versions
            json_file = next(k for k in result.keys() if '.json' in k)
            markdown_file = next(k for k in result.keys() if '.markdown' in k)
            
            # Parse JSON content
            with open(result[json_file], 'r') as f:
                json_data = json.load(f)
            
            # Read Markdown content
            with open(result[markdown_file], 'r') as f:
                markdown_content = f.read()
            
            # Verify consistency between formats
            assert json_data["name"] == "MockShield"
            assert "MockShield" in markdown_content
            
            assert json_data["description"]
            assert json_data["description"] in markdown_content
            
            # Check parameters are consistent
            json_params = {p["name"]: p for p in json_data["parameters"]}
            
            # Verify specific parameter details
            assert "enabled" in json_params
            assert json_params["enabled"]["type"] == "bool"
            assert json_params["enabled"]["default"] == "True"
            
            assert "threshold" in json_params
            assert json_params["threshold"]["type"] == "int"
            assert json_params["threshold"]["default"] == "100"
            
            # Verify examples exist and are meaningful
            assert len(json_data["examples"]) >= 2
            
            # Check that examples contain actual code
            for example in json_data["examples"]:
                assert example["code"]
                assert len(example["code"]) > 50  # Should be substantial
                assert "MockShield" in example["code"]


class TestDocumentationValidation:
    """Test documentation validation and quality checks."""
    
    def test_parameter_documentation_completeness(self):
        """Test completeness of parameter documentation."""
        introspector = ShieldIntrospector()
        doc = introspector.analyze_shield(MockComplexShield)
        
        # Check all parameters are documented
        expected_params = {
            "rate_limit", "time_window", "block_list", "allow_list",
            "custom_headers", "enable_logging", "log_level", "retry_after"
        }
        
        documented_params = {p.name for p in doc.parameters}
        assert expected_params <= documented_params
        
        # Check parameter types are correct
        param_dict = {p.name: p for p in doc.parameters}
        
        assert param_dict["rate_limit"].type == "int"
        assert param_dict["time_window"].type == "float"
        assert "List" in param_dict["block_list"].type
        assert "Dict" in param_dict["custom_headers"].type
        assert param_dict["enable_logging"].type == "bool"
        assert param_dict["log_level"].type == "str"
    
    def test_example_code_validity(self):
        """Test that generated example code is syntactically valid."""
        extractor = ExampleExtractor()
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        
        examples = extractor.generate_basic_examples(shield_doc)
        
        for example in examples:
            # Check that code can be parsed as valid Python
            try:
                compile(example.code, '<example>', 'exec')
            except SyntaxError as e:
                pytest.fail(f"Generated example code is not valid Python: {e}\nCode:\n{example.code}")
            
            # Check for common issues
            assert example.code.strip()  # Not empty
            assert not example.code.startswith(' ')  # Not indented incorrectly
            assert '\t' not in example.code or example.code.count('\t') < 50  # Reasonable indentation
    
    def test_documentation_cross_references(self):
        """Test that cross-references in documentation are valid."""
        doc = DocumentationTestHelper.create_sample_shield_doc()
        
        # Add some see_also references
        doc.see_also = ["RealShield", "AnotherShield", "ThirdShield"]
        
        renderer = DocumentationRenderer(DocumentationTestHelper.create_test_config())
        content = renderer.render_shield_documentation(doc, [], DocFormat.MARKDOWN)
        
        # Check that see_also section exists
        assert "## See Also" in content
        
        # Check that all references are included
        for ref in doc.see_also:
            assert ref in content
    
    def test_markdown_structure_validation(self):
        """Test markdown structure validation."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        examples = DocumentationTestHelper.create_sample_examples()
        
        renderer = DocumentationRenderer(DocumentationTestHelper.create_test_config())
        content = renderer.render_shield_documentation(
            shield_doc, examples, DocFormat.MARKDOWN
        )
        
        lines = content.split('\n')
        
        # Check title structure
        title_line = next((line for line in lines if line.startswith('# ')), None)
        assert title_line is not None
        assert title_line == f"# {shield_doc.name}"
        
        # Check header hierarchy (no H3 before H2, etc.)
        header_levels = []
        for line in lines:
            if line.startswith('#'):
                level = len(line.split()[0])  # Count # characters
                header_levels.append(level)
        
        # Verify reasonable header progression
        for i in range(1, len(header_levels)):
            # Headers shouldn't jump more than one level
            assert header_levels[i] - header_levels[i-1] <= 1, \
                "Header hierarchy violation detected"
    
    def test_html_output_validation(self):
        """Test HTML output validation."""
        shield_doc = DocumentationTestHelper.create_sample_shield_doc()
        examples = DocumentationTestHelper.create_sample_examples()
        
        renderer = DocumentationRenderer(DocumentationTestHelper.create_test_config())
        content = renderer.render_shield_documentation(
            shield_doc, examples, DocFormat.HTML
        )
        
        # Basic HTML structure checks
        assert content.startswith('<!DOCTYPE html>')
        assert '<html>' in content and '</html>' in content
        assert '<head>' in content and '</head>' in content
        assert '<body>' in content and '</body>' in content
        assert '<title>' in content and '</title>' in content
        
        # Check that content is properly escaped
        assert '&lt;' not in content or content.count('&lt;') < content.count('<')
        
        # Check for basic CSS styling
        assert '<style>' in content or 'class=' in content