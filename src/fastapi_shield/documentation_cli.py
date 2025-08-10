"""Command Line Interface for FastAPI Shield Documentation Generator.

This module provides command-line tools for generating, validating, and managing
shield documentation. It includes features for batch processing, continuous
integration, and automated documentation workflows.
"""

import argparse
import asyncio
import json
import logging
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type
import warnings

try:
    import click
    import rich
    from rich.console import Console
    from rich.progress import Progress, TaskID
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

from fastapi_shield.shield import Shield
from fastapi_shield.documentation import (
    DocumentationGenerator,
    DocumentationConfig,
    DocFormat,
    ShieldDocumentation,
    generate_shield_documentation,
    create_mkdocs_site,
    create_sphinx_site
)


class DocumentationCLI:
    """Command line interface for shield documentation generation."""
    
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.logger = self._setup_logging()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for CLI operations."""
        logger = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger
    
    def _print(self, message: str, style: str = None):
        """Print message with optional styling."""
        if self.console and RICH_AVAILABLE:
            self.console.print(message, style=style)
        else:
            print(message)
    
    def _print_error(self, message: str):
        """Print error message."""
        self._print(f"❌ {message}", "bold red")
    
    def _print_success(self, message: str):
        """Print success message."""
        self._print(f"✅ {message}", "bold green")
    
    def _print_warning(self, message: str):
        """Print warning message."""
        self._print(f"⚠️  {message}", "bold yellow")
    
    def _print_info(self, message: str):
        """Print info message."""
        self._print(f"ℹ️  {message}", "bold blue")
    
    def discover_shields(self, search_paths: List[str]) -> List[Type[Shield]]:
        """Discover shield classes in the given paths."""
        self._print_info(f"Discovering shields in {len(search_paths)} paths...")
        
        shield_classes = []
        for path_str in search_paths:
            path = Path(path_str)
            if not path.exists():
                self._print_warning(f"Path does not exist: {path}")
                continue
            
            # Import modules and discover shields
            if path.is_file() and path.suffix == '.py':
                shields_in_file = self._discover_shields_in_file(path)
                shield_classes.extend(shields_in_file)
            elif path.is_dir():
                shields_in_dir = self._discover_shields_in_directory(path)
                shield_classes.extend(shields_in_dir)
        
        self._print_success(f"Found {len(shield_classes)} shield classes")
        return shield_classes
    
    def _discover_shields_in_file(self, file_path: Path) -> List[Type[Shield]]:
        """Discover shield classes in a single file."""
        shields = []
        try:
            # Import the module dynamically
            import importlib.util
            spec = importlib.util.spec_from_file_location("shield_module", file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find shield classes
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, Shield) and 
                    attr != Shield):
                    shields.append(attr)
            
        except Exception as e:
            self._print_error(f"Failed to import {file_path}: {e}")
        
        return shields
    
    def _discover_shields_in_directory(self, dir_path: Path) -> List[Type[Shield]]:
        """Discover shield classes in a directory."""
        shields = []
        for py_file in dir_path.rglob("*.py"):
            if py_file.name.startswith("__"):
                continue
            
            file_shields = self._discover_shields_in_file(py_file)
            shields.extend(file_shields)
        
        return shields
    
    def generate_documentation(
        self,
        shield_classes: List[Type[Shield]],
        output_dir: str,
        formats: List[str],
        config_file: Optional[str] = None,
        include_tests: bool = True,
        validate: bool = True
    ) -> Dict[str, str]:
        """Generate documentation for shield classes."""
        
        if not shield_classes:
            self._print_error("No shield classes provided")
            return {}
        
        self._print_info(f"Generating documentation for {len(shield_classes)} shields")
        
        # Load configuration
        config = self._load_config(config_file, output_dir, formats)
        
        # Create generator
        generator = DocumentationGenerator(config)
        
        # Find test directories
        test_dirs = []
        if include_tests:
            test_dirs = self._find_test_directories()
        
        # Generate documentation
        try:
            with Progress() if RICH_AVAILABLE else nullcontext():
                generated_docs = generator.generate_shield_docs(shield_classes, test_dirs)
            
            # Validate if requested
            if validate:
                self.validate_documentation(generated_docs)
            
            self._print_success(f"Generated {len(generated_docs)} documentation files")
            
            if self.console and RICH_AVAILABLE:
                table = Table(title="Generated Documentation")
                table.add_column("File", style="cyan")
                table.add_column("Path", style="green")
                
                for filename, filepath in generated_docs.items():
                    table.add_row(filename, filepath)
                
                self.console.print(table)
            
            return generated_docs
            
        except Exception as e:
            self._print_error(f"Documentation generation failed: {e}")
            self.logger.error(traceback.format_exc())
            return {}
    
    def _load_config(
        self, 
        config_file: Optional[str], 
        output_dir: str, 
        formats: List[str]
    ) -> DocumentationConfig:
        """Load documentation configuration."""
        
        # Parse formats
        doc_formats = []
        for fmt in formats:
            try:
                doc_formats.append(DocFormat(fmt.lower()))
            except ValueError:
                self._print_warning(f"Unknown format: {fmt}")
        
        if not doc_formats:
            doc_formats = [DocFormat.MARKDOWN]
        
        # Create base config
        config = DocumentationConfig(
            output_dir=Path(output_dir),
            formats=doc_formats
        )
        
        # Load from file if provided
        if config_file:
            config_path = Path(config_file)
            if config_path.exists():
                try:
                    import yaml
                    with open(config_path) as f:
                        file_config = yaml.safe_load(f)
                    
                    # Update config with file values
                    for key, value in file_config.items():
                        if hasattr(config, key):
                            setattr(config, key, value)
                    
                    self._print_info(f"Loaded configuration from {config_path}")
                    
                except Exception as e:
                    self._print_warning(f"Failed to load config file: {e}")
            else:
                self._print_warning(f"Config file not found: {config_path}")
        
        return config
    
    def _find_test_directories(self) -> List[Path]:
        """Find test directories."""
        test_dirs = []
        current_dir = Path.cwd()
        
        for test_dir_name in ["tests", "test", "testing"]:
            test_path = current_dir / test_dir_name
            if test_path.exists() and test_path.is_dir():
                test_dirs.append(test_path)
        
        return test_dirs
    
    def validate_documentation(self, generated_docs: Dict[str, str]):
        """Validate generated documentation."""
        self._print_info("Validating generated documentation...")
        
        validation_errors = []
        
        for filename, filepath in generated_docs.items():
            try:
                path = Path(filepath)
                if not path.exists():
                    validation_errors.append(f"File not found: {filepath}")
                    continue
                
                content = path.read_text(encoding='utf-8')
                
                # Basic validation checks
                if len(content.strip()) == 0:
                    validation_errors.append(f"Empty file: {filename}")
                
                # Format-specific validation
                if filename.endswith('.json'):
                    try:
                        json.loads(content)
                    except json.JSONDecodeError as e:
                        validation_errors.append(f"Invalid JSON in {filename}: {e}")
                
                elif filename.endswith('.yaml') or filename.endswith('.yml'):
                    try:
                        import yaml
                        yaml.safe_load(content)
                    except yaml.YAMLError as e:
                        validation_errors.append(f"Invalid YAML in {filename}: {e}")
                
                elif filename.endswith('.md'):
                    # Basic markdown validation
                    if '# ' not in content:
                        validation_errors.append(f"No headers found in {filename}")
                
            except Exception as e:
                validation_errors.append(f"Validation error for {filename}: {e}")
        
        if validation_errors:
            self._print_error(f"Found {len(validation_errors)} validation errors:")
            for error in validation_errors:
                self._print_error(f"  - {error}")
        else:
            self._print_success("All documentation files validated successfully")
    
    def create_site(
        self,
        shield_classes: List[Type[Shield]],
        site_type: str,
        output_dir: str,
        site_name: str
    ) -> str:
        """Create a documentation site."""
        
        self._print_info(f"Creating {site_type} site with {len(shield_classes)} shields")
        
        try:
            if site_type.lower() == 'mkdocs':
                config_path = create_mkdocs_site(
                    shield_classes=shield_classes,
                    output_dir=output_dir,
                    site_name=site_name
                )
            elif site_type.lower() == 'sphinx':
                config_path = create_sphinx_site(
                    shield_classes=shield_classes,
                    output_dir=output_dir,
                    project_name=site_name
                )
            else:
                raise ValueError(f"Unknown site type: {site_type}")
            
            self._print_success(f"Created {site_type} site configuration: {config_path}")
            return config_path
            
        except Exception as e:
            self._print_error(f"Failed to create {site_type} site: {e}")
            return ""
    
    def generate_config_template(self, output_path: str):
        """Generate a configuration template file."""
        
        template_config = {
            "title": "Shield Documentation",
            "description": "Comprehensive documentation for FastAPI Shield",
            "author": "Development Team",
            "version": "1.0.0",
            "output_dir": "docs",
            "formats": ["markdown", "html"],
            "theme": "material",
            "include_tests": True,
            "include_examples": True,
            "include_openapi": True,
            "generate_toc": True,
            "custom_css": "",
            "custom_js": "",
            "logo": "",
            "favicon": ""
        }
        
        try:
            with open(output_path, 'w') as f:
                import yaml
                yaml.dump(template_config, f, default_flow_style=False, sort_keys=False)
            
            self._print_success(f"Generated configuration template: {output_path}")
            
        except Exception as e:
            self._print_error(f"Failed to generate config template: {e}")
    
    def list_shields(self, search_paths: List[str]):
        """List discovered shields."""
        
        shield_classes = self.discover_shields(search_paths)
        
        if not shield_classes:
            self._print_warning("No shields found")
            return
        
        if self.console and RICH_AVAILABLE:
            table = Table(title="Discovered Shields")
            table.add_column("Shield Class", style="cyan")
            table.add_column("Module", style="green")
            table.add_column("Description", style="blue")
            
            for shield_class in shield_classes:
                description = shield_class.__doc__ or "No description"
                if len(description) > 50:
                    description = description[:47] + "..."
                
                table.add_row(
                    shield_class.__name__,
                    shield_class.__module__,
                    description
                )
            
            self.console.print(table)
        else:
            self._print_info("Discovered Shields:")
            for shield_class in shield_classes:
                print(f"  - {shield_class.__name__} ({shield_class.__module__})")


def nullcontext():
    """Null context manager for Python < 3.7 compatibility."""
    yield


# CLI Commands

def create_cli():
    """Create the command line interface."""
    
    cli = DocumentationCLI()
    
    parser = argparse.ArgumentParser(
        description="FastAPI Shield Documentation Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate documentation for shields in current directory
  shield-docs generate . --output docs/
  
  # Create MkDocs site
  shield-docs site mkdocs . --name "My Shield Docs" --output docs/
  
  # List available shields
  shield-docs list src/
  
  # Generate config template
  shield-docs config --output shield-docs.yml
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate documentation')
    gen_parser.add_argument(
        'paths', nargs='+', help='Paths to search for shields'
    )
    gen_parser.add_argument(
        '--output', '-o', default='docs', help='Output directory'
    )
    gen_parser.add_argument(
        '--formats', '-f', nargs='+', default=['markdown'],
        choices=['markdown', 'html', 'rst', 'json', 'yaml', 'openapi'],
        help='Documentation formats to generate'
    )
    gen_parser.add_argument(
        '--config', '-c', help='Configuration file path'
    )
    gen_parser.add_argument(
        '--no-tests', action='store_true', help='Skip test directory scanning'
    )
    gen_parser.add_argument(
        '--no-validate', action='store_true', help='Skip validation'
    )
    gen_parser.add_argument(
        '--verbose', '-v', action='store_true', help='Verbose output'
    )
    
    # Site command
    site_parser = subparsers.add_parser('site', help='Create documentation site')
    site_parser.add_argument(
        'type', choices=['mkdocs', 'sphinx'], help='Site type to create'
    )
    site_parser.add_argument(
        'paths', nargs='+', help='Paths to search for shields'
    )
    site_parser.add_argument(
        '--output', '-o', default='docs', help='Output directory'
    )
    site_parser.add_argument(
        '--name', '-n', default='Shield Documentation', help='Site name'
    )
    
    # List command
    list_parser = subparsers.add_parser('list', help='List discovered shields')
    list_parser.add_argument(
        'paths', nargs='+', help='Paths to search for shields'
    )
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Generate config template')
    config_parser.add_argument(
        '--output', '-o', default='shield-docs.yml', help='Output file path'
    )
    
    return parser, cli


def main():
    """Main CLI entry point."""
    parser, cli = create_cli()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'generate':
            # Set logging level
            if hasattr(args, 'verbose') and args.verbose:
                cli.logger.setLevel(logging.DEBUG)
            
            # Discover shields
            shield_classes = cli.discover_shields(args.paths)
            
            if not shield_classes:
                cli._print_error("No shields found in the specified paths")
                sys.exit(1)
            
            # Generate documentation
            generated_docs = cli.generate_documentation(
                shield_classes=shield_classes,
                output_dir=args.output,
                formats=args.formats,
                config_file=getattr(args, 'config', None),
                include_tests=not getattr(args, 'no_tests', False),
                validate=not getattr(args, 'no_validate', False)
            )
            
            if not generated_docs:
                sys.exit(1)
        
        elif args.command == 'site':
            # Discover shields
            shield_classes = cli.discover_shields(args.paths)
            
            if not shield_classes:
                cli._print_error("No shields found in the specified paths")
                sys.exit(1)
            
            # Create site
            config_path = cli.create_site(
                shield_classes=shield_classes,
                site_type=args.type,
                output_dir=args.output,
                site_name=args.name
            )
            
            if not config_path:
                sys.exit(1)
        
        elif args.command == 'list':
            cli.list_shields(args.paths)
        
        elif args.command == 'config':
            cli.generate_config_template(args.output)
    
    except KeyboardInterrupt:
        cli._print_info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        cli._print_error(f"Unexpected error: {e}")
        cli.logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()