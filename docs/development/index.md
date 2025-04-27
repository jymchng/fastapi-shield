# Development Guide

Welcome to the FastAPI Shield development guide. This section contains information for developers who want to contribute to FastAPI Shield or build upon it.

## Getting Started with Development

If you're new to FastAPI Shield development, start with these guides:

- [Contributing](contributing.md) - How to contribute to the project
- [Building](building.md) - How to build and package FastAPI Shield
- [Testing](testing.md) - How to write and run tests

## Understanding the Architecture

To understand how FastAPI Shield works internally:

- [Architecture](architecture.md) - The internal architecture of FastAPI Shield

## Project Vision

To understand where the project is headed:

- [Roadmap](roadmap.md) - The future development plans for FastAPI Shield

## Development Environment Setup

### Prerequisites

- Python 3.9 or higher
- pip, uv, or poetry
- Git

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/your-username/fastapi-shield.git
cd fastapi-shield

# Set up a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```

### IDE Configuration

#### VS Code

We recommend using VS Code with the following extensions:

- Python
- Pylance
- Python Type Hint
- Python Test Explorer
- Python Docstring Generator

Create a `.vscode/settings.json` file with:

```json
{
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.linting.mypyEnabled": true,
    "python.testing.pytestEnabled": true,
    "python.formatting.provider": "black",
    "editor.formatOnSave": true,
    "python.sortImports.args": ["--profile", "black"]
}
```

#### PyCharm

If you're using PyCharm:

1. Open the project folder
2. Set up the Python interpreter (Settings → Project → Python Interpreter)
3. Enable type checking (Settings → Editor → Inspections → Python → Type checking)
4. Configure the formatting settings to use Black and isort

### Pre-commit Hooks

We use pre-commit hooks to ensure code quality. Install them with:

```bash
pre-commit install
```

This will automatically run linters and formatters before each commit.

## Development Workflow

Our typical development workflow is:

1. Create a new branch from `main`
2. Make your changes
3. Write tests for your changes
4. Run the tests locally
5. Push your branch and create a PR

### Running Tests

```bash
# Run all tests
pytest

# Run specific tests
pytest tests/unit/core

# Run with coverage
pytest --cov=fastapi_shield
```

### Building Documentation

```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Build the documentation
mkdocs build

# Serve the documentation locally
mkdocs serve
```

## Coding Standards

We follow these coding standards:

- **Code Style**: We use Black for code formatting and isort for import sorting
- **Type Hints**: All code should include proper type hints
- **Documentation**: All public APIs should have docstrings
- **Testing**: All code should have tests
- **Error Handling**: Use appropriate error handling and provide clear error messages

## Getting Help

If you need help with FastAPI Shield development:

- Open an issue on GitHub
- Join our community chat
- Check the existing documentation 