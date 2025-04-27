# Contributing

Thank you for considering contributing to FastAPI Shield! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and considerate of others.

## Prerequisites

- Python 3.9 or higher
- pip, uv, or poetry
- Git

## Setting Up Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally
   ```bash
   git clone https://github.com/yourusername/fastapi-shield.git
   cd fastapi-shield
   ```

3. Set up a virtual environment and install dependencies using one of the following methods:

   Using venv and pip:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

   Using uv:
   ```bash
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   uv pip install -e ".[dev]"
   ```

   Using poetry:
   ```bash
   poetry install
   ```

4. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Development Workflow

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature-or-bugfix-name
   ```

2. Make your changes, writing tests as needed

3. Run the tests:
   ```bash
   nox
   ```

   Or run a specific test session:
   ```bash
   nox -s tests
   ```

4. Make sure the code is properly formatted and linted:
   ```bash
   nox -s lint
   ```

5. Commit your changes following the [Conventional Commits](https://www.conventionalcommits.org/) specification:
   ```bash
   git commit -m "feat: add new feature"
   ```
   
   Some common prefixes include:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation changes
   - `test:` for changes to tests
   - `refactor:` for code refactoring

6. Push your branch:
   ```bash
   git push origin feature-or-bugfix-name
   ```

7. Create a Pull Request on GitHub

## Pull Request Guidelines

- All tests must pass before a PR can be merged
- Include tests for any new functionality
- Update documentation for any new features or API changes
- Keep changes focused and specific
- Ensure your code adheres to the project's style guidelines (enforced by pre-commit hooks)

## Setting Up Documentation

To build and test the documentation locally:

1. Install documentation dependencies:
   ```bash
   pip install -e ".[docs]"
   ```

2. Build and serve the documentation:
   ```bash
   mkdocs serve
   ```

3. Open http://127.0.0.1:8000 in your browser to view the documentation

## Code Style Guidelines

This project uses:

- [Ruff](https://github.com/charliermarsh/ruff) for linting and formatting
- [Black](https://github.com/psf/black) for code formatting
- [isort](https://github.com/PyCQA/isort) for import sorting
- [mypy](https://github.com/python/mypy) for static type checking

Pre-commit hooks are configured to enforce these standards automatically when you commit code.

## Testing Guidelines

- Write tests for all new functionality
- Use pytest for writing tests
- Aim for high test coverage
- Include both unit tests and integration tests
- Use meaningful test names that describe what's being tested

## Submitting Issues

When submitting an issue, please:

1. Check if the issue already exists
2. Include a clear title and description
3. Add steps to reproduce the issue
4. Include the version of FastAPI Shield, FastAPI, and Python you're using
5. Add any relevant code snippets or error messages

## Getting Help

If you have questions or need help, you can:

- Open an issue on GitHub
- Discussion forums (if available)
- Reach out to the maintainers directly

Thank you for contributing to FastAPI Shield! 