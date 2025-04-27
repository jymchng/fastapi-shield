# Building FastAPI Shield

This guide explains how to build, package, and distribute FastAPI Shield.

## Prerequisites

- Python 3.9 or higher
- pip, uv, or poetry
- Git
- Node.js (for documentation)
- twine (for publishing to PyPI)

## Building the Package

FastAPI Shield uses standard Python packaging tools for building. You can build the package using one of the following methods:

### Using pip

```bash
# Install build dependencies
pip install build twine

# Build the package
python -m build
```

### Using poetry

```bash
# Build the package
poetry build
```

This will create both source distribution (`.tar.gz`) and wheel (`.whl`) files in the `dist/` directory.

## Building Documentation

The documentation is built using MkDocs with the Material theme. To build the documentation:

```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Build the documentation
mkdocs build
```

This will create a `site/` directory containing the static HTML documentation.

## Local Development

For local development, you can install the package in development mode:

### Using pip

```bash
pip install -e ".[dev]"
```

### Using uv

```bash
uv pip install -e ".[dev]"
```

### Using poetry

```bash
poetry install --extras dev
```

## Running Tests

Before building a release, ensure all tests pass:

```bash
# Run all tests
nox

# Run specific test session
nox -s tests
```

## Versioning

FastAPI Shield follows [Semantic Versioning](https://semver.org/). Version numbers are in the format `MAJOR.MINOR.PATCH`:

- `MAJOR` version for incompatible API changes
- `MINOR` version for adding functionality in a backwards-compatible manner
- `PATCH` version for backwards-compatible bug fixes

The version number is defined in `src/fastapi_shield/__init__.py`.

## Creating a Release

To create a new release:

1. Update version number in `src/fastapi_shield/__init__.py`
2. Update changelog
3. Create a commit with the version change
4. Tag the commit with the version number
   ```bash
   git tag v0.1.0
   ```
5. Push the changes and tag
   ```bash
   git push origin main --tags
   ```
6. Build the package
   ```bash
   python -m build
   ```
7. Check the package
   ```bash
   twine check dist/*
   ```
8. Upload to PyPI (for maintainers)
   ```bash
   twine upload dist/*
   ```

## Continuous Integration

FastAPI Shield uses GitHub Actions for continuous integration. The workflows are defined in the `.github/workflows/` directory:

- `tests.yml` - Runs tests on multiple Python versions
- `lint.yml` - Runs linters and type checkers
- `release.yml` - Builds and publishes packages to PyPI on new tag

## Building with Nox

Nox is used to automate testing, linting, and other tasks in different Python environments. To run all Nox sessions:

```bash
nox
```

Available sessions:

- `tests`: Run pytest
- `lint`: Run linters
- `typecheck`: Run type checkers
- `docs`: Build documentation
- `coverage`: Generate coverage report

## Building Docker Images

If you need to build Docker images for FastAPI Shield, a sample Dockerfile is provided:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY dist/*.whl .
RUN pip install --no-cache-dir *.whl

# Clean up
RUN rm -rf *.whl

EXPOSE 8000

CMD ["uvicorn", "your_app:app", "--host", "0.0.0.0", "--port", "8000"]
```

To build the Docker image:

```bash
# Build the Python package first
python -m build

# Build the Docker image
docker build -t fastapi-shield:latest .
```

## Cross-Platform Compatibility

FastAPI Shield aims to be compatible with all platforms supported by Python 3.9+. When building, ensure compatibility with:

- Linux (various distributions)
- macOS (Intel and Apple Silicon)
- Windows

The continuous integration pipeline tests on multiple platforms to ensure cross-platform compatibility. 