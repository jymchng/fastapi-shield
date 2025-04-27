# Installation

FastAPI Shield is a Python library that can be installed using various package managers.

## Requirements

- Python 3.9 or higher
- FastAPI 0.68.0 or higher

## Using pip

The simplest way to install FastAPI Shield is using pip:

```bash
pip install fastapi-shield
```

## Using uv

[uv](https://github.com/astral-sh/uv) is a much faster alternative to pip:

```bash
uv add fastapi-shield
```

## Using Poetry

For projects using [Poetry](https://python-poetry.org/) for dependency management:

```bash
poetry add fastapi-shield
```

## Installing Development Version

To install the latest development version directly from GitHub:

```bash
pip install git+https://github.com/jymchng/fastapi-shield.git
```

## Verifying Installation

You can verify that FastAPI Shield is correctly installed by importing it in a Python shell:

```python
import fastapi_shield
print(fastapi_shield.__version__)
``` 