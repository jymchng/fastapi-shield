# FastAPI Shield Architecture

This document explains the internal architecture of FastAPI Shield, helping developers understand how the library works and how to contribute effectively.

## Core Concepts

FastAPI Shield is built around several key concepts:

### Shields

Shields are the fundamental building blocks of FastAPI Shield's security model. A shield is a wrapper around a type that adds security and validation capabilities. Shields are implemented using Python's `NewType` to provide type safety while maintaining compatibility with dependency injection systems.

### Shield Factory

The Shield Factory pattern enables the creation of shields with specific configurations. It allows for conditional shield creation based on runtime factors and provides a unified interface for shield instantiation.

### Method Interception

Method interception is the mechanism that allows shields to intercept and modify requests, perform validation, and enforce security policies. It works by wrapping endpoint methods and adding pre- and post-processing hooks.

### Dependency Injection Integration

FastAPI Shield integrates with FastAPI's dependency injection system to provide seamless security enforcement. This integration is achieved through special dependency types like `ShieldedDepends` and `ShieldDepends`.

## Package Structure

FastAPI Shield is organized into the following modules:

```
src/fastapi_shield/
├── __init__.py           # Package exports and version
├── core/                 # Core functionality
│   ├── __init__.py
│   ├── shield.py         # Shield base class and factory
│   ├── depends.py        # Custom dependency types
│   └── types.py          # Type definitions
├── interceptors/         # Method interception logic
│   ├── __init__.py
│   ├── base.py           # Base interceptor class
│   └── handlers.py       # Interceptor handlers
├── validation/           # Validation utilities
│   ├── __init__.py
│   ├── string.py         # String validation
│   └── type_check.py     # Type checking utilities
└── utils/                # Utility functions
    ├── __init__.py
    └── helpers.py        # Helper functions
```

## Core Components

### Shield Class

The `Shield` class is the central component of the library. It:

1. Wraps a base type
2. Provides validation logic
3. Manages interceptor chains
4. Integrates with FastAPI's dependency injection

```python
class Shield(Generic[T]):
    """Base class for all shields."""
    
    def __init__(
        self, 
        base_type: Type[T],
        validators: List[Callable] = None,
        interceptors: List[Interceptor] = None
    ):
        self.base_type = base_type
        self.validators = validators or []
        self.interceptors = interceptors or []
    
    def __call__(self, value: Any) -> T:
        # Validate and transform input
        self._validate(value)
        return self._transform(value)
```

### ShieldedDepends

`ShieldedDepends` extends FastAPI's `Depends` to integrate shield validation with the dependency injection system:

```python
class ShieldedDepends(Depends):
    """A dependency that applies a shield to the resolved value."""
    
    def __init__(
        self,
        dependency: Callable,
        shield: Shield,
        use_cache: bool = True
    ):
        super().__init__(dependency, use_cache)
        self.shield = shield
    
    async def __call__(self, *args, **kwargs):
        # Resolve the dependency
        value = await super().__call__(*args, **kwargs)
        # Apply the shield
        return self.shield(value)
```

### Interceptors

Interceptors implement the method interception pattern:

```python
class Interceptor:
    """Base class for interceptors."""
    
    async def before(self, *args, **kwargs):
        """Run before the target method."""
        pass
    
    async def after(self, result, *args, **kwargs):
        """Run after the target method."""
        return result
    
    async def on_error(self, exception, *args, **kwargs):
        """Handle exceptions raised by the target method."""
        raise exception
```

## Request Flow

When a request comes into a FastAPI application using FastAPI Shield:

1. The HTTP request arrives at a FastAPI endpoint
2. Shield dependencies are resolved through FastAPI's dependency injection
3. Shield interceptors run their `before` hooks
4. Shield validators check input data
5. The endpoint logic executes
6. Shield interceptors run their `after` hooks
7. The response is returned to the client

## Type System

FastAPI Shield uses a sophisticated type system to provide type safety:

1. `NewType` to create shield types that are distinct at the type level
2. Generics to maintain type information across shields
3. Type hints to provide IDE support and static type checking

## Extension Points

FastAPI Shield is designed to be extensible:

1. Custom Shield types can be created by subclassing `Shield`
2. Custom interceptors can be implemented by subclassing `Interceptor`
3. Custom validators can be added to shields
4. The Shield Factory pattern allows for customized shield creation

## Integration with FastAPI

FastAPI Shield integrates with FastAPI:

1. Dependency Injection: `ShieldedDepends` and `ShieldDepends` extend FastAPI's dependency system
2. Type Validation: Shields can leverage Pydantic models for validation
3. Documentation: Shield type annotations appear in generated OpenAPI docs

## Performance Considerations

FastAPI Shield is designed for minimal overhead:

1. Lazy loading of interceptors and validators
2. Selective application of shields only where needed
3. Efficient type checking through Python's type system
4. Caching of validation results where appropriate

## Testing Architecture

FastAPI Shield's testing infrastructure:

1. Unit tests for each component
2. Integration tests for FastAPI integration
3. Performance benchmarks
4. Type checking tests to ensure type safety
5. Documentation tests to ensure examples work 