"""Constants used throughout the FastAPI Shield library.

This module defines key constants that are used internally by FastAPI Shield
to mark and identify shielded endpoints and store metadata about them.
These constants should not be modified by end users.
"""

IS_SHIELDED_ENDPOINT_KEY = "__shielded__"
"""Attribute key used to mark callables as shielded endpoints.

When a callable has this attribute set to True, it indicates that the callable
has been wrapped by one or more Shield decorators. This is used internally
to distinguish between regular FastAPI endpoints and shielded ones.

This attribute is checked during OpenAPI schema generation and other internal
operations to determine if special handling is needed for shielded endpoints.
"""

SHIELDED_ENDPOINT_KEY = "__shielded_endpoint__"
"""Attribute key used to store the original endpoint function.

When shields are applied to an endpoint, this key is used to store a reference
to the original, unshielded endpoint function. This allows the system to
access the original function when needed, even after multiple shields have
been applied in a decorator chain.

This is particularly useful for introspection and debugging purposes.
"""

SHIELDED_ENDPOINT_PATH_FORMAT_KEY = "__shielded_endpoint_path_format__"
"""Attribute key used to store the raw path format of shielded endpoints.

This constant defines the attribute name where the raw path format string
(e.g., "/users/{user_id}") is stored for shielded endpoints. The path format
is used internally for dependency resolution and OpenAPI schema generation.

The path format is typically extracted from the FastAPI route definition
and cached on the endpoint function to avoid repeated lookups during
request processing.
"""
