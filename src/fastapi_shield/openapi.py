"""OpenAPI schema generation utilities for FastAPI Shield.

This module provides functions to integrate FastAPI Shield with OpenAPI schema
generation, ensuring that shielded endpoints are properly documented in the
generated API documentation while maintaining the shield functionality.

The main challenge is that shields modify endpoint signatures, so special handling
is required to generate accurate OpenAPI schemas that reflect the original
endpoint parameters rather than the wrapped shield parameters.
"""

from contextlib import contextmanager
from functools import wraps
from inspect import Signature, signature
from typing import Callable, Optional, Union

from fastapi import FastAPI
from fastapi.dependencies.utils import get_dependant
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute

from starlette.routing import BaseRoute, compile_path

from fastapi_shield.shield import IS_SHIELDED_ENDPOINT_KEY
from fastapi_shield.typing import EndPointFunc
from fastapi_shield.utils import (
    get_body_field_from_dependant,
    merge_dedup_seq_params,
    rearrange_params,
)


@contextmanager
def switch_routes(app: FastAPI):
    """Context manager that temporarily switches shielded routes to their original signatures.

    This context manager temporarily modifies all shielded routes in a FastAPI app
    to use their original endpoint signatures instead of the shield-wrapped versions.
    This is necessary for accurate OpenAPI schema generation, as shields modify
    endpoint signatures in ways that shouldn't be reflected in the API documentation.

    The context manager:
    1. Identifies all shielded routes in the app
    2. Creates mock endpoints with the original, unwrapped signatures
    3. Temporarily replaces the shielded endpoints with the mock versions
    4. Yields the modified routes for schema generation
    5. Restores the original shielded endpoints when done

    Args:
        app: The FastAPI application instance to modify.

    Yields:
        list: The app's routes with temporarily switched endpoint signatures.

    Examples:
        >>> app = FastAPI()
        >>> # ... add shielded routes ...
        >>> with switch_routes(app) as routes:
        ...     # Generate OpenAPI schema using original signatures
        ...     schema = get_openapi(routes=routes, title="My API", version="1.0.0")

    Note:
        This function safely handles the temporary modification and guarantees
        that the original shielded endpoints are restored even if an exception
        occurs during schema generation.
    """
    shielded_endpoints = {}
    shielded_dependants = {}
    shielded_body_fields = {}

    route: Union[BaseRoute, APIRoute]
    try:
        # Switch all routes to their original endpoints
        for route in app.routes:
            if isinstance(route, APIRoute):
                shielded_endpoint = route.endpoint

                # okay to disable cell-var-from-loop from pylint
                # because we're not using the `shielded_endpoint`
                # in the closure `mocked_endpoint_signature`
                @wraps(shielded_endpoint)  # pylint: disable=cell-var-from-loop
                def mocked_endpoint_signature(*_, **__):
                    return ...

                mocked_signature = (
                    Signature(
                        rearrange_params(  # type:ignore[reportArgumentType]
                            merge_dedup_seq_params(
                                gather_signature_params_across_wrapped_endpoints(
                                    shielded_endpoint
                                )
                            )
                        )
                    )
                    if hasattr(shielded_endpoint, IS_SHIELDED_ENDPOINT_KEY)
                    else signature(shielded_endpoint)
                )
                mocked_endpoint_signature.__signature__ = mocked_signature  # type:ignore[attr-defined]
                shielded_dependant = route.dependant
                shielded_body_field = route.body_field

                shielded_endpoints[route.unique_id] = shielded_endpoint
                shielded_dependants[route.unique_id] = shielded_dependant
                shielded_body_fields[route.unique_id] = shielded_body_field

                original_endpoint = mocked_endpoint_signature
                original_dependant = get_dependant(
                    path=route.path, call=original_endpoint
                )
                _, path_format, _ = compile_path(route.path)
                original_body_field, _ = get_body_field_from_dependant(
                    original_dependant, path_format
                )

                route.endpoint = original_endpoint
                route.dependant = original_dependant
                route.body_field = original_body_field
        yield app.routes
    finally:
        # Restore the shielded endpoints
        for route in app.routes:
            if isinstance(route, APIRoute):
                route.endpoint = shielded_endpoints.get(
                    getattr(route, "unique_id", ""), route.endpoint
                )
                route.dependant = shielded_dependants.get(
                    getattr(route, "unique_id", ""),
                    hasattr(route, "dependant") and route.dependant or None,
                )
                route.body_field = shielded_body_fields.get(
                    getattr(route, "unique_id", ""),
                    hasattr(route, "body_field") and route.body_field or None,
                )


def patch_get_openapi(app: FastAPI):
    """Create a patched OpenAPI schema generator for FastAPI Shield compatibility.

    Returns a function that generates OpenAPI schemas while properly handling
    shielded endpoints. The patched function ensures that the generated schema
    reflects the original endpoint signatures rather than the shield-wrapped
    versions, providing accurate API documentation.

    The function caches the generated schema to avoid repeated computation,
    as schema generation can be expensive for large applications.

    Args:
        app: The FastAPI application instance to create a schema generator for.

    Returns:
        Callable: A function that generates the OpenAPI schema for the app.
                 The function signature matches fastapi.openapi.utils.get_openapi.

    Examples:
        >>> app = FastAPI()
        >>> # ... add shielded endpoints ...
        >>> patched_openapi = patch_get_openapi(app)
        >>> schema = patched_openapi()
        >>> print(schema["paths"])  # Shows original endpoint signatures

    Note:
        The returned function automatically handles the temporary route switching
        needed for accurate schema generation and caches the result for performance.
    """
    original_schema = app.openapi()

    @wraps(get_openapi)
    def patch_openapi():
        with switch_routes(app) as switched_routes:
            openapi_schema = get_openapi(
                routes=switched_routes,
                title=original_schema.get("title", app.title),
                version=original_schema.get("version", app.version),
                openapi_version=original_schema.get(
                    "openapi_version", app.openapi_version
                ),
                summary=original_schema.get("summary"),
                description=original_schema.get("description"),
                webhooks=original_schema.get("webhooks"),
                tags=original_schema.get("tags"),
                servers=original_schema.get("servers"),
                terms_of_service=original_schema.get("termsOfService"),
                contact=original_schema.get("contact"),
                license_info=original_schema.get("license"),
                separate_input_output_schemas=True,
            )
        app.openapi_schema = openapi_schema
        return openapi_schema

    return patch_openapi


def gather_signature_params_across_wrapped_endpoints(maybe_wrapped_fn: EndPointFunc):
    """Recursively gather signature parameters from wrapped endpoint functions.

    Traverses the chain of wrapped functions (created by decorators like shields)
    to collect all unique parameters from each function in the chain. This is
    necessary because shields and other decorators can modify function signatures,
    and we need to reconstruct the complete parameter list for OpenAPI schema
    generation.

    The function follows the __wrapped__ attribute chain, which is automatically
    set by `functools.wraps()` and similar decorators.

    Args:
        maybe_wrapped_fn: An endpoint function that may have been wrapped by
                         decorators (shields, dependency injectors, etc.).

    Yields:
        Parameter: inspect.Parameter objects from the function and all its
                  wrapped ancestors, in the order they're encountered.

    Examples:
        >>> @shield
        ... def auth_shield(request): pass
        ...
        >>> @auth_shield
        ... def endpoint(user_id: int, name: str): pass
        ...
        >>> params = list(gather_signature_params_across_wrapped_endpoints(endpoint))
        >>> [p.name for p in params]  # ['request', 'user_id', 'name', ...]

    Note:
        This function is recursive and will traverse the entire decorator chain.
        Duplicate parameters (same name) should be handled by the caller using
        functions like merge_dedup_seq_params().
    """
    yield from signature(maybe_wrapped_fn).parameters.values()
    if hasattr(maybe_wrapped_fn, "__wrapped__"):
        yield from gather_signature_params_across_wrapped_endpoints(
            maybe_wrapped_fn.__wrapped__  # type:ignore[reportFunctionMemberAccess]
        )


def patch_shields_for_openapi(
    endpoint: Optional[EndPointFunc] = None,
    /,
    activated_when: Union[Callable[[], bool], bool] = lambda: True,
):
    """Decorator to patch shielded endpoints for proper OpenAPI schema generation.

    This decorator can be applied to shielded endpoints to ensure they generate
    correct OpenAPI schemas. It reconstructs the endpoint's signature by gathering
    parameters from the entire decorator chain and properly arranging them according
    to Python's parameter ordering rules.

    The decorator can be conditionally activated, allowing you to enable/disable
    the patching based on runtime conditions (e.g., only in development mode).

    Args:
        endpoint: The endpoint function to patch. If None, returns a decorator
                 function that can be applied to an endpoint.
        activated_when: Condition for activating the patch. Can be:
                       - A boolean value (True/False)
                       - A callable that returns a boolean
                       Defaults to always True (always activated).

    Returns:
        EndPointFunc: The patched endpoint with corrected signature for OpenAPI,
                     or the original endpoint if not shielded or not activated.

    Examples:
        >>> # Basic usage
        >>> @patch_shields_for_openapi
        ... @shield
        ... def auth_shield(request): pass
        ...
        >>> @auth_shield
        ... def endpoint(user_id: int): pass

        >>> # Conditional activation
        >>> @patch_shields_for_openapi(activated_when=lambda: settings.DEBUG)
        ... @shield
        ... def debug_shield(request): pass

        >>> # As a decorator factory
        >>> patch_for_dev = patch_shields_for_openapi(activated_when=settings.DEBUG)
        >>> @patch_for_dev
        ... @shield
        ... def my_shield(request): pass

    Note:
        This decorator only affects endpoints that have been marked as shielded
        (have the `IS_SHIELDED_ENDPOINT_KEY` attribute). Non-shielded endpoints
        are returned unchanged.
    """
    if endpoint is None:
        return lambda endpoint: patch_shields_for_openapi(
            endpoint, activated_when=activated_when
        )
    if not getattr(endpoint, IS_SHIELDED_ENDPOINT_KEY, False) or not (
        activated_when() if callable(activated_when) else activated_when
    ):
        return endpoint
    signature_params = gather_signature_params_across_wrapped_endpoints(endpoint)
    endpoint.__signature__ = Signature(  # type:ignore[attr-defined]
        rearrange_params(  # type:ignore[reportArgumentType]
            merge_dedup_seq_params(
                signature_params,
            )
        )
    )
    return endpoint
