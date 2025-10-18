"""Utility functions for FastAPI Shield dependency resolution and request processing.

This module provides core utility functions used throughout the FastAPI Shield library
for handling dependency injection, request body parsing, signature manipulation,
and other internal operations.
"""

import email.message
import json
import re
from collections.abc import Iterator
from contextlib import AsyncExitStack
from inspect import Parameter, signature
from typing import Any, Callable, Optional, List, Union

from fastapi import HTTPException, Request, params
from fastapi._compat import ModelField, Undefined
from fastapi.dependencies.models import Dependant
from fastapi.dependencies.utils import (
    _should_embed_body_fields,
    get_body_field,
    get_dependant,
    get_flat_dependant,
    solve_dependencies,
)
from fastapi.exceptions import RequestValidationError

from starlette.routing import get_name


def generate_unique_id_for_fastapi_shield(dependant: Dependant, path_format: str):
    """Generate a unique identifier for FastAPI Shield dependants.

    Creates a unique operation ID by combining the dependant's callable name
    with the path format, then sanitizing the result to ensure it's valid
    for use in OpenAPI schemas and internal operations.

    Args:
        dependant: The FastAPI Dependant object containing the callable.
        path_format: The raw path format string (e.g., "/users/{user_id}").

    Returns:
        str: A sanitized unique identifier string with non-word characters
             replaced by underscores.

    Examples:
        >>> dependant = Dependant(call=lambda: None)
        >>> dependant.call.__name__ = "get_user"
        >>> generate_unique_id_for_fastapi_shield(dependant, "/users/{user_id}")
        "get_user_users__user_id_"
    """
    name = get_name(dependant.call)
    operation_id = f"{name}{path_format}"
    operation_id = re.sub(r"\W", "_", operation_id)
    return operation_id


def get_body_field_from_dependant(
    dependant: Dependant, path_format: str
) -> tuple[Optional[ModelField], bool]:
    """Extract body field information from a FastAPI Dependant.

    Analyzes a FastAPI Dependant to determine the appropriate body field
    configuration and whether body fields should be embedded. This is used
    for proper request body parsing and validation.

    Args:
        dependant: The FastAPI Dependant object to analyze.
        path_format: The raw path format string for generating unique IDs.

    Returns:
        tuple[Optional[ModelField], bool]: A tuple containing:
            - The body field (ModelField) if one exists, None otherwise
            - Boolean indicating whether body fields should be embedded

    Examples:
        >>> dependant = get_dependant(path="/users", call=endpoint_func)
        >>> body_field, embed = get_body_field_from_dependant(dependant, "/users")
        >>> if body_field:
        ...     print(f"Body field type: {body_field.type_}")
    """
    flat_dependant = get_flat_dependant(dependant)
    embed_body_fields = _should_embed_body_fields(flat_dependant.body_params)
    body_field = get_body_field(
        flat_dependant=flat_dependant,
        name=generate_unique_id_for_fastapi_shield(dependant, path_format),
        embed_body_fields=embed_body_fields,
    )
    return body_field, embed_body_fields


async def get_body_from_request(  # pylint: disable=too-many-nested-blocks,too-many-branches
    request: Request, body_field: Optional[ModelField] = None
):
    """Extract and parse the request body based on content type and field configuration.

    Handles various content types including JSON, form data, and raw bytes.
    Properly manages file uploads and form closures to prevent resource leaks.
    Provides comprehensive error handling for malformed requests.

    Args:
        request: The FastAPI Request object to extract body from.
        body_field: Optional ModelField specifying expected body structure.
                   If None, no body parsing is performed.

    Returns:
        Any: The parsed request body. Type depends on content type:
            - dict/list for JSON content
            - FormData for form submissions
            - bytes for other content types
            - None if no body field specified

    Raises:
        RequestValidationError: If JSON parsing fails or body is malformed.
        HTTPException: If there's an error parsing the request body.

    Examples:
        >>> # JSON request
        >>> body = await get_body_from_request(request, json_body_field)
        >>> print(body)  # {'key': 'value'}

        >>> # Form request
        >>> body = await get_body_from_request(request, form_body_field)
        >>> print(body.get('field_name'))  # 'field_value'
    """
    body: Any = None
    is_body_form = body_field and isinstance(body_field.field_info, params.Form)
    async with AsyncExitStack() as file_stack:
        try:  # pylint: disable=too-many-nested-blocks
            if body_field:
                if is_body_form:
                    body = await request.form()
                    file_stack.push_async_callback(body.close)
                else:
                    body_bytes = await request.body()
                    if body_bytes:
                        json_body: Any = Undefined
                        content_type_value = request.headers.get("content-type")
                        if not content_type_value:
                            json_body = await request.json()
                        else:
                            message = email.message.Message()
                            message["content-type"] = content_type_value
                            if message.get_content_maintype() == "application":
                                subtype = message.get_content_subtype()
                                if subtype == "json" or subtype.endswith("+json"):
                                    json_body = await request.json()
                        if json_body != Undefined:
                            body = json_body
                        else:
                            body = body_bytes
        except json.JSONDecodeError as e:
            validation_error = RequestValidationError(
                [
                    {
                        "type": "json_invalid",
                        "loc": ("body", e.pos),
                        "msg": "JSON decode error",
                        "input": {},
                        "ctx": {"error": e.msg},
                    }
                ],
                body=e.doc,
            )
            raise validation_error from e
        except HTTPException:
            # If a middleware raises an HTTPException, it should be raised again
            raise
        except Exception as e:
            http_error = HTTPException(
                status_code=400, detail="There was an error parsing the body"
            )
            raise http_error from e
    return body


def get_path_format_from_request_for_endpoint(request: Request) -> str:
    """Extract the path format from a FastAPI request.

    Attempts to retrieve the raw path format (with parameter placeholders)
    from the request's route. Falls back to the actual URL path if the
    route doesn't have a `path_format` attribute.

    Args:
        request: The FastAPI `Request` object to extract path format from.

    Returns:
        str: The path format string (e.g., "/users/{user_id}") or the
             actual request path if format is unavailable.

    Examples:
        >>> # For a request to /users/123 with route pattern /users/{user_id}
        >>> path_format = get_path_format_from_request_for_endpoint(request)
        >>> print(path_format)  # "/users/{user_id}"

        >>> # For a request without route pattern
        >>> path_format = get_path_format_from_request_for_endpoint(request)
        >>> print(path_format)  # "/users/123"
    """
    scope = request.scope
    route = scope.get("route")
    path_format = getattr(route, "path_format", None)

    return path_format if path_format else request.url.path


async def get_solved_dependencies(
    request: Request,
    path_format: str,
    endpoint: Callable,
    dependency_cache: dict,
):
    """Resolve all dependencies for a FastAPI endpoint.

    Performs complete dependency resolution for an endpoint, including
    parsing the request body, resolving nested dependencies, and handling
    dependency caching. This is the core function used by shields to
    access resolved dependency values.

    Args:
        request: The FastAPI `Request` object containing request data.
        path_format: The raw path format string for the endpoint.
        endpoint: The endpoint callable to resolve dependencies for.
        dependency_cache: Dictionary for caching resolved dependencies
                         to avoid duplicate resolution.

    Returns:
        tuple: A tuple containing:
            - Solved dependencies object with resolved values and any errors
            - The parsed request body (if any)

    Raises:
        Various exceptions may be raised during dependency resolution,
        including validation errors, HTTP exceptions, etc.

    Examples:
        >>> solved_deps, body = await get_solved_dependencies(
        ...     request, "/users/{user_id}", endpoint_func, {}
        ... )
        >>> if not solved_deps.errors:
        ...     user_id = solved_deps.values.get("user_id")
        ...     print(f"Resolved user_id: {user_id}")
    """
    endpoint_dependant = get_dependant(path=path_format, call=endpoint)
    (
        body_field,
        should_embed_body_fields,
    ) = get_body_field_from_dependant(endpoint_dependant, path_format)
    body = await get_body_from_request(request, body_field)
    async with AsyncExitStack() as stack:
        endpoint_solved_dependencies = await solve_dependencies(
            request=request,
            dependant=endpoint_dependant,
            async_exit_stack=stack,
            embed_body_fields=should_embed_body_fields,
            body=body,
            dependency_cache=dependency_cache,
        )
    return endpoint_solved_dependencies, body


def merge_dedup_seq_params(
    *seqs_of_params: Iterator[Parameter],
):
    """Merge multiple iterator of Parameters while removing duplicates.

    Combines multiple iterator of `inspect.Parameter` objects, keeping only
    the first occurrence of each parameter name. This is used when merging
    parameters from wrapped functions to avoid duplicate parameters in
    the final signature.

    Args:
        *seqs_of_params: Variable number of `Parameter` iterator to merge.

    Yields:
        Parameter: Unique parameters in the order they first appear.

    Examples:
        >>> from inspect import Parameter
        >>> seq1 = [Parameter('a', Parameter.POSITIONAL_OR_KEYWORD)]
        >>> seq2 = [Parameter('b', Parameter.POSITIONAL_OR_KEYWORD)]
        >>> seq3 = [Parameter('a', Parameter.KEYWORD_ONLY)]  # duplicate 'a'
        >>> merged = list(merge_dedup_seq_params(seq1, seq2, seq3))
        >>> [p.name for p in merged]  # ['a', 'b'] - duplicate 'a' removed
    """
    seen = {}
    for seq_of_params in seqs_of_params:
        for param in seq_of_params:
            if param.name not in seen:
                seen[param.name] = param
                yield param


def prepend_request_to_signature_params_of_function(
    function: Callable,
):
    """Prepend a `Request` parameter to a function's signature parameters.

    Creates a new parameter sequence that starts with a positional-only
    `Request` parameter, followed by all the original function's parameters.
    This is used internally to ensure shield functions have access to the
    `Request` object.

    Args:
        function: The callable to prepend the Request parameter to.

    Yields:
        Parameter: The new Request parameter followed by original parameters.

    Examples:
        >>> def my_func(user_id: int, name: str): pass
        >>> params = list(prepend_request_to_signature_params_of_function(my_func))
        >>> [p.name for p in params]  # ['request', 'user_id', 'name']
        >>> params[0].annotation  # <class 'fastapi.Request'>
    """
    new_request_param: Parameter = Parameter(
        name="request",
        kind=Parameter.POSITIONAL_ONLY,
        annotation=Request,
        default=Parameter.empty,
    )
    new_signature = signature(function)
    yield from [new_request_param]
    yield from new_signature.parameters.values()


def rearrange_params(iter_params: Iterator[Parameter]):
    """Rearrange function parameters according to Python's parameter ordering rules.

    Sorts parameters to follow Python's required parameter order:
    1. POSITIONAL_ONLY parameters
    2. Required POSITIONAL_OR_KEYWORD parameters (no default)
    3. Optional POSITIONAL_OR_KEYWORD parameters (with default)
    4. VAR_POSITIONAL (*args)
    5. KEYWORD_ONLY parameters
    6. VAR_KEYWORD (**kwargs)

    This function is highly optimized using alternating buffers and minimal
    operations for performance when processing large parameter lists.

    Args:
        iter_params: Iterator of Parameter objects to rearrange.

    Yields:
        Parameter: Parameters in the correct order according to Python rules.

    Examples:
        >>> from inspect import Parameter, signature
        >>> def func(a, *args, b=1, c, **kwargs, d=2): pass
        >>> params = signature(func).parameters.values()
        >>> arranged = list(rearrange_params(iter(params)))
        >>> [p.name for p in arranged]  # ['a', 'c', 'd', 'b', 'args', 'kwargs']

    Note:
        This function handles the special case where POSITIONAL_OR_KEYWORD
        parameters are split into required and optional categories for
        proper ordering.
    """
    p: Parameter

    # Pre-compute constants
    POS_ONLY = Parameter.POSITIONAL_ONLY
    POS_KW = Parameter.POSITIONAL_OR_KEYWORD
    VAR_POS = Parameter.VAR_POSITIONAL
    KW_ONLY = Parameter.KEYWORD_ONLY
    VAR_KW = Parameter.VAR_KEYWORD
    EMPTY = Parameter.empty

    # Define kind order mapping
    ORDER = (
        POS_ONLY,  # 0: POSITIONAL_ONLY
        1,  # 1: required POSITIONAL_OR_KEYWORD (special handling)
        2,  # 2: optional POSITIONAL_OR_KEYWORD (special handling)
        VAR_POS,  # 3: VAR_POSITIONAL
        KW_ONLY,  # 4: KEYWORD_ONLY
        VAR_KW,  # 5: VAR_KEYWORD
    )

    kind_idx = 0
    now_kind = ORDER[kind_idx]

    # First pass: process params and create buffer1
    buffer1: List[Union[Parameter, None]] = []
    for p in iter_params:
        kind = p.kind
        if kind == POS_KW:
            # Special handling for POSITIONAL_OR_KEYWORD
            kind = 1 if p.default is EMPTY else 2  # type: ignore[assignment]

        if kind == now_kind:
            yield p
        else:
            buffer1.append(p)

    # Prepare buffer2 with exact size
    buffer2: List[Union[Parameter, None]] = [None] * len(buffer1)

    # Process remaining kinds
    while buffer1:
        kind_idx += 1
        if kind_idx >= len(ORDER):
            break
        now_kind = ORDER[kind_idx]

        # Process elements in buffer1 and fill buffer2
        buffer2_idx = 0
        for p in buffer1:  # type: ignore[assignment]
            kind = p.kind
            if kind == POS_KW:
                # Special handling for POSITIONAL_OR_KEYWORD
                kind = 1 if p.default is EMPTY else 2  # type: ignore[assignment]

            if kind == now_kind:
                yield p
            else:
                buffer2[buffer2_idx] = p
                buffer2_idx += 1

        # Truncate buffer2 to the number of valid elements
        buffer2 = buffer2[:buffer2_idx]

        # Truncate buffer1 to the valid elements before swapping
        buffer1 = buffer1[:buffer2_idx]

        # Swap buffers for next iteration
        buffer1, buffer2 = buffer2, buffer1
