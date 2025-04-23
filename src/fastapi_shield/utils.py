import json
from fastapi import HTTPException, Request
from typing import Any, Callable, Optional
from fastapi.exceptions import RequestValidationError
from inspect import Parameter, signature
from fastapi.dependencies.models import Dependant
from fastapi.dependencies.utils import (
    _should_embed_body_fields,
    get_body_field,
    get_dependant,
    get_flat_dependant,
    solve_dependencies,
)
import re
from fastapi.routing import compile_path, get_name
from fastapi._compat import Undefined, ModelField
from contextlib import AsyncExitStack
from fastapi import params
import email.message
from typing import Sequence
from collections.abc import Iterator


def generate_unique_id_for_fastapi_shield(dependant: Dependant, path_format: str):
    name = get_name(dependant.call)
    operation_id = f"{name}{path_format}"
    operation_id = re.sub(r"\W", "_", operation_id)
    return operation_id


def get_body_field_from_dependant(
    dependant: Dependant, path_format: str
) -> tuple[Optional[ModelField], bool]:
    flat_dependant = get_flat_dependant(dependant)
    embed_body_fields = _should_embed_body_fields(flat_dependant.body_params)
    body_field = get_body_field(
        flat_dependant=flat_dependant,
        name=generate_unique_id_for_fastapi_shield(dependant, path_format),
        embed_body_fields=embed_body_fields,
    )
    return body_field, embed_body_fields


async def get_body_from_request(
    request: Request, body_field: Optional[ModelField] = None
):
    body: Any = None
    is_body_form = body_field and isinstance(body_field.field_info, params.Form)
    async with AsyncExitStack() as file_stack:
        try:
            body: Any = None
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


def get_raw_or_full_path(request: Request) -> str:
    scope = request.scope
    root_path = scope.get("root_path", "")

    route = scope.get("route")

    if not route:
        return request.url.path

    path_format = getattr(route, "path_format", None)

    if not path_format:
        return request.url.path

    if path_format:
        return f"{root_path}{path_format}"


async def get_solved_dependencies(
    request: Request,
    endpoint: Callable,
    dependency_cache: dict,
):
    full_or_raw_path = get_raw_or_full_path(request)
    _, path_format, _ = compile_path(full_or_raw_path)
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
    *seqs_of_params: Sequence[Parameter],
):
    seen = {}
    for seq_of_params in seqs_of_params:
        for param in seq_of_params:
            if param.name not in seen:
                seen[param.name] = param
                yield param


def prepend_request_to_signature_params_of_function(
    function: Callable,
):
    new_request_param: Parameter = Parameter(
        name="request",
        kind=Parameter.POSITIONAL_ONLY,
        annotation=Request,
        default=Parameter.empty,
    )
    new_signature = signature(function)
    yield from [new_request_param]
    yield from new_signature.parameters.values()


def rearrange_params(params: Iterator[Parameter]):
    """
    Perfectly optimized parameter rearrangement with:
    - Direct iterator consumption
    - Two alternating buffers with proper truncation
    - Minimal operations and comparisons
    - Early returns for improved performance

    Order: POSITIONAL_ONLY, required POSITIONAL_OR_KEYWORD, optional POSITIONAL_OR_KEYWORD,
           VAR_POSITIONAL, KEYWORD_ONLY, VAR_KEYWORD
    """
    # Pre-compute constants
    POS_ONLY = Parameter.POSITIONAL_ONLY
    POS_KW = Parameter.POSITIONAL_OR_KEYWORD
    VAR_POS = Parameter.VAR_POSITIONAL
    KW_ONLY = Parameter.KEYWORD_ONLY
    VAR_KW = Parameter.VAR_KEYWORD
    EMPTY = Parameter.empty

    # Convert params to an iterator to consume only once
    params = iter(params)

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
    buffer1 = []
    for p in params:
        kind = p.kind
        if kind == POS_KW:
            # Special handling for POSITIONAL_OR_KEYWORD
            kind = 1 if p.default is EMPTY else 2  # type: ignore[assignment]

        if kind == now_kind:
            yield p
        else:
            buffer1.append(p)

    # Prepare buffer2 with exact size
    buffer2 = [None] * len(buffer1)

    # Process remaining kinds
    while buffer1:
        kind_idx += 1
        if kind_idx >= len(ORDER):
            break
        now_kind = ORDER[kind_idx]

        # Process elements in buffer1 and fill buffer2
        buffer2_idx = 0
        for p in buffer1:
            kind = p.kind
            if kind == POS_KW:
                # Special handling for POSITIONAL_OR_KEYWORD
                kind = 1 if p.default is EMPTY else 2

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
