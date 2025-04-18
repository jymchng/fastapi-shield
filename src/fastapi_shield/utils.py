from inspect import Parameter, signature
from typing import Iterator, Sequence

from fastapi_shield.typing import EndPointFunc
from fastapi import Request


def merge_dedup_seq_params(
    *seqs_of_params: Sequence[Parameter],
):
    seen = {}
    for seq_of_params in seqs_of_params:
        for param in seq_of_params:
            if param.name not in seen:
                seen[param.name] = param
                yield param


def prepend_request_to_signature_params_of_endpoint(
    endpoint: EndPointFunc,
):
    new_request_param: Parameter = Parameter(
        name="request",
        kind=Parameter.POSITIONAL_ONLY,
        annotation=Request,
        default=Parameter.empty,
    )
    new_signature = signature(endpoint)
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
