from contextlib import contextmanager
from functools import wraps
from inspect import Signature, signature
from typing import Callable, Optional, Union

from fastapi import FastAPI
from fastapi.dependencies.utils import get_dependant
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute, compile_path

from fastapi_shield.shield import IS_SHIELDED_ENDPOINT_KEY
from fastapi_shield.typing import EndPointFunc
from fastapi_shield.utils import (
    get_body_field_from_dependant,
    merge_dedup_seq_params,
    rearrange_params,
)


@contextmanager
def switch_routes(app: FastAPI):
    shielded_endpoints = {}
    shielded_dependants = {}
    shielded_body_fields = {}

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
                        rearrange_params(
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
                mocked_endpoint_signature.__signature__ = mocked_signature
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
            route: APIRoute
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
    original_schema = app.openapi()

    final_schema = None

    @wraps(get_openapi)
    def patch_openapi():
        nonlocal final_schema
        if final_schema is not None:
            return final_schema
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
            final_schema = openapi_schema
        app.openapi_schema = final_schema
        return app.openapi_schema

    return patch_openapi


def gather_signature_params_across_wrapped_endpoints(maybe_wrapped_fn: EndPointFunc):
    yield from signature(maybe_wrapped_fn).parameters.values()
    if hasattr(maybe_wrapped_fn, "__wrapped__"):
        yield from gather_signature_params_across_wrapped_endpoints(
            maybe_wrapped_fn.__wrapped__
        )


def patch_shields_for_openapi(
    endpoint: Optional[EndPointFunc] = None,
    /,
    activated_when: Union[Callable[[], bool], bool] = lambda: True,
):
    if endpoint is None:
        return lambda endpoint: patch_shields_for_openapi(
            endpoint, activated_when=activated_when
        )
    if not getattr(endpoint, IS_SHIELDED_ENDPOINT_KEY, False) or not (
        activated_when() if callable(activated_when) else activated_when
    ):
        return endpoint
    signature_params = gather_signature_params_across_wrapped_endpoints(endpoint)
    endpoint.__signature__ = Signature(
        rearrange_params(
            merge_dedup_seq_params(
                signature_params,
            )
        )
    )
    return endpoint
