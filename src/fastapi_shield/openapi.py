from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from functools import wraps
from contextlib import contextmanager
from inspect import signature, Signature
from fastapi.routing import APIRoute
from fastapi_shield.shield import (
    IS_SHIELDED_ENDPOINT_KEY,
    gather_signature_params_across_wrapped_endpoints,
)
from fastapi.dependencies.utils import get_dependant
from fastapi.routing import compile_path
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

                @wraps(shielded_endpoint)
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
