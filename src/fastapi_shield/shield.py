from contextlib import asynccontextmanager
from functools import cached_property, wraps
from inspect import Parameter, Signature, signature
from typing import Annotated, Any, Callable, Generic, Optional, Sequence, Tuple, Union

from fastapi import HTTPException, Request, Response, status
from fastapi._compat import _normalize_errors
from fastapi.dependencies.utils import is_coroutine_callable
from fastapi.exceptions import RequestValidationError
from fastapi.params import Security
from typing_extensions import Doc

from fastapi_shield.consts import IS_SHIELDED_ENDPOINT_KEY
from fastapi_shield.typing import EndPointFunc, U
from fastapi_shield.utils import (
    get_solved_dependencies,
    merge_dedup_seq_params,
    prepend_request_to_signature_params_of_function,
    rearrange_params,
)


class ShieldDepends(Generic[U], Security):
    __slots__ = ("dependency", "shielded_dependency", "unblocked")

    def __init__(
        self,
        shielded_dependency: Optional[U] = None,
        *,
        auto_error: bool = True,
        scopes: Optional[Sequence[str]] = None,
        use_cache: bool = True,
    ):
        super().__init__(use_cache=use_cache, scopes=scopes, dependency=lambda: self)
        self.shielded_dependency = shielded_dependency
        self.unblocked = False
        self.auto_error = auto_error
        self._shielded_dependency_params = signature(shielded_dependency).parameters

    @cached_property
    def first_param(self) -> Optional[Parameter]:
        dep = self.shielded_dependency
        if not dep:
            return None
        params = list(self._shielded_dependency_params.values())
        if len(params) == 0:
            return None
        first = params[0]
        if first.default is Parameter.empty:
            return first
        return None

    @cached_property
    def rest_params(self):
        dep = self.shielded_dependency
        if not dep:
            return
        params = list(self._shielded_dependency_params.values())
        if not params:
            return
        first, *rest = params
        if first.default is Parameter.empty:
            yield from rest
        else:
            yield first
            yield from rest

    def __repr__(self) -> str:
        return f"{type(self).__name__}(unblocked={self.unblocked}, shielded_dependency={self.shielded_dependency.__name__ if self.shielded_dependency else None})"

    async def __call__(self, *args, **kwargs):
        if self.unblocked:
            if is_coroutine_callable(self.shielded_dependency):
                return await self.shielded_dependency(*args, **kwargs)
            else:
                return self.shielded_dependency(*args, **kwargs)
        return self

    @property
    def __dict__(self):
        """Custom __dict__ implementation to exclude signature parameters from serialization"""
        return {
            "unblocked": self.unblocked,
            "dependency": self.dependency,
            "shielded_dependency": self.shielded_dependency,
            "use_cache": self.use_cache,
            "scopes": self.scopes,
        }

    def __bool__(self):
        return self.unblocked

    @cached_property
    def __signature__(self) -> Signature:
        """Generate the rearranged signature for FastAPI solving."""
        return Signature(self.rest_params)

    async def resolve_dependencies(self, request: Request):
        solved_dependencies = await get_solved_dependencies(
            request=request,
            endpoint=self,
            dependency_cache={},
        )

        return solved_dependencies

    @asynccontextmanager
    async def _as_unblocked(self):
        self.unblocked = True
        try:
            yield
        finally:
            self.unblocked = False


def ShieldedDepends(  # noqa: N802
    shielded_dependency: Annotated[
        Optional[Callable[..., Any]],
        Doc(
            """
            The dependency to be shielded.
            """
        ),
    ],
    *,
    auto_error: bool = True,
    scopes: Optional[Sequence[str]] = None,
    use_cache: bool = True,
) -> Any:
    return ShieldDepends(
        shielded_dependency=shielded_dependency,
        auto_error=auto_error,
        scopes=scopes,
        use_cache=use_cache,
    )


class Shield(Generic[U]):
    __slots__ = (
        "auto_error",
        "name",
        "_guard_func",
        "_guard_func_is_async",
        "_guard_func_params",
        "_exception_to_raise_if_fail",
        "_default_response_to_return_if_fail",
        "__weakref__",
    )

    def __init__(
        self,
        shield_func: U,
        *,
        name: str = None,
        auto_error: bool = True,
        exception_to_raise_if_fail: Optional[HTTPException] = None,
        default_response_to_return_if_fail: Optional[Response] = None,
    ):
        assert callable(shield_func), "`shield_func` must be callable"
        self._guard_func = shield_func
        self._guard_func_is_async = is_coroutine_callable(shield_func)
        self._guard_func_params = signature(shield_func).parameters
        self.name = name or "unknown"
        self._exception_to_raise_if_fail = exception_to_raise_if_fail or HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Shield with name `{self.name}` blocks the request",
        )
        assert isinstance(self._exception_to_raise_if_fail, HTTPException), (
            "`exception_to_raise_if_fail` must be an instance of `HTTPException`"
        )
        self._default_response_to_return_if_fail = (
            default_response_to_return_if_fail
            or Response(
                content=f"Shield with name `{self.name}` blocks the request",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        )
        self.auto_error = auto_error

    def _raise_or_return_default_response(self):
        if self.auto_error:
            raise self._exception_to_raise_if_fail
        else:
            return self._default_response_to_return_if_fail

    def __call__(self, endpoint: EndPointFunc) -> EndPointFunc:
        assert callable(endpoint), "`endpoint` must be callable"

        endpoint_params = signature(endpoint).parameters
        endpoint_is_async = is_coroutine_callable(endpoint)
        shielded_depends_in_endpoint = {
            param.name: param.default
            for param in endpoint_params.values()
            if isinstance(param.default, ShieldDepends)
        }

        dependency_cache = {}

        @wraps(endpoint)
        async def wrapper(*args, **kwargs):
            guard_func_args = {
                k: v for k, v in kwargs.items() if k in self._guard_func_params
            }
            if self._guard_func_is_async:
                obj = await self._guard_func(**guard_func_args)
            else:
                obj = self._guard_func(**guard_func_args)
            if obj:
                # from here onwards, the shield's job is done
                # hence we should raise an error from now on if anything goes wrong
                request: Request = kwargs.get("request")

                if not request:
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST,
                        detail="Request is required",
                    )
                # because `solve_dependencies` is async, we need to await it
                # hence no point to split returning `wrapper` into two functions, one sync and one async
                endpoint_solved_dependencies, body = await get_solved_dependencies(
                    request, endpoint, dependency_cache
                )
                if endpoint_solved_dependencies.errors:
                    validation_error = RequestValidationError(
                        _normalize_errors(endpoint_solved_dependencies.errors),
                        body=body,
                    )
                    raise validation_error
                kwargs.update(endpoint_solved_dependencies.values)
                resolved_shielded_depends = (
                    await inject_authenticated_entities_into_args_kwargs(
                        obj, request, **shielded_depends_in_endpoint
                    )
                )
                endpoint_kwargs = {
                    k: resolved_shielded_depends.get(k) or kwargs.get(k)
                    for k in endpoint_params
                }
                if endpoint_is_async:
                    return await endpoint(*args, **endpoint_kwargs)
                else:
                    return endpoint(*args, **endpoint_kwargs)

            return self._raise_or_return_default_response()

        wrapper.__signature__ = Signature(
            rearrange_params(
                merge_dedup_seq_params(
                    prepend_request_to_signature_params_of_function(self._guard_func),
                )
            )
        )
        getattr(endpoint, IS_SHIELDED_ENDPOINT_KEY, False) or setattr(
            wrapper,
            IS_SHIELDED_ENDPOINT_KEY,
            True,
        )
        setattr(wrapper, "__endpoint_params__", endpoint_params)
        return wrapper


async def inject_authenticated_entities_into_args_kwargs(
    obj, request: Request, **kwargs: ShieldDepends
) -> dict[str, Any]:
    for idx_kw, arg_kwargs in kwargs.items():
        if idx_kw is not None:
            if arg_kwargs.unblocked:
                raise HTTPException(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Already unblocked",
                )
            solved_dependencies, body = await arg_kwargs.resolve_dependencies(request)
            if solved_dependencies.errors:
                validation_error = RequestValidationError(
                    _normalize_errors(solved_dependencies.errors), body=body
                )
                raise validation_error
            async with arg_kwargs._as_unblocked():
                new_arg_kwargs = await arg_kwargs(
                    *((obj,) if arg_kwargs.first_param is not None else ()),
                    **solved_dependencies.values,
                )
            if (
                new_arg_kwargs is None
                and arg_kwargs.first_param.annotation is not Optional
            ):
                return kwargs
            if isinstance(idx_kw, str):
                kwargs[idx_kw] = new_arg_kwargs
    return kwargs


def search_args_kwargs_for_authenticated_depends(*args, **kwargs):
    for idx, arg in enumerate(args):
        if isinstance(arg, ShieldDepends):
            yield (idx, arg)
    for kw, kwarg in kwargs.items():
        if isinstance(kwarg, ShieldDepends):
            yield (kw, kwarg)
    return ()


def shield(
    shield_func: Optional[U] = None,
    /,
    name: str = None,
    auto_error: bool = True,
    exception_to_raise_if_fail: Optional[HTTPException] = None,
    default_response_to_return_if_fail: Optional[Response] = None,
) -> Shield[U]:
    if shield_func is None:
        return lambda shield_func: shield(
            shield_func,
            name=name,
            auto_error=auto_error,
            exception_to_raise_if_fail=exception_to_raise_if_fail,
            default_response_to_return_if_fail=default_response_to_return_if_fail,
        )
    return Shield(
        shield_func,
        name=name,
        auto_error=auto_error,
        exception_to_raise_if_fail=exception_to_raise_if_fail,
        default_response_to_return_if_fail=default_response_to_return_if_fail,
    )


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
