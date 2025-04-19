from typing_extensions import Doc
from fastapi import Request, HTTPException, status
from fastapi.dependencies.utils import (
    solve_dependencies,
    get_dependant,
    is_coroutine_callable,
)
from contextlib import asynccontextmanager
from fastapi.params import Security
from fastapi_shield.utils import (
    rearrange_params,
    prepend_request_to_signature_params_of_endpoint,
    merge_dedup_seq_params,
)
from fastapi_shield.typing import EndPointFunc, ShieldFunc, U

from functools import cached_property, wraps
from inspect import signature, Signature, Parameter

from typing import (
    Annotated,
    Optional,
    Callable,
    Any,
    Generic,
    Tuple,
)


def check_shield_instances_match(shield_inst: "Shield", shield_depends: "ShieldDepends"):
    if shield_inst is shield_depends.shielded_by:
        return True
    else:
        return False


class ShieldDepends(Security):
    __slots__ = ("dependency", "shielded_dependency", "authenticated", "shielded_by")

    def __init__(
        self,
        shielded_dependency: Optional[Callable[..., Any]] = None,
        shielded_by: Optional["Shield"] = None,
        auto_error: bool = True,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.dependency = lambda: self
        self.shielded_dependency = shielded_dependency
        self.authenticated = False
        self.shielded_by = shielded_by
        self.auto_error = auto_error
        self.check_dependency_signature(signature(shielded_dependency))
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
        return f"{type(self).__name__}(authenticated={self.authenticated}, shielded_dependency={self.shielded_dependency.__name__ if self.shielded_dependency else None})"

    async def __call__(self, *args, **kwargs):
        if self.authenticated:
            if is_coroutine_callable(self.shielded_dependency):
                return await self.shielded_dependency(*args, **kwargs)
            else:
                return self.shielded_dependency(*args, **kwargs)
        return self

    def check_dependency_signature(self, signature: Signature):
        params = signature.parameters
        for idx, param in enumerate(params.values()):
            if idx == 0:
                continue
            if param.default is Parameter.empty:
                raise ValueError(f"Parameter '{param.name}' must have a default value")

    @property
    def __dict__(self):
        """Custom __dict__ implementation to exclude signature parameters from serialization"""
        return {
            "authenticated": self.authenticated,
            "dependency": self.dependency,
            "shielded_dependency": self.shielded_dependency,
            "use_cache": self.use_cache,
            "scopes": self.scopes,
        }
        
    def __bool__(self):
        return self.authenticated

    @cached_property
    def __signature__(self) -> Signature:
        """Generate the rearranged signature for FastAPI solving."""
        return Signature(self.rest_params)

    async def resolve_dependencies(self, request: Request):
        solved_dependencies = await solve_dependencies(
            request=request,
            dependant=get_dependant(path="", call=self),
            async_exit_stack=None,
            embed_body_fields=False,
        )
        if solved_dependencies.errors:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to solve dependencies",
            )
        return solved_dependencies.values

    @asynccontextmanager
    async def _as_authenticated(self):
        self.authenticated = True
        try:
            yield
        finally:
            self.authenticated = False


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
    shielded_by: Optional["Shield"] = None,
    use_cache: bool = True,
) -> Any:
    return ShieldDepends(
        shielded_dependency=shielded_dependency,
        use_cache=use_cache,
        shielded_by=shielded_by,
    )


class Shield(Generic[U]):
    def __init__(
        self,
        shield_func: ShieldFunc[U],
        exception_to_raise_if_fail: HTTPException = HTTPException(
            status_code=401, detail="Unauthorized"
        ),
    ):
        assert callable(shield_func), "`shield_func` must be callable"
        self._guard_func = shield_func
        self._guard_func_params = signature(shield_func).parameters
        assert isinstance(exception_to_raise_if_fail, HTTPException), (
            "`exception_to_raise_if_fail` must be an instance of `HTTPException`"
        )
        self._exception_to_raise_if_fail = exception_to_raise_if_fail

    def __call__(self, endpoint: EndPointFunc) -> EndPointFunc:
        assert callable(endpoint), "`endpoint` must be callable"

        endpoint_params = signature(endpoint).parameters
        
        @wraps(endpoint)
        async def wrapper(*args, **kwargs):
            guard_func_args = {
                k: v for k, v in kwargs.items() if k in self._guard_func_params
            }
            if is_coroutine_callable(self._guard_func):
                obj = await self._guard_func(**guard_func_args)
            else:
                obj = self._guard_func(**guard_func_args)
            if obj:
                (
                    args,
                    endpoint_kwargs,
                ) = await inject_authenticated_entities_into_args_kwargs(
                    obj, self, *args, **kwargs
                )
                endpoint_kwargs = {
                    k: v
                    for k, v in endpoint_kwargs.items()
                    if k in endpoint_params
                }
                if is_coroutine_callable(endpoint):
                    return await endpoint(*args, **endpoint_kwargs)
                else:
                    return endpoint(*args, **endpoint_kwargs)

            raise self._exception_to_raise_if_fail

        wrapper.__signature__ = Signature(
            rearrange_params(
                merge_dedup_seq_params(
                    self._guard_func_params.values(),
                    prepend_request_to_signature_params_of_endpoint(endpoint),
                )
            )
        )
        return wrapper


async def inject_authenticated_entities_into_args_kwargs(
    obj, shield_inst: Shield, *args, **kwargs
) -> Tuple[Tuple[Any, ...], dict[str, Any]]:
    authenticated_depends = search_args_kwargs_for_authenticated_depends(
        shield_inst, *args, **kwargs
    )
    for idx_kw, arg_kwargs in authenticated_depends:
        if idx_kw is not None:
            if arg_kwargs.authenticated:
                raise HTTPException(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Already authenticated",
                )
            request = kwargs.get("request")
            if not request:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    detail="Request is required",
                )
            solved_dependencies_values = await arg_kwargs.resolve_dependencies(request)
            async with arg_kwargs._as_authenticated():
                new_arg_kwargs = await arg_kwargs(
                    *((obj,) if arg_kwargs.first_param is not None else ()),
                    **solved_dependencies_values,
                )
            if (
                new_arg_kwargs is None
                and arg_kwargs.first_param.annotation is not Optional
            ):
                return args, kwargs
            if isinstance(idx_kw, int):
                args = args[:idx_kw] + (new_arg_kwargs,) + args[idx_kw + 1 :]
            if isinstance(idx_kw, str):
                kwargs[idx_kw] = new_arg_kwargs
    return args, kwargs


def search_args_kwargs_for_authenticated_depends(shield_inst: Shield, *args, **kwargs):
    for idx, arg in enumerate(args):
        if isinstance(arg, ShieldDepends) and (
            arg.shielded_by is None or arg.shielded_by is shield_inst
        ):
            yield (idx, arg)
    for kw, kwarg in kwargs.items():
        if isinstance(kwarg, ShieldDepends) and (
            kwarg.shielded_by is None or kwarg.shielded_by is shield_inst
        ):
            yield (kw, kwarg)
