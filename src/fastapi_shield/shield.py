from typing_extensions import Doc
from fastapi import Request, HTTPException, status, Depends
from fastapi.dependencies.utils import (
    solve_dependencies,
    get_dependant,
)
from fastapi.params import Security
from fastapi_shield.utils import rearrange_params

from functools import cached_property, wraps
from inspect import signature, Signature, Parameter
from enum import Enum

from typing import (
    Annotated,
    Optional,
    Callable,
    Any,
    Generic,
    TypeVar,
    Tuple,
    Sequence,
    Union,
)

T = TypeVar("T")
U = TypeVar("U")


class AuthenticationStatus(Enum):
    AUTHENTICATED = "AUTHENTICATED"
    UNAUTHENTICATED = "UNAUTHENTICATED"

    def __bool__(self) -> bool:
        return self is AuthenticationStatus.AUTHENTICATED


EndPointFunc = Callable[..., Any]
ShieldFunc = Callable[[T], Tuple[Union[AuthenticationStatus, bool], U]]


class ShieldDepends(Security):
    def __init__(
        self,
        shielded_dependency: Optional[Callable[..., Any]] = None,
        shielded_by: Optional["Shield"] = None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.dependency = lambda: self
        self.shielded_dependency = shielded_dependency
        self.authenticated = False
        self.shielded_by = shielded_by
        self.check_dependency_signature(signature(shielded_dependency))

    @cached_property
    def first_param(self) -> Optional[Parameter]:
        dep = self.shielded_dependency
        if not dep:
            return None
        params = list(signature(dep).parameters.values())
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
        params = list(signature(dep).parameters.values())
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

    def __call__(self, *args, **kwargs):
        if self.authenticated:
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


def prepend_params_to_signature(
    params: Sequence[Parameter], signature: Signature
) -> Signature:
    new_params = [*params, *signature.parameters.values()]
    return Signature(new_params)


def merge_dedup_seq_params(
    *seqs_of_params: Sequence[Parameter],
):
    seen = {}
    for seq_of_params in seqs_of_params:
        for param in seq_of_params:
            if param.name not in seen:
                seen[param.name] = param
                yield param


def change_all_shielded_depends_defaults_to_annotated_as_shielded_depends(
    seq_of_params: Sequence[Parameter],
) -> list[Parameter]:
    return [
        param.replace(annotation=ShieldDepends)
        if isinstance(param.default, ShieldDepends)
        else param
        for param in seq_of_params
    ]


class Shield(Generic[T, U]):
    def __init__(
        self,
        shield_func: ShieldFunc[T, U],
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

        @wraps(endpoint)
        async def wrapper(*args, **kwargs):
            guard_func_args = {
                k: v for k, v in kwargs.items() if k in self._guard_func_params
            }
            auth_status, obj = self._guard_func(**guard_func_args)
            if auth_status:
                (
                    args,
                    endpoint_kwargs,
                ) = await inject_authenticated_entities_into_args_kwargs(
                    obj, *args, **kwargs
                )
                endpoint_kwargs = {
                    k: v
                    for k, v in endpoint_kwargs.items()
                    if k in signature(endpoint).parameters
                }
                return await endpoint(*args, **endpoint_kwargs)

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


def get_values_from_kwargs_for_dependency(
    dependency_func: Callable[[Any], Any], **kwargs
):
    dependency_func_params = signature(dependency_func).parameters
    dependency_kwargs = {k: v for k, v in kwargs.items() if k in dependency_func_params}
    return dependency_kwargs


async def inject_authenticated_entities_into_args_kwargs(
    obj, *args, **kwargs
) -> Tuple[Tuple[Any, ...], dict[str, Any]]:
    authenticated_depends = search_args_kwargs_for_authenticated_depends(
        *args, **kwargs
    )
    for idx_kw, arg_kwargs in authenticated_depends:
        if idx_kw is not None:
            if arg_kwargs.authenticated:
                raise HTTPException(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Already authenticated",
                )
            arg_kwargs.authenticated = True
            request = kwargs.get("request")
            if not request:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    detail="Request is required",
                )
            solved_dependencies_values = await arg_kwargs.resolve_dependencies(request)
            new_arg_kwargs = arg_kwargs.shielded_dependency(
                *((obj,) if arg_kwargs.first_param is not None else ()),
                **solved_dependencies_values,
            )
            if (
                new_arg_kwargs is None
                and arg_kwargs.first_param.annotation is not Optional
            ):
                arg_kwargs.authenticated = False
                return args, kwargs
            arg_kwargs.authenticated = False
            if isinstance(idx_kw, int):
                args = args[:idx_kw] + (new_arg_kwargs,) + args[idx_kw + 1 :]
            if isinstance(idx_kw, str):
                kwargs[idx_kw] = new_arg_kwargs
    return args, kwargs


def remove_authenticated_depends_from_signature_of_endpoint(
    endpoint: EndPointFunc,
) -> Signature:
    new_signature = signature(endpoint)
    return remove_authenticated_depends_from_signature(new_signature)


def remove_authenticated_depends_from_signature(
    signature: Signature,
) -> Signature:
    new_params = [
        param
        for param in signature.parameters.values()
        if not isinstance(param.default, ShieldDepends)
    ]
    return Signature(new_params)


def search_args_kwargs_for_authenticated_depends(
    *args, **kwargs
) -> list[Tuple[Union[str, int], ShieldDepends]]:
    results = []
    for idx, arg in enumerate(args):
        if isinstance(arg, ShieldDepends):
            results.append((idx, arg))
    for kw, kwarg in kwargs.items():
        if isinstance(kwarg, ShieldDepends):
            results.append((kw, kwarg))
    return results
