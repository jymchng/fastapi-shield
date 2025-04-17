from typing_extensions import Doc
from fastapi import Request, HTTPException, status
from fastapi.dependencies.utils import get_typed_signature
from pydantic_core import core_schema
from pydantic.fields import FieldInfo
from fastapi.params import Depends, Security

from functools import wraps
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
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.dependency = lambda: self
        self.shielded_dependency = shielded_dependency
        self.authenticated = False

    def __repr__(self) -> str:
        return f"{type(self).__name__}(authenticated={self.authenticated}, shielded_dependency={self.shielded_dependency.__name__ if self.shielded_dependency else None})"

    def __call__(self, *args, **kwargs):
        if self.authenticated:
            return self.shielded_dependency(*args, **kwargs)
        return self

    def __pydantic_core_schema__(self, *_, **__):
        return core_schema.no_info_after_validator_function(
            self,
            core_schema.union_schema(
                [
                    core_schema.none_schema(),
                    core_schema.str_schema(),
                    core_schema.any_schema(),
                ],
            ),
        )


def ShieldedDepends(  # noqa: N802
    shielded_dependency: Annotated[
        Optional[Callable[..., Any]],
        Doc(
            """
            The dependency to be shielded.
            """
        ),
    ] = None,
) -> Any:
    return ShieldDepends(shielded_dependency=shielded_dependency)


def prepend_request_to_signature_of_endpoint(endpoint: EndPointFunc) -> Signature:
    new_request_param: Parameter = Parameter(
        name="request",
        kind=Parameter.POSITIONAL_ONLY,
        annotation=Request,
        default=Parameter.empty,
    )
    new_signature = signature(endpoint)
    new_params = [*[new_request_param], *new_signature.parameters.values()]
    return Signature(new_params)


def prepend_params_to_signature(
    params: Sequence[Parameter], signature: Signature
) -> Signature:
    new_params = [*params, *signature.parameters.values()]
    return Signature(new_params)


def merge_dedup_seq_params(
    *seqs_of_params: Sequence[Parameter],
) -> list[Parameter]:
    seen = {}
    results = []
    for seq_of_params in seqs_of_params:
        for param in seq_of_params:
            if param.name not in seen:
                seen[param.name] = param
                results.append(param)
    return results


def change_all_shielded_depends_defaults_to_annotated_as_shielded_depends(
    seq_of_params: Sequence[Parameter],
) -> list[Parameter]:
    return [
        param.replace(annotation=ShieldDepends)
        if isinstance(param.default, ShieldDepends)
        else param
        for param in seq_of_params
    ]


def rearrange_params(seq_of_params: Sequence[Parameter]) -> list[Parameter]:
    pos_only_params = [
        param for param in seq_of_params if param.kind == Parameter.POSITIONAL_ONLY
    ]
    var_pos_params = [
        param for param in seq_of_params if param.kind == Parameter.VAR_POSITIONAL
    ]
    kw_or_pos_params = [
        param
        for param in seq_of_params
        if (
            param.kind == Parameter.POSITIONAL_OR_KEYWORD
            and param.default is param.empty
        )
    ] + [
        param
        for param in seq_of_params
        if (
            param.kind == Parameter.POSITIONAL_OR_KEYWORD
            and param.default is not param.empty
        )
    ]
    var_kw_params = [
        param for param in seq_of_params if param.kind == Parameter.VAR_KEYWORD
    ]
    kw_only_params = [
        param for param in seq_of_params if param.kind == Parameter.KEYWORD_ONLY
    ]
    rearranged_params = [
        *pos_only_params,
        *var_pos_params,
        *kw_or_pos_params,
        *var_kw_params,
        *kw_only_params,
    ]
    return rearranged_params


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
                print(
                    "`wrapper::inject_authenticated_entities_into_args_kwargs`: ",
                    obj,
                    args,
                    kwargs,
                )
                args, endpoint_kwargs = inject_authenticated_entities_into_args_kwargs(
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
                    signature(endpoint).parameters.values(),
                )
            )
        )
        print("`wrapper.__name__`: ", wrapper.__name__)
        print("`signature(endpoint)`: ", signature(endpoint))
        print("`wrapper::__signature__`: ", wrapper.__signature__)
        print("`get_typed_signature(wrapper)`: ", get_typed_signature(wrapper))
        return wrapper


def get_values_from_kwargs_for_dependency(
    dependency_func: Callable[[Any], Any], **kwargs
):
    dependency_func_params = signature(dependency_func).parameters
    dependency_kwargs = {k: v for k, v in kwargs.items() if k in dependency_func_params}
    return dependency_kwargs


def inject_authenticated_entities_into_args_kwargs(
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
            new_arg_kwargs = arg_kwargs.shielded_dependency(obj)
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
