"""Core shield implementation for FastAPI Shield.

This module contains the main Shield and ShieldDepends classes that provide
the request interception and validation functionality. Shields act as decorators
that can validate, transform, or block requests before they reach FastAPI endpoints.

The shield system works by:
1. Intercepting requests before endpoint execution
2. Running validation logic (shield functions)
3. Either allowing the request to proceed or blocking it
4. Optionally transforming request data and injecting it into dependencies

Key Classes:
    - Shield: The main decorator class for creating request interceptors
    - ShieldDepends: A dependency wrapper that integrates with FastAPI's DI system
    - shield: Factory function for creating Shield instances
"""

from contextlib import asynccontextmanager
from functools import cached_property, wraps
from inspect import Parameter, Signature, signature
from typing import (
    Annotated,
    Any,
    Callable,
    Generic,
    Optional,
    Sequence,
    Union,
    overload,
    Dict,
)
from types import MappingProxyType

from fastapi import HTTPException, Request, Response, status
from fastapi._compat import _normalize_errors
from fastapi.dependencies.utils import is_coroutine_callable
from fastapi.exceptions import RequestValidationError
from fastapi.params import Security
from typing_extensions import Doc

# Import directly to make patching work correctly in tests
import fastapi_shield.utils
from fastapi_shield.consts import (
    IS_SHIELDED_ENDPOINT_KEY,
    SHIELDED_ENDPOINT_PATH_FORMAT_KEY,
)
from fastapi_shield.typing import EndPointFunc, U
from fastapi_shield.utils import (
    get_solved_dependencies,
    merge_dedup_seq_params,
    prepend_request_to_signature_params_of_function,
    rearrange_params,
)


class ShieldDepends(Security, Generic[U]):
    """A dependency wrapper that integrates shields with FastAPI's dependency injection system.

    ShieldDepends allows shield-validated data to be injected into FastAPI endpoints
    as dependencies. It extends FastAPI's Security class to provide authentication
    and authorization capabilities while maintaining compatibility with the standard
    dependency injection system.

    The class manages the lifecycle of shielded dependencies:
    1. Initially blocked (unblocked=False) to prevent unauthorized access
    2. Unblocked after successful shield validation
    3. Dependency resolution with shield-provided data
    4. Injection into endpoint parameters

    Attributes:
        dependency: The FastAPI dependency callable
        shielded_dependency: The original dependency function to be shielded
        unblocked: Flag indicating whether the shield has validated the request
        auto_error: Whether to automatically raise HTTP errors on validation failure

    Examples:
        ```python
        def get_current_user(user_data: dict) -> User:
            return User(**user_data)

        @shield
        def auth_shield(request: Request) -> Optional[dict]:
            # Validate authentication and return user data
            return {"id": 1, "name": "John"}

        @app.get("/profile")
        @auth_shield
        def get_profile(user: User = ShieldedDepends(get_current_user)):
            return {"user": user.name}
        ```
    """

    __slots__ = (
        "dependency",
        "shielded_dependency",
        "unblocked",
        "dependency_cache",
        "auto_error",
        "_shielded_dependency_params",
    )

    def __init__(
        self,
        shielded_dependency: Optional[U] = None,
        *,
        auto_error: bool = True,
        scopes: Optional[Sequence[str]] = None,
        use_cache: bool = True,
    ):
        """Initialize a new ShieldDepends instance.

        Args:
            shielded_dependency: The dependency function to be protected by shields.
                                Can accept data returned by the shield as its first parameter.
            auto_error: Whether to automatically raise HTTP errors on failure.
                       If False, returns default responses instead.
            scopes: OAuth2 scopes required for this dependency (inherited from Security).
            use_cache: Whether to cache the dependency result (inherited from Security).

        Examples:
            ```python
            # Basic shielded dependency
            user_dep = ShieldDepends(get_current_user)

            # With custom error handling
            user_dep = ShieldDepends(get_current_user, auto_error=False)

            # With OAuth2 scopes
            admin_dep = ShieldDepends(get_admin_user, scopes=["admin"])
            ```
        """
        super().__init__(use_cache=use_cache, scopes=scopes, dependency=lambda: self)
        self.shielded_dependency = shielded_dependency
        self.unblocked = False
        self.auto_error = auto_error
        if shielded_dependency is None:
            self._shielded_dependency_params: MappingProxyType[str, Parameter] = (
                MappingProxyType({})
            )
        else:
            self._shielded_dependency_params = signature(shielded_dependency).parameters
        self.dependency_cache: Dict[str, Any] = {}

    @cached_property
    def first_param(self) -> Optional[Parameter]:
        """Get the first parameter of the shielded dependency function.

        The first parameter is special because it receives the shield's returned data.
        If the first parameter has no default value, it's considered required and
        will receive the shield data. Otherwise, it's treated as optional.

        Returns:
            Optional[Parameter]: The first parameter if it has no default value,
                               None if the dependency has no parameters or the
                               first parameter has a default value.

        """
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
        """Get all parameters except the first one (if it has no default).

        These parameters will be resolved using FastAPI's standard dependency
        injection system, while the first parameter (if it exists and has no
        default) receives the shield's validated data.

        Yields:
            Parameter: All parameters that should be resolved via dependency injection.
        """
        dep = self.shielded_dependency
        if not dep:
            return
        params = list(self._shielded_dependency_params.values())
        if not params:
            return
        first, *rest = params
        if first.default is not Parameter.empty:
            yield first
        yield from rest

    def __repr__(self) -> str:
        """Return a string representation of the ShieldDepends instance.

        Returns:
            str: A descriptive string showing the unblocked status and dependency name.
        """
        return f"{type(self).__name__}(unblocked={self.unblocked}, shielded_dependency={self.shielded_dependency.__name__ if self.shielded_dependency else None})"  # pylint: disable=line-too-long

    async def __call__(self, *args, **kwargs):
        """Execute the shielded dependency if unblocked.

        This method is called by FastAPI's dependency injection system. If the
        shield has validated the request (unblocked=True), the dependency function
        is executed with the provided arguments. Otherwise, returns self to
        indicate the dependency is still blocked.

        Args:
            *args: Positional arguments for the dependency function
            **kwargs: Keyword arguments for the dependency function

        Returns:
            Any: The result of the dependency function if unblocked,
                 or self if still blocked.
        """
        if self.unblocked:
            if self.shielded_dependency is not None:
                if is_coroutine_callable(self.shielded_dependency):
                    return await self.shielded_dependency(*args, **kwargs)
                return self.shielded_dependency(*args, **kwargs)
        return self

    @property
    def __dict__(self):  # type: ignore[override]
        """Custom __dict__ implementation to exclude signature parameters from serialization.

        This prevents the signature parameters from being included when the object
        is serialized, which could cause issues with caching and other operations.

        Returns:
            dict: Dictionary containing only the essential attributes.
        """
        return {
            "unblocked": self.unblocked,
            "dependency": self.dependency,
            "shielded_dependency": self.shielded_dependency,
            "use_cache": self.use_cache,
            "scopes": self.scopes,
        }

    def __bool__(self):
        """Return the unblocked status as a boolean.

        Returns:
            bool: True if the dependency is unblocked, False otherwise.
        """
        return self.unblocked

    @cached_property
    def __signature__(self) -> Signature:
        """Generate the rearranged signature for FastAPI dependency resolution.

        Creates a signature containing only the parameters that should be resolved
        by FastAPI's dependency injection system (excludes the first parameter
        if it receives shield data).

        Returns:
            Signature: The signature for FastAPI dependency resolution.
        """
        return Signature(self.rest_params)  # type:ignore[reportArgumentType]

    async def resolve_dependencies(self, request: Request, path_format: str):
        """Resolve the dependencies for this shielded dependency.

        Uses FastAPI's dependency resolution system to resolve all the dependency's
        parameters (except the first one if it receives shield data).

        Args:
            request: The FastAPI request object
            path_format: The raw path format string for the endpoint

        Returns:
            tuple: Solved dependencies and request body

        Raises:
            Various exceptions during dependency resolution
        """
        solved_dependencies = await get_solved_dependencies(
            request=request,
            path_format=path_format,
            endpoint=self,
            dependency_cache=self.dependency_cache,
        )

        return solved_dependencies

    @asynccontextmanager
    async def _as_unblocked(self):
        """Context manager to temporarily unblock the dependency.

        This is used internally during dependency resolution to temporarily
        allow the dependency to be called. The dependency is automatically
        re-blocked when the context exits.

        Yields:
            None: The dependency is unblocked for the duration of the context.
        """
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
            The dependency function to be protected by shields.
            
            This function will be called with shield-validated data as its first
            parameter (if the first parameter has no default value), followed by
            any other dependencies resolved by FastAPI's dependency injection system.
            """
        ),
    ],
    *,
    auto_error: bool = True,
    scopes: Optional[Sequence[str]] = None,
    use_cache: bool = True,
) -> Any:
    """Factory function to create a ShieldDepends instance.

    This is the main function users should use to create shielded dependencies.
    It provides a clean interface for creating `ShieldDepends` instances with
    proper type hints and documentation.

    Args:
        shielded_dependency: The dependency function to be protected by shields.
                           Can accept data returned by the shield as its first parameter.
        auto_error: Whether to automatically raise HTTP errors on failure.
                   If False, returns default responses instead.
        scopes: OAuth2 scopes required for this dependency.
        use_cache: Whether to cache the dependency result.

    Returns:
        ShieldDepends: A configured shielded dependency instance.

    Examples:
        ```python
        from fastapi import Depends
        from fastapi_shield import ShieldedDepends, shield

        def get_current_user(user_data: dict, db: Session = Depends(get_db)) -> User:
            return User.get(db, user_data["id"])

        @shield
        def auth_shield(request: Request) -> Optional[dict]:
            token = request.headers.get("Authorization")
            if validate_token(token):
                return {"id": 123, "username": "john"}
            return None

        @app.get("/profile")
        @auth_shield
        def get_profile(user: User = ShieldedDepends(get_current_user)):
            return {"username": user.username}
        ```
    """
    return ShieldDepends(
        shielded_dependency=shielded_dependency,
        auto_error=auto_error,
        scopes=scopes,
        use_cache=use_cache,
    )


class Shield(Generic[U]):
    """The main shield decorator class for request interception and validation.

    Shield provides a powerful framework for intercepting FastAPI requests before
    they reach the endpoint handlers. It can validate authentication, authorization,
    rate limiting, input sanitization, and any other request-level logic.

    The `Shield` class works as a decorator that wraps endpoint functions. When a
    request is made to a shielded endpoint:

    1. The shield function is called first with request parameters
    2. If the shield returns truthy data, the request proceeds
    3. The data returned by the shield is available to `ShieldedDepends` dependencies
    4. If the shield returns None/False, the request is blocked

    Attributes:
        auto_error: Whether to raise HTTP exceptions on shield failure
        name: Human-readable name for the shield (used in error messages)

    Examples:
        ```python
        # Basic authentication shield
        @shield
        def auth_shield(request: Request) -> Optional[dict]:
            token = request.headers.get("Authorization")
            if validate_token(token):
                return {"user_id": 123, "username": "john"}
            return None  # Block the request

        # Apply shield to endpoint
        @app.get("/protected")
        @auth_shield
        def protected_endpoint():
            return {"message": "Access granted"}

        # Custom error handling
        auth_shield_custom = Shield(
            auth_shield,
            name="Authentication",
            auto_error=False,
            default_response_to_return_if_fail=Response(
                content="Authentication required",
                status_code=401
            )
        )
        ```
    """

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
        name: Optional[str] = None,
        auto_error: bool = True,
        exception_to_raise_if_fail: Optional[HTTPException] = None,
        default_response_to_return_if_fail: Optional[Response] = None,
    ):
        """Initialize a new Shield instance.

        Args:
            shield_func: The validation function to use for this shield.
                        Should return truthy data to allow requests, or None/False to block.
                        Can be sync or async.
            name: Human-readable name for the shield. Used in error messages and logging.
                 Defaults to "unknown" if not provided.
            auto_error: Whether to automatically raise HTTP exceptions when the shield
                       blocks a request. If False, returns the default response instead.
            exception_to_raise_if_fail: Custom HTTP exception to raise when shield blocks
                                       a request and auto_error=True. Defaults to a 500
                                       error with the shield name.
            default_response_to_return_if_fail: Custom response to return when shield
                                               blocks a request and auto_error=False.
                                               Defaults to a 500 response with shield name.

        Raises:
            AssertionError: If shield_func is not callable, or if exception/response
                           parameters are not the correct types.

        Examples:
            ```python
            # Basic shield
            shield = Shield(my_auth_function)

            # Named shield with custom error
            shield = Shield(
                my_auth_function,
                name="Authentication",
                exception_to_raise_if_fail=HTTPException(401, "Authentication required")
            )

            # Shield with custom response instead of exceptions
            shield = Shield(
                my_auth_function,
                name="Authentication",
                auto_error=False,
                default_response_to_return_if_fail=Response(
                    content="Please log in",
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
            )
            ```
        """
        assert callable(shield_func), "`shield_func` must be callable"
        self._guard_func: U = shield_func
        self._guard_func_is_async: bool = is_coroutine_callable(shield_func)
        self._guard_func_params: MappingProxyType[str, Parameter] = signature(
            shield_func
        ).parameters
        self.name: str = name or "unknown"
        self.auto_error: bool = auto_error
        self._exception_to_raise_if_fail: Optional[HTTPException] = (
            exception_to_raise_if_fail
        )
        if self._exception_to_raise_if_fail is not None:
            assert isinstance(self._exception_to_raise_if_fail, HTTPException), (
                "`exception_to_raise_if_fail` must be an instance of `HTTPException`"
            )
        self._default_response_to_return_if_fail: Optional[Response] = (
            default_response_to_return_if_fail
        )
        if self._default_response_to_return_if_fail is not None:
            assert isinstance(self._default_response_to_return_if_fail, Response), (
                "`default_response_to_return_if_fail` must be an instance of `Response`"
            )

    def _raise_or_return_default_response(self):
        """Handle shield failure by raising an exception or returning a default response.

        This method is called when the shield blocks a request (returns None/False).
        The behavior depends on the auto_error setting:
        - If auto_error=True: raises the configured HTTP exception
        - If auto_error=False: returns the configured default response

        Returns:
            Response: The default response if auto_error=False

        Raises:
            HTTPException: The configured exception if auto_error=True
        """
        if self.auto_error:
            if self._exception_to_raise_if_fail is None:
                self._exception_to_raise_if_fail = HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Shield with name `{self.name}` blocks the request",
                )
            raise self._exception_to_raise_if_fail  # type: ignore[reportGeneralTypeIssues]
        if self._default_response_to_return_if_fail is None:
            self._default_response_to_return_if_fail = Response(
                content=f"Shield with name `{self.name}` blocks the request",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return self._default_response_to_return_if_fail

    def __call__(self, endpoint: EndPointFunc) -> EndPointFunc:
        """Apply the shield to a FastAPI endpoint function.

        This method implements the decorator functionality, wrapping the endpoint
        function with shield validation logic. When the returned wrapper is called:

        1. Extracts relevant parameters for the shield function
        2. Calls the shield function with those parameters
        3. If shield returns truthy data:
           - Resolves all endpoint dependencies
           - Injects data returned by the shield into `ShieldedDepends` dependencies
           - Calls the original endpoint with resolved parameters
        4. If shield returns None/False:
           - Blocks the request by raising an exception or returning error response

        The wrapper handles both sync and async shield functions and endpoints
        automatically, and integrates with FastAPI's dependency injection system.

        Args:
            endpoint: The FastAPI endpoint function to protect with this shield.
                     Can be sync or async.

        Returns:
            EndPointFunc: The wrapped endpoint function with shield protection.

        Raises:
            AssertionError: If endpoint is not callable.

        Examples:
            ```python
            @shield
            def auth_shield(request: Request) -> Optional[dict]:
                # Validation logic
                return user_data or None

            # Using as decorator
            @app.get("/protected")
            @auth_shield
            def protected_endpoint():
                return {"message": "Success"}
            ```

        Note:
            The wrapper function is always async, even if the original endpoint
            is sync, because dependency resolution is inherently async in FastAPI.
        """
        assert callable(endpoint), "`endpoint` must be callable"

        endpoint_params = signature(endpoint).parameters
        endpoint_is_async = is_coroutine_callable(endpoint)
        shielded_depends_in_endpoint = {
            param.name: param.default
            for param in endpoint_params.values()
            if isinstance(param.default, ShieldDepends)
        }

        dependency_cache: Dict[str, Any] = {}

        @wraps(endpoint)
        async def wrapper(*args, **kwargs):
            guard_func_args: Dict[str, Any] = {
                k: v for k, v in kwargs.items() if k in self._guard_func_params
            }
            if self._guard_func_is_async:
                obj = await self._guard_func(**guard_func_args)
            else:
                obj = self._guard_func(**guard_func_args)

            if obj:
                # from here onwards, the shield's job is done
                # hence we should raise an error from now on if anything goes wrong
                request = kwargs.get("request")

                if not request and not isinstance(request, Request):
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST,
                        detail="Request is required or `request` is not of type `Request`",
                    )

                if not hasattr(wrapper, SHIELDED_ENDPOINT_PATH_FORMAT_KEY):
                    path_format = (
                        fastapi_shield.utils.get_path_format_from_request_for_endpoint(
                            request
                        )
                    )
                else:
                    path_format = getattr(wrapper, SHIELDED_ENDPOINT_PATH_FORMAT_KEY)
                setattr(endpoint, SHIELDED_ENDPOINT_PATH_FORMAT_KEY, path_format)

                # because `solve_dependencies` is async, we need to await it
                # hence no point to split returning `wrapper` into two functions, one sync and one async
                endpoint_solved_dependencies, body = await get_solved_dependencies(
                    request, path_format, endpoint, dependency_cache
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
                        obj, request, path_format, **shielded_depends_in_endpoint
                    )
                )
                endpoint_kwargs = {
                    k: resolved_shielded_depends.get(k) or kwargs.get(k)
                    for k in endpoint_params
                }
                if endpoint_is_async:
                    return await endpoint(*args, **endpoint_kwargs)
                return endpoint(*args, **endpoint_kwargs)

            return self._raise_or_return_default_response()

        wrapper.__signature__ = Signature(  # type:ignore[attr-defined]
            rearrange_params(  # type:ignore[reportArgumentType]
                merge_dedup_seq_params(
                    prepend_request_to_signature_params_of_function(self._guard_func),
                )
            )
        )
        _ = getattr(endpoint, IS_SHIELDED_ENDPOINT_KEY, False) or setattr(  # type: ignore[func-returns-value]
            endpoint,
            IS_SHIELDED_ENDPOINT_KEY,
            True,
        )
        return wrapper


async def inject_authenticated_entities_into_args_kwargs(
    obj, request: Request, path_format: str, **kwargs: ShieldDepends
) -> dict[str, Any]:
    """Inject data returned by the shield into `ShieldedDepends` dependencies.

    This function is called after a shield has successfully validated a request.
    It resolves all `ShieldedDepends` dependencies in the endpoint, providing them
    with the shield's validated data and any other resolved dependencies.

    The process for each `ShieldedDepends`:
    1. Ensure it's currently blocked (for security)
    2. Resolve its dependencies using FastAPI's DI system
    3. Temporarily unblock it
    4. Call it with shield data (if it has a first parameter) + resolved dependencies
    5. Store the result for injection into the endpoint

    Args:
        obj: The data returned by the shield function (data returned by the shield).
        request: The FastAPI Request object.
        path_format: The raw path format string for the endpoint.
        **kwargs: Dictionary of parameter names to ShieldDepends instances
                 found in the endpoint signature.

    Returns:
        dict[str, Any]: Updated kwargs dictionary with resolved `ShieldedDepends`
                       values replacing the ShieldDepends instances.

    Raises:
        HTTPException: If a `ShieldedDepends` is already unblocked (security error)
                      or if dependency resolution fails.
        RequestValidationError: If dependency validation fails.

    Examples:
        This function is called internally by the Shield decorator. For example:

        ```python
        @shield
        def auth_shield(request: Request) -> dict:
            return {"user_id": 123, "role": "admin"}

        def get_user(user_data: dict, db: Session = Depends(get_db)) -> User:
            return db.get(User, user_data["user_id"])

        @app.get("/profile")
        @auth_shield
        def profile(user: User = ShieldedDepends(get_user)):
            # user will be injected with the result of get_user(auth_shield_data, db)
            return {"username": user.username}
        ```
    """
    for idx_kw, arg_kwargs in kwargs.items():
        if idx_kw is not None:
            if arg_kwargs.unblocked:
                raise HTTPException(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Already unblocked",
                )
            solved_dependencies, body = await arg_kwargs.resolve_dependencies(
                request, path_format
            )
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
                and arg_kwargs.first_param is not None
                and arg_kwargs.first_param.annotation is not Optional
            ):
                return kwargs
            if isinstance(idx_kw, str):
                kwargs[idx_kw] = new_arg_kwargs
    return kwargs


@overload
def shield(
    shield_func: None = None,
    /,
    name: Optional[str] = None,
    auto_error: bool = True,
    exception_to_raise_if_fail: Optional[HTTPException] = None,
    default_response_to_return_if_fail: Optional[Response] = None,
) -> Callable[[U], Shield[U]]: ...


@overload
def shield(
    shield_func: U,
    /,
    name: Optional[str] = None,
    auto_error: bool = True,
    exception_to_raise_if_fail: Optional[HTTPException] = None,
    default_response_to_return_if_fail: Optional[Response] = None,
) -> Shield[U]: ...


def shield(
    shield_func: Optional[U] = None,
    /,
    name: Optional[str] = None,
    auto_error: bool = True,
    exception_to_raise_if_fail: Optional[HTTPException] = None,
    default_response_to_return_if_fail: Optional[Response] = None,
) -> Union[Callable[[U], Shield[U]], Shield[U]]:
    """Factory function and decorator for creating `Shield` instances.

    This is the main entry point for creating shields. It can be used as a
    decorator with or without parameters, or as a factory function to create
    `Shield` instances.

    The shield function should accept parameters that match FastAPI endpoint
    parameters (like request, path parameters, query parameters, etc.) and
    return either:
    - Truthy data (dict, object, etc.) to allow the request and provide data
      to `ShieldedDepends` dependencies
    - None or False to block the request

    Args:
        shield_func: The validation function to use. If None, returns a decorator
                    function that accepts the shield function.
        name: Human-readable name for the shield (used in error messages).
        auto_error: Whether to raise HTTP exceptions on shield failure.
        exception_to_raise_if_fail: Custom exception to raise on failure.
        default_response_to_return_if_fail: Custom response when auto_error=False.

    Returns:
        Shield[U]: A `Shield` instance that can be used as a decorator.

    Examples:
        ```python
        # Basic usage as decorator
        @shield
        def auth_shield(request: Request) -> Optional[dict]:
            token = request.headers.get("Authorization")
            if validate_token(token):
                return {"user_id": 123}
            return None

        # With parameters
        @shield(name="Authentication", auto_error=False)
        def auth_shield(request: Request) -> Optional[dict]:
            # validation logic
            pass

        # As factory function
        auth_shield = shield(
            my_auth_function,
            name="Authentication",
            exception_to_raise_if_fail=HTTPException(401, "Unauthorized")
        )

        # Apply to endpoints
        @app.get("/protected")
        @auth_shield
        def protected_endpoint():
            return {"message": "Access granted"}

        # Shield with path parameters
        @shield
        def user_ownership_shield(request: Request, user_id: int) -> Optional[dict]:
            current_user = get_current_user_from_token(request)
            if current_user.id == user_id or current_user.is_admin:
                return {"current_user": current_user}
            return None
        ```

    Note:
        Shield functions can be sync or async. The shield system handles both
        transparently. Shield functions should use type hints for better
        integration with FastAPI's dependency injection.
    """
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
