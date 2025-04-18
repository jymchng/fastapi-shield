from typing import TypeVar, Callable, Any, Tuple, Union

TYPE_CHECKING = False

if TYPE_CHECKING:
    from fastapi_shield.shield import AuthenticationStatus

T = TypeVar("T")
U = TypeVar("U")
EndPointFunc = Callable[..., Any]
ShieldFunc = Callable[..., U]
