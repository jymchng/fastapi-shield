from typing import TypeVar, Callable, Any

TYPE_CHECKING = False

T = TypeVar("T")
U = TypeVar("U")
EndPointFunc = Callable[..., Any]
ShieldFunc = Callable[..., U]
