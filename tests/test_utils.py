from inspect import Parameter, Signature
from fastapi_shield.utils import rearrange_params


def make_param(name, kind, default=Parameter.empty):
    return Parameter(name, kind, default=default)


def test_pos_only():
    params = [
        make_param("a", Parameter.POSITIONAL_ONLY),
        make_param("b", Parameter.POSITIONAL_ONLY),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["a", "b"]


def test_pos_or_kw_required():
    params = [
        make_param("a", Parameter.POSITIONAL_OR_KEYWORD),
        make_param("b", Parameter.POSITIONAL_OR_KEYWORD),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["a", "b"]


def test_pos_or_kw_optional():
    params = [
        make_param("a", Parameter.POSITIONAL_OR_KEYWORD),
        make_param("b", Parameter.POSITIONAL_OR_KEYWORD, default=0),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["a", "b"]


def test_pos_or_kw_mixed():
    params = [
        make_param("a", Parameter.POSITIONAL_OR_KEYWORD),
        make_param("b", Parameter.POSITIONAL_OR_KEYWORD, default=0),
        make_param("c", Parameter.POSITIONAL_OR_KEYWORD),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["a", "c", "b"]


def test_pos_only_kw_only():
    params = [
        make_param("a", Parameter.POSITIONAL_ONLY),
        make_param("b", Parameter.POSITIONAL_OR_KEYWORD, default=0),
        make_param("c", Parameter.KEYWORD_ONLY),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["a", "b", "c"]


def test_var_pos_kw_only():
    params = [
        make_param("args", Parameter.VAR_POSITIONAL),
        make_param("kwargs", Parameter.VAR_KEYWORD),
        make_param("z", Parameter.KEYWORD_ONLY),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["args", "z", "kwargs"]


def test_all_mixed():
    params = [
        make_param("a", Parameter.POSITIONAL_ONLY),
        make_param("b", Parameter.POSITIONAL_OR_KEYWORD, default=0),
        make_param("c", Parameter.KEYWORD_ONLY),
        make_param("d", Parameter.VAR_POSITIONAL),
        make_param("e", Parameter.VAR_KEYWORD),
        make_param("f", Parameter.POSITIONAL_OR_KEYWORD),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["a", "f", "b", "d", "c", "e"]


def test_var_pos():
    params = [
        make_param("args", Parameter.VAR_POSITIONAL),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["args"]


def test_var_kw():
    params = [
        make_param("kwargs", Parameter.VAR_KEYWORD),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["kwargs"]


def test_keyword_only():
    params = [
        make_param("x", Parameter.KEYWORD_ONLY),
        make_param("y", Parameter.KEYWORD_ONLY),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["x", "y"]


def test_empty():
    params = []
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert result == []


def test_positional_then_args():
    params = [
        make_param("args", Parameter.VAR_POSITIONAL),
        make_param("a", Parameter.POSITIONAL_OR_KEYWORD),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["a", "args"]


def test_kwargs_then_args_then_positional():
    params = [
        make_param("kwargs", Parameter.VAR_KEYWORD),
        make_param("args", Parameter.VAR_POSITIONAL),
        make_param("z", Parameter.POSITIONAL_ONLY),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["z", "args", "kwargs"]


def test_positional_only_and_optional_kw():
    params = [
        make_param("a", Parameter.POSITIONAL_ONLY),
        make_param("b", Parameter.POSITIONAL_OR_KEYWORD, default=0),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["a", "b"]


def test_kw_only_last():
    params = [
        make_param("a", Parameter.POSITIONAL_ONLY),
        make_param("b", Parameter.POSITIONAL_OR_KEYWORD, default=0),
        make_param("c", Parameter.KEYWORD_ONLY),
    ]
    result = list(rearrange_params(params))
    _ = Signature(result)
    assert [p.name for p in result] == ["a", "b", "c"]
