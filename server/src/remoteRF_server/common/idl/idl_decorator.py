from functools import wraps

# todo: actually implement the whatever dynamic building ...

def idl_expose(func=None, *, name=None, desc=None, kind="method"):
    valid_kinds = {"method", "get", "set"}

    if kind not in valid_kinds:
        raise ValueError(f"kind must be one of {valid_kinds}, got {kind!r}")

    def decorator(fn):
        fn._idl_exposed = True
        fn._idl_name = name or fn.__name__
        fn._idl_desc = desc or (fn.__doc__.strip() if fn.__doc__ else "")
        fn._idl_kind = kind
        return fn

    if func is not None:
        return decorator(func)

    return decorator