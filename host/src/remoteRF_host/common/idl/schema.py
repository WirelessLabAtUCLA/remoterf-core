# src/remoteRF_host/common/idl/schema.py
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import sys
import types
from pathlib import Path
from typing import Any, Dict

from ..utils.db_location import get_drivers_dir

_EXPOSE_KEY = "__idl__"


def idl_expose(_fn=None, *, kind: str = "call", doc: str = ""):
    def _apply(fn):
        meta = {
            "kind": kind,
            "doc": doc or (fn.__doc__ or "").strip(),
        }
        setattr(fn, _EXPOSE_KEY, meta)
        return fn

    if _fn is not None:
        return _apply(_fn)
    return _apply


_DRIVER_REGISTRY: Dict[str, type] = {}


def register_driver(device_type: str):
    def decorator(cls):
        key = device_type.strip().lower()
        _DRIVER_REGISTRY[key] = cls
        return cls

    return decorator


idl_register = register_driver


def get_driver_class(device_type: str) -> type:
    cls = _DRIVER_REGISTRY.get(device_type.strip().lower())
    if cls is None:
        raise KeyError(
            f"no driver for type '{device_type}'. "
            f"registered: {list(_DRIVER_REGISTRY.keys()) or ['(none)']}"
        )
    return cls


def list_registered_drivers() -> Dict[str, str]:
    return {
        k: f"{cls.device_type} v{cls.driver_version}"
        for k, cls in _DRIVER_REGISTRY.items()
    }


def ensure_default_driver_files() -> Dict[str, str]:
    drivers_dir = get_drivers_dir()
    drivers_dir.mkdir(parents=True, exist_ok=True)

    results: Dict[str, str] = {}
    for filename in ("pluto_schema.py", "pluto_mimo_schema.py"):
        target = drivers_dir / filename
        if target.exists():
            results[filename] = "exists"
            continue

        source = Path(__file__).with_name(filename)
        try:
            text = source.read_text(encoding="utf-8")
            with target.open("x", encoding="utf-8") as f:
                f.write(text)
            results[filename] = "created"
        except FileExistsError:
            results[filename] = "exists"
        except Exception as e:
            results[filename] = f"error: {e}"

    return results


def install_server_import_compat() -> None:
    """
    Make server-authored schema imports resolve to the host IDL implementation.

    This lets host driver files reuse the exact same import lines as server
    driver files, e.g.:

        from remoteRF_server.common.idl import DeviceSchema, idl_register, idl_expose
    """
    schema_mod = sys.modules[__name__]
    idl_pkg = sys.modules.get(__package__)
    if idl_pkg is None:
        return

    server_pkg_name = "remoteRF_server"
    common_pkg_name = "remoteRF_server.common"
    idl_pkg_name = "remoteRF_server.common.idl"
    schema_pkg_name = "remoteRF_server.common.idl.schema"

    server_pkg = sys.modules.get(server_pkg_name)
    if server_pkg is None:
        server_pkg = types.ModuleType(server_pkg_name)
        server_pkg.__path__ = []
        sys.modules[server_pkg_name] = server_pkg

    common_pkg = sys.modules.get(common_pkg_name)
    if common_pkg is None:
        common_pkg = types.ModuleType(common_pkg_name)
        common_pkg.__path__ = []
        sys.modules[common_pkg_name] = common_pkg

    sys.modules[idl_pkg_name] = idl_pkg
    sys.modules[schema_pkg_name] = schema_mod

    setattr(server_pkg, "common", common_pkg)
    setattr(common_pkg, "idl", idl_pkg)
    setattr(idl_pkg, "schema", schema_mod)


def load_drivers() -> Dict[str, str]:
    install_server_import_compat()
    ensure_default_driver_files()
    drivers_dir = get_drivers_dir()
    drivers_dir.mkdir(parents=True, exist_ok=True)

    results: Dict[str, str] = {}
    if not drivers_dir.is_dir():
        return {"__error__": f"{drivers_dir} is not a directory"}

    for f in sorted(drivers_dir.glob("*.py")):
        if f.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f.stem, str(f))
            if spec is None or spec.loader is None:
                results[f.name] = "skip: not a valid module"
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[f.stem] = mod
            spec.loader.exec_module(mod)
            results[f.name] = "ok"
        except Exception as e:
            results[f.name] = f"error: {e}"

    return results


class DeviceSchema:
    device_type: str = ""
    driver_version: str = ""

    def __init__(self):
        self.device = None
        self._exposed: Dict[str, _Exposed] = {}
        self._schema_cache: dict | None = None
        self._hash_cache: str | None = None
        self._introspect()

    @staticmethod
    def make_device(**kwargs):
        raise NotImplementedError("make_device() must be implemented in the schema")

    def bind(self, device) -> None:
        self.device = device

    def is_connected(self) -> bool:
        return self.device is not None

    def _introspect(self):
        seen: set[str] = set()
        for klass in type(self).__mro__:
            for name, obj in vars(klass).items():
                if name in seen or name.startswith("_"):
                    continue
                meta = getattr(obj, _EXPOSE_KEY, None)
                if meta is None:
                    continue
                seen.add(name)
                self._exposed[name] = _Exposed(
                    name=name,
                    fn=obj,
                    kind=meta["kind"],
                    doc=meta["doc"],
                )

    def get_idl(self) -> dict:
        if self._schema_cache is not None:
            return self._schema_cache

        body = self._build_body()
        canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
        h = f"sha256:{hashlib.sha256(canon.encode()).hexdigest()}"

        self._hash_cache = h
        self._schema_cache = {**body, "schema_hash": h}
        return self._schema_cache

    def get_idl_hash(self) -> str:
        if self._hash_cache is None:
            self.get_idl()
        return self._hash_cache  # type: ignore[return-value]

    def get_idl_json(self, *, pretty: bool = False) -> str:
        d = self.get_idl()
        if pretty:
            return json.dumps(d, indent=2, sort_keys=True)
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    def _build_body(self) -> dict:
        getters = {}
        setters = {}
        calls = {}

        for name, ex in sorted(self._exposed.items()):
            entry = {"doc": ex.doc} if ex.doc else {}
            if ex.kind == "get":
                getters[name] = entry
            elif ex.kind == "set":
                entry["args"] = self._args_metadata(ex, skip_self=True)
                setters[name] = entry
            elif ex.kind == "call":
                entry["args"] = self._args_metadata(ex, skip_self=True)
                calls[name] = entry

        body = {
            "schema_version": "1.0",
            "device_type": self.device_type,
            "driver_version": self.driver_version,
            "getters": getters,
            "setters": setters,
            "calls": calls,
        }

        client_class = getattr(self, "client_class", "")
        if client_class:
            body["client_class"] = str(client_class)

        return body

    def _args_metadata(self, ex: "_Exposed", *, skip_self: bool) -> list[dict]:
        sig = inspect.signature(ex.fn)
        args = []
        for pname, param in sig.parameters.items():
            if skip_self and pname == "self":
                continue
            if param.kind is inspect.Parameter.POSITIONAL_ONLY:
                raise TypeError(
                    f"{self.device_type}.{ex.name} cannot expose positional-only "
                    f"parameter {pname!r}"
                )
            if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                raise TypeError(
                    f"{self.device_type}.{ex.name} cannot be exposed with "
                    f"{param.kind.description} parameter {pname!r}"
                )

            item = {
                "name": pname,
                "required": param.default is inspect.Parameter.empty,
                "type": self._annotation_name(param.annotation),
                "kind": (
                    "keyword_only"
                    if param.kind is inspect.Parameter.KEYWORD_ONLY
                    else "positional_or_keyword"
                ),
            }
            if param.default is not inspect.Parameter.empty:
                item["default"] = self._json_default(ex, pname, param.default)
            args.append(item)
        return args

    @staticmethod
    def _annotation_name(annotation: Any) -> str:
        if annotation is inspect.Parameter.empty:
            return "any"
        if isinstance(annotation, str):
            return annotation
        name = getattr(annotation, "__name__", None)
        if name:
            return str(name)
        return str(annotation).replace("typing.", "")

    def _json_default(self, ex: "_Exposed", pname: str, value: Any) -> Any:
        try:
            json.dumps(value)
            return value
        except TypeError as exc:
            raise TypeError(
                f"{self.device_type}.{ex.name} default for {pname!r} is not JSON serializable"
            ) from exc

    def _bind_exposed_args(
        self,
        ex: "_Exposed",
        args: dict,
        *,
        allow_value_alias: bool,
        allow_first_arg: bool = False,
    ) -> dict:
        sig = inspect.signature(ex.fn)
        bound = {}
        params = [
            (pname, param)
            for pname, param in sig.parameters.items()
            if pname != "self"
        ]

        for pname, param in params:
            if param.kind is inspect.Parameter.POSITIONAL_ONLY:
                raise TypeError(
                    f"{self.device_type}.{ex.name} cannot be dispatched with "
                    f"positional-only parameter {pname!r}"
                )
            if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                raise TypeError(
                    f"{self.device_type}.{ex.name} cannot be dispatched with "
                    f"{param.kind.description} parameter {pname!r}"
                )

            if pname in args:
                bound[pname] = args[pname]
            elif allow_value_alias and len(params) == 1 and "value" in args:
                bound[pname] = args["value"]
            elif allow_first_arg and len(params) == 1 and args:
                first_key = next(iter(args))
                bound[pname] = args[first_key]
            elif param.default is inspect.Parameter.empty:
                raise TypeError(f"missing required argument {pname!r} for {ex.name}")

        return bound

    def dispatch(self, method_name: str, args: dict) -> Any:
        ex = self._exposed.get(method_name)
        if ex is None:
            raise KeyError(
                f"'{method_name}' is not exposed on {self.device_type}. "
                f"Available: {list(self._exposed.keys())}"
            )

        if self.device is None:
            raise RuntimeError(f"no device bound to {self.device_type} schema")

        if ex.kind == "get":
            return ex.fn(self)

        if ex.kind == "set":
            call_args = self._bind_exposed_args(
                ex,
                args,
                allow_value_alias=True,
                allow_first_arg=True,
            )
            if not call_args:
                raise TypeError(f"missing required setter value for {ex.name}")
            return ex.fn(self, **call_args)

        if ex.kind == "call":
            call_args = self._bind_exposed_args(ex, args, allow_value_alias=True)
            return ex.fn(self, **call_args)

        raise ValueError(f"unknown kind '{ex.kind}' on {method_name}")

    def list_exposed(self) -> dict:
        by_kind: Dict[str, list] = {"get": [], "set": [], "call": []}
        for name, ex in sorted(self._exposed.items()):
            by_kind.get(ex.kind, []).append(name)
        return {
            "device_type": self.device_type,
            "driver_version": self.driver_version,
            "connected": self.is_connected(),
            "getters": by_kind["get"],
            "setters": by_kind["set"],
            "calls": by_kind["call"],
        }

    def get_capabilities(self) -> Dict[str, str]:
        caps: Dict[str, str] = {}

        for name, ex in sorted(self._exposed.items()):
            prop = self._capability_name(name=name, kind=ex.kind)
            if not prop:
                continue

            if ex.kind == "get":
                caps[prop] = "rw" if caps.get(prop) == "w" else "r"
                continue

            if ex.kind == "set":
                caps[prop] = "rw" if caps.get(prop) == "r" else "w"
                continue

            caps[prop] = self._call_capability(ex.fn)

        return caps

    def get_capabilities_string(self) -> str:
        return ",".join(
            f"{name}:{mode}"
            for name, mode in sorted(self.get_capabilities().items())
        )

    @staticmethod
    def _capability_name(*, name: str, kind: str) -> str:
        prefixes = {
            "get": "get_",
            "set": "set_",
            "call": "call_",
        }
        prefix = prefixes.get(kind, "")
        if prefix and name.startswith(prefix):
            return name[len(prefix):]
        return name

    @staticmethod
    def _call_capability(fn) -> str:
        sig = inspect.signature(fn)
        params = [
            p
            for p in sig.parameters.values()
            if p.name != "self"
            and p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
        ]
        argc = len(params)
        if argc <= 0:
            return "call0"
        if (
            argc == 1
            and params[0].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
            and params[0].default is inspect.Parameter.empty
        ):
            return "call1"
        return "calln"

    def __repr__(self) -> str:
        return f"<{type(self).__name__} type={self.device_type!r} connected={self.is_connected()}>"


class _Exposed:
    __slots__ = ("name", "fn", "kind", "doc")

    def __init__(self, *, name, fn, kind, doc):
        self.name = name
        self.fn = fn
        self.kind = kind
        self.doc = doc
