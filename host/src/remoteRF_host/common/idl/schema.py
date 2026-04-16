# src/remoteRF_host/common/idl/schema.py
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import sys
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


def load_drivers() -> Dict[str, str]:
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
                setters[name] = entry
            elif ex.kind == "call":
                calls[name] = entry

        return {
            "schema_version": "1.0",
            "device_type": self.device_type,
            "driver_version": self.driver_version,
            "getters": getters,
            "setters": setters,
            "calls": calls,
        }

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
            value = args.get("value")
            if value is None and "value" not in args:
                for _, v in args.items():
                    value = v
                    break
            return ex.fn(self, value)

        if ex.kind == "call":
            sig = inspect.signature(ex.fn)
            params = [p for p in sig.parameters if p != "self"]

            if len(params) == 0:
                return ex.fn(self)
            if len(params) == 1:
                pname = params[0]
                val = args.get(pname, args.get("value"))
                return ex.fn(self, val)

            call_args = {p: args.get(p) for p in params if p in args}
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
            if p.name != "self" and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        argc = len(params)
        if argc <= 0:
            return "call0"
        if argc == 1:
            return "call1"
        return f"call{argc}"

    def __repr__(self) -> str:
        return f"<{type(self).__name__} type={self.device_type!r} connected={self.is_connected()}>"


class _Exposed:
    __slots__ = ("name", "fn", "kind", "doc")

    def __init__(self, *, name, fn, kind, doc):
        self.name = name
        self.fn = fn
        self.kind = kind
        self.doc = doc
