# src/remoteRF_server/common/idl/schema.py
"""
IDL Schema framework.

Admin writes one .py per device TYPE, drops it in ~/.config/remoterf/drivers/,
and the server auto-discovers it on startup via load_drivers().

    ~/.config/remoterf/
        devices.env                 ← "I have 3 plutos at these serials"
        drivers/
            pluto_schema.py         ← "here's what a pluto IS"
            hackrf_schema.py
            webcam_schema.py

The admin's schema file:
    1. Imports from this module
    2. Subclasses DeviceSchema
    3. Decorates with @register_driver("pluto")
    4. Implements make_device(**kwargs) — factory from manifest config
    5. Decorates exposed methods with @idl_expose(kind="get"|"set"|"call")

That's it. The server never needs to be modified.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from ..utils import *

# ───────────────────────────────────────────────────────────────────
# @idl_expose decorator
# ───────────────────────────────────────────────────────────────────

_EXPOSE_KEY = "__idl__"

def idl_expose(_fn=None, *, kind: str = "call", doc: str = ""):
    """
    Mark a method as exposed over IDL.

        @idl_expose(kind="get")
        def get_tx_lo(self):
            return self.device.tx_lo

        @idl_expose(kind="set")
        def set_tx_lo(self, value):
            self.device.tx_lo = value

        @idl_expose(kind="call")
        def call_rx(self):
            return self.device.rx()

        @idl_expose                     # bare — defaults to kind="call"
        def some_method(self, x):
            ...

    kind:
        "get"  — property getter (no args beyond self)
        "set"  — property setter (one arg: value)
        "call" — general method (any args)
    """
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


# ───────────────────────────────────────────────────────────────────
# Driver registry
# ───────────────────────────────────────────────────────────────────

_DRIVER_REGISTRY: Dict[str, type] = {}

def register_driver(device_type: str):
    """
    Class decorator — registers a schema so the server can find it by type string.

        @register_driver("pluto")
        class PlutoSchema(DeviceSchema):
            ...
    """
    def decorator(cls):
        key = device_type.strip().lower()
        _DRIVER_REGISTRY[key] = cls
        return cls
    return decorator

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

# ───────────────────────────────────────────────────────────────────
# Plugin loader — auto-discover driver schemas from a folder
# ───────────────────────────────────────────────────────────────────

def load_drivers() -> Dict[str, str]:
    """
    Import every .py in the drivers config dir.  Each file's @idl_register
    decorator self-registers into the global registry.

    Returns {filename: status} for logging.

    Called once at server startup:
        load_drivers()
    """
    drivers_dir = get_drivers_dir()
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
            # Make our module importable from inside the driver file
            # so `from schema import ...` works even when loaded as a plugin
            sys.modules[f.stem] = mod
            spec.loader.exec_module(mod)
            results[f.name] = "ok"
        except Exception as e:
            results[f.name] = f"error: {e}"

    return results


# ───────────────────────────────────────────────────────────────────
# DeviceSchema base class
# ───────────────────────────────────────────────────────────────────

class DeviceSchema:
    """
    Base for all device schemas.  Admin subclasses this once per device type.

    Class attributes (admin sets these):
        device_type      str   — must match the TYPE in devices.env
        driver_version   str   — semver

    Admin implements:
        make_device(**kwargs)  — factory: manifest config → live device handle
                                 returns the device object, or None on failure

    Admin decorates exposed methods with @idl_expose(kind=...).

    The server calls:
        schema = PlutoSchema()
        dev = schema.make_device(serial="00000001")
        schema.device = dev                 # or schema.bind(dev)
        schema.dispatch("get_tx_lo", {})    # → calls get_tx_lo()
    """

    device_type: str = ""
    driver_version: str = ""

    def __init__(self):
        self.device = None                      # set after make_device()
        self._exposed: Dict[str, _Exposed] = {}
        self._schema_cache: dict | None = None
        self._hash_cache: str | None = None
        self._introspect()

    # ── Factory (admin overrides) ─────────────────────────────────

    @staticmethod
    def make_device(**kwargs):
        """
        Create and return a live device handle using kwargs from the manifest.
        Admin MUST override this.
        """
        raise NotImplementedError("make_device() must be implemented in the schema")

    # ── Bind device to schema instance ────────────────────────────

    def bind(self, device) -> None:
        """Attach a live device handle so exposed methods can use self.device."""
        self.device = device

    def is_connected(self) -> bool:
        return self.device is not None

    # ── Introspection ─────────────────────────────────────────────

    def _introspect(self):
        seen: set = set()
        for klass in type(self).__mro__:
            for name, obj in vars(klass).items():
                if name in seen or name.startswith("_"):
                    continue
                meta = getattr(obj, _EXPOSE_KEY, None)
                if meta is None:
                    continue
                seen.add(name)
                self._exposed[name] = _Exposed(
                    name=name, fn=obj, kind=meta["kind"], doc=meta["doc"],
                )

    # ── IDL generation ────────────────────────────────────────────

    def get_idl(self) -> dict:
        """Full wire-ready schema dict with content-addressed hash."""
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
        return self._hash_cache  # type: ignore

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

    # ── Dispatch (server RPC layer calls this) ────────────────────

    def dispatch(self, method_name: str, args: dict) -> Any:
        """
        Called by the RPC layer.  Finds the exposed method and calls it.

            dispatch("get_tx_lo", {})               → self.get_tx_lo()
            dispatch("set_tx_lo", {"value": 2.4e9}) → self.set_tx_lo(2.4e9)
            dispatch("call_rx", {})                 → self.call_rx()
            dispatch("call_tx", {"value": samples}) → self.call_tx(samples)
        """
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

        elif ex.kind == "set":
            value = args.get("value")
            if value is None and "value" not in args:
                # Also check first positional-style arg key
                for k, v in args.items():
                    value = v
                    break
            return ex.fn(self, value)

        elif ex.kind == "call":
            # Calls can have 0 or more args
            # Simple convention: if the function takes 'value', pass it
            import inspect
            sig = inspect.signature(ex.fn)
            params = [p for p in sig.parameters if p != "self"]

            if len(params) == 0:
                return ex.fn(self)
            elif len(params) == 1:
                # Single arg — pull from args dict by param name or "value"
                pname = params[0]
                val = args.get(pname, args.get("value"))
                return ex.fn(self, val)
            else:
                # Multi-arg — match by name
                call_args = {p: args.get(p) for p in params if p in args}
                return ex.fn(self, **call_args)
        else:
            raise ValueError(f"unknown kind '{ex.kind}' on {method_name}")

    # ── Debug ─────────────────────────────────────────────────────

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

    def __repr__(self) -> str:
        return f"<{type(self).__name__} type={self.device_type!r} connected={self.is_connected()}>"


# ───────────────────────────────────────────────────────────────────
# Internal
# ───────────────────────────────────────────────────────────────────

class _Exposed:
    __slots__ = ("name", "fn", "kind", "doc")
    def __init__(self, *, name, fn, kind, doc):
        self.name = name
        self.fn = fn
        self.kind = kind
        self.doc = doc