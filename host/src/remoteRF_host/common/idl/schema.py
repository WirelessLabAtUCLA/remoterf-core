# src/remoteRF_host/common/idl/schema.py
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import keyword
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

from ..utils.db_location import get_drivers_dir

_EXPOSE_KEY = "__idl__"
_CLIENT_MODULE_PREFIX = "remoteRF.drivers.support."
_CLIENT_CTOR_SENTINELS = {"$self", "$result"}
_CLIENT_OBJECT_KINDS = {
    "module",
    "namespace",
    "payload_class",
    "strict_class",
    "proxy_class",
    "enum",
    "function",
    "method",
}
_CLIENT_FUNCTION_TEMPLATES = {
    "uhd_payload",
    "uhd_get_rx_stream",
    "uhd_get_tx_stream",
    "uhd_close_all_streams",
    "uhd_streamer",
    "uhd_tune_request",
    "uhd_subdev_spec",
}
_CLIENT_METHOD_TEMPLATES = {
    "payload_as_payload",
    "timespec_get_real_secs",
    "timespec_get_full_secs",
    "timespec_get_frac_secs",
    "timespec_to_ticks",
    "timespec_get_tick_count",
    "timespec_float",
    "metadata_update",
    "metadata_strerror",
    "streamer_get_max_num_samps",
    "streamer_issue_stream_cmd",
    "streamer_close",
    "rx_streamer_recv",
    "tx_streamer_send",
}
_CLIENT_INIT_TEMPLATES = {
    "timespec",
    "stream_args",
    "stream_cmd",
    "rx_metadata",
    "tx_metadata",
    "streamer_handle",
}
_CLIENT_OPERATOR_TEMPLATES = {"timespec_numeric"}


def _valid_identifier(value: str) -> bool:
    return value.isidentifier() and not keyword.iskeyword(value)


def _valid_dotted_identifier(value: str) -> bool:
    return all(_valid_identifier(part) for part in value.split("."))


def _json_checked(value: Any, *, label: str) -> Any:
    try:
        json.dumps(value)
    except TypeError as exc:
        raise TypeError(f"{label} is not JSON serializable") from exc
    return value


def idl_client_ctor(target: str, *args: Any) -> dict:
    target = str(target).strip()
    if not target or not _valid_dotted_identifier(target):
        raise ValueError(f"client constructor target must be a dotted identifier: {target!r}")

    checked_args = []
    for index, arg in enumerate(args):
        label = f"client constructor arg {index}"
        if isinstance(arg, str) and arg.startswith("$"):
            if arg not in _CLIENT_CTOR_SENTINELS:
                raise ValueError(
                    f"{label} uses unsupported sentinel {arg!r}; "
                    f"supported: {sorted(_CLIENT_CTOR_SENTINELS)}"
                )
            checked_args.append(arg)
            continue

        if isinstance(arg, dict):
            if set(arg.keys()) != {"const"}:
                raise ValueError(f"{label} dict must be exactly {{'const': value}}")
            checked_args.append({"const": _json_checked(arg["const"], label=label)})
            continue

        raise ValueError(
            f"{label} must be '$self', '$result', or {{'const': json_safe_value}}"
        )

    return {
        "kind": "constructor",
        "target": target,
        "args": checked_args,
    }


def _normal_client_members(members: Any, *, label: str) -> dict:
    if not isinstance(members, dict):
        raise TypeError(f"{label} members must be a dict")
    out = {}
    for name, spec in members.items():
        name = str(name).strip()
        if not _valid_identifier(name):
            raise ValueError(f"{label} member {name!r} must be a valid Python identifier")
        if not isinstance(spec, dict):
            raise TypeError(f"{label}.{name} must be a client object metadata dict")
        out[name] = spec
    return out


def _normal_client_fields(fields: Any, *, label: str) -> list:
    if isinstance(fields, dict):
        raw_fields = []
        for name, meta in fields.items():
            if meta is None:
                meta = {}
            if not isinstance(meta, dict):
                raise TypeError(f"{label} field {name!r} metadata must be a dict")
            raw_fields.append({"name": name, **meta})
    elif isinstance(fields, (list, tuple)):
        raw_fields = []
        for item in fields:
            if isinstance(item, str):
                raw_fields.append({"name": item})
            elif isinstance(item, dict):
                raw_fields.append(dict(item))
            else:
                raise TypeError(f"{label} fields entries must be strings or dicts")
    else:
        raise TypeError(f"{label} fields must be a dict or list")

    out = []
    for item in raw_fields:
        name = str(item.get("name", "")).strip()
        if not _valid_identifier(name):
            raise ValueError(f"{label} field {name!r} must be a valid Python identifier")
        normalized = dict(item)
        normalized["name"] = name
        _json_checked(normalized, label=f"{label}.{name}")
        out.append(normalized)
    return out


def _normal_template(value: Any, *, label: str, allowed: set):
    if value in (None, ""):
        return None
    if isinstance(value, str):
        value = {"template": value}
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be a template string or dict")
    template = str(value.get("template", "")).strip()
    if template not in allowed:
        raise ValueError(f"{label} uses unknown template {template!r}")
    out = dict(value)
    out["template"] = template
    _json_checked(out, label=label)
    return out


def _normal_methods(methods: Any, *, label: str) -> list:
    if methods in (None, ""):
        return []
    if not isinstance(methods, (list, tuple)):
        raise TypeError(f"{label} methods must be a list")
    out = []
    for index, method in enumerate(methods):
        if not isinstance(method, dict):
            raise TypeError(f"{label} methods[{index}] must be a dict")
        out.append(idl_client_method(method.get("template"), **dict(method.get("options") or {})))
    return out


def _normal_operators(operators: Any, *, label: str) -> list:
    if operators in (None, ""):
        return []
    if not isinstance(operators, (list, tuple)):
        raise TypeError(f"{label} operators must be a list")
    out = []
    for operator in operators:
        operator = str(operator).strip()
        if operator not in _CLIENT_OPERATOR_TEMPLATES:
            raise ValueError(f"{label} uses unknown operator template {operator!r}")
        out.append(operator)
    return out


def idl_client_module(members: dict, *, exports=None, bind_client_class_to=None) -> dict:
    metadata = {
        "kind": "module",
        "members": _normal_client_members(members, label="client module"),
    }
    if exports is not None:
        if not isinstance(exports, (list, tuple)):
            raise TypeError("client module exports must be a list")
        normalized_exports = []
        for export in exports:
            export = str(export).strip()
            if not _valid_identifier(export):
                raise ValueError(f"client module export {export!r} must be a valid identifier")
            normalized_exports.append(export)
        metadata["exports"] = normalized_exports
    if bind_client_class_to is not None:
        bind_path = str(bind_client_class_to).strip()
        if not bind_path or not _valid_dotted_identifier(bind_path):
            raise ValueError("client module bind_client_class_to must be a dotted identifier")
        metadata["bind_client_class_to"] = bind_path
    return metadata


def idl_client_namespace(members: dict) -> dict:
    return {
        "kind": "namespace",
        "members": _normal_client_members(members, label="client namespace"),
    }


def idl_client_payload_class(
    payload_type: str,
    fields: Any,
    *,
    init: Any = None,
    methods: Any = None,
    operators: Any = None,
) -> dict:
    payload_type = str(payload_type).strip()
    if not payload_type:
        raise ValueError("client payload class payload_type is required")
    metadata = {
        "kind": "payload_class",
        "payload_type": payload_type,
        "fields": _normal_client_fields(fields, label=f"client payload class {payload_type}"),
    }
    init_spec = _normal_template(
        init,
        label=f"client payload class {payload_type} init",
        allowed=_CLIENT_INIT_TEMPLATES,
    )
    if init_spec is not None:
        metadata["init"] = init_spec
    method_specs = _normal_methods(methods, label=f"client payload class {payload_type}")
    if method_specs:
        metadata["methods"] = method_specs
    operator_specs = _normal_operators(operators, label=f"client payload class {payload_type}")
    if operator_specs:
        metadata["operators"] = operator_specs
    return metadata


def idl_client_strict_class(
    fields: Any,
    *,
    defaults=None,
    init: Any = None,
    methods: Any = None,
) -> dict:
    metadata = {
        "kind": "strict_class",
        "fields": _normal_client_fields(fields, label="client strict class"),
    }
    if defaults:
        if not isinstance(defaults, dict):
            raise TypeError("client strict class defaults must be a dict")
        metadata["defaults"] = _json_checked(defaults, label="client strict class defaults")
    init_spec = _normal_template(
        init,
        label="client strict class init",
        allowed=_CLIENT_INIT_TEMPLATES,
    )
    if init_spec is not None:
        metadata["init"] = init_spec
    method_specs = _normal_methods(methods, label="client strict class")
    if method_specs:
        metadata["methods"] = method_specs
    return metadata


def idl_client_proxy_class(fields: Any, *, init: Any = None, methods: Any = None) -> dict:
    metadata = {
        "kind": "proxy_class",
        "fields": _normal_client_fields(fields, label="client proxy class"),
    }
    init_spec = _normal_template(
        init,
        label="client proxy class init",
        allowed=_CLIENT_INIT_TEMPLATES,
    )
    if init_spec is not None:
        metadata["init"] = init_spec
    method_specs = _normal_methods(methods, label="client proxy class")
    if method_specs:
        metadata["methods"] = method_specs
    return metadata


def idl_client_enum(values) -> dict:
    if not isinstance(values, (list, tuple)):
        raise TypeError("client enum values must be a list")
    out = []
    for value in values:
        value = str(value).strip()
        if not _valid_identifier(value):
            raise ValueError(f"client enum value {value!r} must be a valid identifier")
        out.append(value)
    return {"kind": "enum", "values": out}


def idl_client_function(template: str, **options: Any) -> dict:
    spec = _normal_template(
        {"template": template, "options": _json_checked(options, label="client function options")},
        label="client function",
        allowed=_CLIENT_FUNCTION_TEMPLATES,
    )
    return {"kind": "function", **spec}


def idl_client_method(template: str, **options: Any) -> dict:
    spec = _normal_template(
        {"template": template, "options": _json_checked(options, label="client method options")},
        label="client method",
        allowed=_CLIENT_METHOD_TEMPLATES,
    )
    return {"kind": "method", **spec}


def idl_expose(_fn=None, *, kind: str = "call", doc: str = "", client_return: Any = None):
    def _apply(fn):
        if kind not in {"get", "set", "call"}:
            raise ValueError(f"idl_expose kind must be 'get', 'set', or 'call': {kind!r}")
        if kind == "set" and client_return is not None:
            raise ValueError("idl_expose client_return is only supported for getters and calls")
        meta = {
            "kind": kind,
            "doc": doc or (fn.__doc__ or "").strip(),
            "client_return": client_return,
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


idl_client = SimpleNamespace(
    ctor=idl_client_ctor,
    enum=idl_client_enum,
    function=idl_client_function,
    method=idl_client_method,
    module=idl_client_module,
    namespace=idl_client_namespace,
    payload_class=idl_client_payload_class,
    proxy_class=idl_client_proxy_class,
    strict_class=idl_client_strict_class,
)


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
    v2_mod = sys.modules.get(f"{__package__}.v2")
    if v2_mod is not None:
        sys.modules["remoteRF_server.common.idl.v2"] = v2_mod

    setattr(server_pkg, "common", common_pkg)
    setattr(common_pkg, "idl", idl_pkg)
    setattr(idl_pkg, "schema", schema_mod)

    # Server-authored USRP schema files are intentionally portable to HostRF.
    # Alias their pinned, hardware-independent manifest to the host package so
    # a shared ~/.config/remoterf/drivers directory works in either process.
    try:
        host_drivers = importlib.import_module("remoteRF_host.drivers")
        host_usrp = importlib.import_module("remoteRF_host.drivers.usrp")
        host_manifest = importlib.import_module(
            "remoteRF_host.drivers.usrp.uhd_manifest"
        )
    except Exception:
        pass
    else:
        sys.modules["remoteRF_server.drivers"] = host_drivers
        sys.modules["remoteRF_server.drivers.usrp"] = host_usrp
        sys.modules["remoteRF_server.drivers.usrp.uhd_manifest"] = host_manifest
        setattr(server_pkg, "drivers", host_drivers)
        setattr(host_drivers, "usrp", host_usrp)
        setattr(host_usrp, "uhd_manifest", host_manifest)


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
                    client_return=meta.get("client_return"),
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
            if ex.client_return is not None:
                entry["client_return"] = self._client_return_metadata(ex, ex.client_return)
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
            body["client_class"] = self._client_class_metadata(client_class)

        client_modules = getattr(self, "client_modules", None)
        client_module_roots = set()
        if client_modules:
            body["client_modules"] = self._client_modules_metadata(client_modules)
            client_module_roots = set(body["client_modules"])

        client_objects = getattr(self, "client_objects", None)
        client_object_roots = set()
        if client_objects:
            body["client_objects"] = self._client_objects_metadata(client_objects)
            self._validate_client_object_symbols(body["client_objects"])
            client_object_roots = set(body["client_objects"])
            overlap = client_module_roots & set(body["client_objects"])
            if overlap:
                joined = ", ".join(sorted(overlap))
                raise ValueError(
                    f"{self.device_type}.client_objects duplicates client_modules roots: {joined}"
                )

        self._validate_client_return_roots(body, client_module_roots | client_object_roots)

        return body

    def _client_modules_metadata(self, value: Any) -> dict:
        if not isinstance(value, dict):
            raise TypeError(f"{self.device_type}.client_modules must be a dict")

        out = {}
        for alias, module_path in value.items():
            alias = str(alias).strip()
            module_path = str(module_path).strip()
            if not _valid_identifier(alias):
                raise ValueError(
                    f"{self.device_type}.client_modules alias {alias!r} "
                    "must be a valid Python identifier"
                )
            if (
                not module_path.startswith(_CLIENT_MODULE_PREFIX)
                or not _valid_dotted_identifier(module_path)
            ):
                raise TypeError(
                    f"{self.device_type}.client_modules[{alias!r}] must be a dotted "
                    f"module path under {_CLIENT_MODULE_PREFIX!r}"
                )
            out[alias] = module_path
        return out

    def _client_class_metadata(self, value: Any) -> str:
        client_class = str(value).strip()
        if not _valid_identifier(client_class):
            raise ValueError(
                f"{self.device_type}.client_class must be a valid Python identifier"
            )
        return client_class

    def _client_objects_metadata(self, value: Any) -> dict:
        if not isinstance(value, dict):
            raise TypeError(f"{self.device_type}.client_objects must be a dict")

        out = {}
        for alias, spec in value.items():
            alias = str(alias).strip()
            if not _valid_identifier(alias):
                raise ValueError(
                    f"{self.device_type}.client_objects alias {alias!r} "
                    "must be a valid Python identifier"
                )
            out[alias] = self._client_object_metadata(
                spec,
                path=f"{self.device_type}.client_objects[{alias!r}]",
                root=True,
            )
        return out

    def _client_object_metadata(self, spec: Any, *, path: str, root: bool = False) -> dict:
        if not isinstance(spec, dict):
            raise TypeError(f"{path} must be a client object metadata dict")
        kind = str(spec.get("kind", "")).strip()
        if kind not in _CLIENT_OBJECT_KINDS:
            raise ValueError(f"{path} has unknown client object kind {kind!r}")
        if root and kind != "module":
            raise ValueError(f"{path} must be a client module")
        if not root and kind == "module":
            raise ValueError(f"{path} cannot be a nested client module")

        if kind in {"module", "namespace"}:
            members = spec.get("members", {})
            if not isinstance(members, dict):
                raise TypeError(f"{path}.members must be a dict")
            normalized_members = {}
            for name, member in members.items():
                name = str(name).strip()
                if not _valid_identifier(name):
                    raise ValueError(f"{path}.members key {name!r} must be a valid identifier")
                normalized_members[name] = self._client_object_metadata(
                    member,
                    path=f"{path}.{name}",
                )
            out = {"kind": kind, "members": normalized_members}
            if kind == "module":
                exports = spec.get("exports", [])
                if exports:
                    if not isinstance(exports, list):
                        raise TypeError(f"{path}.exports must be a list")
                    checked_exports = []
                    for export in exports:
                        export = str(export).strip()
                        if not _valid_identifier(export):
                            raise ValueError(f"{path}.exports contains invalid identifier {export!r}")
                        if export not in normalized_members:
                            raise ValueError(f"{path}.exports references unknown member {export!r}")
                        checked_exports.append(export)
                    out["exports"] = checked_exports
                bind_path = spec.get("bind_client_class_to")
                if bind_path:
                    bind_path = str(bind_path).strip()
                    if not _valid_dotted_identifier(bind_path):
                        raise ValueError(f"{path}.bind_client_class_to must be a dotted identifier")
                    self._validate_client_bind_path(
                        bind_path,
                        normalized_members,
                        path=f"{path}.bind_client_class_to",
                    )
                    out["bind_client_class_to"] = bind_path
            return self._json_checked_metadata(path, out)

        if kind in {"payload_class", "strict_class", "proxy_class"}:
            fields = spec.get("fields", [])
            if not isinstance(fields, list):
                raise TypeError(f"{path}.fields must be a list")
            checked_fields = []
            for field in fields:
                if not isinstance(field, dict):
                    raise TypeError(f"{path}.fields entries must be dicts")
                name = str(field.get("name", "")).strip()
                if not _valid_identifier(name):
                    raise ValueError(f"{path}.fields contains invalid name {name!r}")
                checked_fields.append(dict(field, name=name))

            out = {"kind": kind, "fields": checked_fields}
            if kind == "payload_class":
                payload_type = str(spec.get("payload_type", "")).strip()
                if not payload_type:
                    raise ValueError(f"{path}.payload_type is required")
                out["payload_type"] = payload_type

            init = spec.get("init")
            if init is not None:
                out["init"] = self._client_template_metadata(
                    init,
                    path=f"{path}.init",
                    allowed=_CLIENT_INIT_TEMPLATES,
                )
            methods = spec.get("methods", [])
            if methods:
                if not isinstance(methods, list):
                    raise TypeError(f"{path}.methods must be a list")
                out["methods"] = [
                    self._client_object_metadata(method, path=f"{path}.methods[{index}]")
                    for index, method in enumerate(methods)
                ]
            operators = spec.get("operators", [])
            if operators:
                if not isinstance(operators, list):
                    raise TypeError(f"{path}.operators must be a list")
                checked_operators = []
                for operator in operators:
                    operator = str(operator).strip()
                    if operator not in _CLIENT_OPERATOR_TEMPLATES:
                        raise ValueError(f"{path}.operators contains unknown template {operator!r}")
                    checked_operators.append(operator)
                out["operators"] = checked_operators
            if "defaults" in spec:
                if not isinstance(spec["defaults"], dict):
                    raise TypeError(f"{path}.defaults must be a dict")
                out["defaults"] = spec["defaults"]
            return self._json_checked_metadata(path, out)

        if kind == "enum":
            values = spec.get("values", [])
            if not isinstance(values, list):
                raise TypeError(f"{path}.values must be a list")
            checked_values = []
            for value in values:
                value = str(value).strip()
                if not _valid_identifier(value):
                    raise ValueError(f"{path}.values contains invalid identifier {value!r}")
                checked_values.append(value)
            return {"kind": "enum", "values": checked_values}

        if kind == "function":
            return {
                "kind": "function",
                **self._client_template_metadata(
                    spec,
                    path=path,
                    allowed=_CLIENT_FUNCTION_TEMPLATES,
                ),
            }

        if kind == "method":
            return {
                "kind": "method",
                **self._client_template_metadata(
                    spec,
                    path=path,
                    allowed=_CLIENT_METHOD_TEMPLATES,
                ),
            }

        raise ValueError(f"{path} has unsupported client object kind {kind!r}")

    def _client_template_metadata(self, spec: Any, *, path: str, allowed: set) -> dict:
        if not isinstance(spec, dict):
            raise TypeError(f"{path} must be a template metadata dict")
        template = str(spec.get("template", "")).strip()
        if template not in allowed:
            raise ValueError(f"{path} uses unknown template {template!r}")
        out = {"template": template}
        options = spec.get("options", {})
        if options:
            if not isinstance(options, dict):
                raise TypeError(f"{path}.options must be a dict")
            out["options"] = options
        return self._json_checked_metadata(path, out)

    def _json_checked_metadata(self, path: str, value: Any) -> Any:
        try:
            json.dumps(value)
            return value
        except TypeError as exc:
            raise TypeError(f"{path} is not JSON serializable") from exc

    def _validate_client_bind_path(self, bind_path: str, members: dict, *, path: str) -> None:
        current_members = members
        for part in bind_path.split("."):
            target = current_members.get(part)
            if target is None:
                raise ValueError(f"{path} references unknown member {part!r}")
            kind = target.get("kind")
            if kind != "namespace":
                raise ValueError(f"{path} must reference a client namespace")
            current_members = target.get("members", {})

    def _validate_client_object_symbols(self, client_objects: dict) -> None:
        seen = {}

        def walk(spec: dict, path: str) -> None:
            for name, member in spec.get("members", {}).items():
                kind = member.get("kind")
                child_path = f"{path}.{name}"
                if kind == "namespace":
                    walk(member, child_path)
                    continue
                if kind == "module":
                    raise ValueError(f"{child_path} cannot be a nested client module")
                previous = seen.get(name)
                if previous is not None:
                    raise ValueError(
                        f"{child_path} duplicates generated client object name "
                        f"{name!r}; already declared at {previous}"
                    )
                seen[name] = child_path

        for alias, spec in client_objects.items():
            walk(spec, f"{self.device_type}.client_objects[{alias!r}]")

    def _validate_client_return_roots(self, body: dict, roots: set) -> None:
        for section_name in ("getters", "calls"):
            for name, entry in body.get(section_name, {}).items():
                client_return = entry.get("client_return")
                if not client_return:
                    continue
                target = str(client_return.get("target", "")).strip()
                root = target.split(".", 1)[0]
                if root not in roots:
                    raise ValueError(
                        f"{self.device_type}.{name} client_return target root {root!r} "
                        "is not declared in client_modules or client_objects"
                    )

    def _client_return_metadata(self, ex: "_Exposed", value: Any) -> dict:
        if not isinstance(value, dict):
            raise TypeError(f"{self.device_type}.{ex.name} client_return must be a dict")
        if value.get("kind") != "constructor":
            raise ValueError(
                f"{self.device_type}.{ex.name} client_return kind must be 'constructor'"
            )

        target = str(value.get("target", "")).strip()
        if not target or not _valid_dotted_identifier(target):
            raise ValueError(
                f"{self.device_type}.{ex.name} client_return target must be a dotted identifier"
            )

        args = value.get("args", [])
        if not isinstance(args, list):
            raise TypeError(f"{self.device_type}.{ex.name} client_return args must be a list")

        normalized = idl_client_ctor(target, *args)
        return self._json_metadata(ex, "client_return", normalized)

    def _json_metadata(self, ex: "_Exposed", field: str, value: Any) -> Any:
        try:
            json.dumps(value)
            return value
        except TypeError as exc:
            raise TypeError(
                f"{self.device_type}.{ex.name} {field} is not JSON serializable"
            ) from exc

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
    __slots__ = ("name", "fn", "kind", "doc", "client_return")

    def __init__(self, *, name, fn, kind, doc, client_return):
        self.name = name
        self.fn = fn
        self.kind = kind
        self.doc = doc
        self.client_return = client_return
