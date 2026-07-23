"""Declarative Dynamic IDL v2 helpers.

V2 is additive to :mod:`schema`; v1 schemas and their wire representation are
not translated or modified.  The small builders here intentionally return
plain JSON-safe dictionaries so device manifests can be generated, hashed,
cached, and consumed by clients in other languages.
"""
from __future__ import annotations

import hashlib
import json
import keyword
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = "2.0"
CONTROL_PROTOCOL_VERSION = "2.0"
STREAMING_PROTOCOL_VERSION = "1.0"

OBJECT_KINDS = {"namespace", "value_class", "enum", "remote_handle"}
EXECUTION_KINDS = {
    "client_local",
    "server_control",
    "server_handle",
    "sample_stream",
    "hybrid",
    "server_optimized",
}
MUTABILITY_KINDS = {"immutable", "value", "inout", "remote_handle"}
PARAMETER_DIRECTIONS = {"in", "out", "inout"}
PARAMETER_KINDS = {
    "positional_only",
    "positional_or_keyword",
    "var_positional",
    "keyword_only",
    "var_keyword",
}


def _json_safe(value: Any, label: str) -> Any:
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{label} must be JSON serializable") from exc
    return value


def parameter(
    name: str,
    wire_type: str = "any",
    *,
    kind: str = "positional_or_keyword",
    direction: str = "in",
    required: bool = True,
    default: Any = None,
    ndarray: Mapping[str, Any] | None = None,
) -> dict:
    if kind not in PARAMETER_KINDS:
        raise ValueError(f"unsupported parameter kind: {kind!r}")
    if direction not in PARAMETER_DIRECTIONS:
        raise ValueError(f"unsupported parameter direction: {direction!r}")
    out = {
        "name": str(name),
        "type": str(wire_type),
        "kind": kind,
        "direction": direction,
        "required": bool(required),
    }
    if not required:
        out["default"] = _json_safe(default, f"default for {name}")
    if ndarray is not None:
        out["ndarray"] = _json_safe(dict(ndarray), f"ndarray descriptor for {name}")
    return out


def overload(
    overload_id: str,
    parameters: Iterable[Mapping[str, Any]] = (),
    *,
    returns: str = "None",
    doc: str = "",
) -> dict:
    return {
        "id": str(overload_id),
        "parameters": [dict(item) for item in parameters],
        "returns": str(returns),
        "doc": str(doc),
    }


def method(
    name: str,
    owner: str,
    overloads: Iterable[Mapping[str, Any]],
    *,
    execution: str = "server_control",
    mutations: Iterable[str] = (),
    availability: Mapping[str, Any] | None = None,
    policy: str | None = None,
    doc: str = "",
) -> dict:
    if execution not in EXECUTION_KINDS:
        raise ValueError(f"unsupported execution kind: {execution!r}")
    out = {
        "name": str(name),
        "owner": str(owner),
        "execution": execution,
        "overloads": [dict(item) for item in overloads],
        "mutations": [str(item) for item in mutations],
        "doc": str(doc),
    }
    if availability:
        out["availability"] = _json_safe(dict(availability), f"availability for {name}")
    if policy:
        out["policy"] = str(policy)
    return out


def object_type(
    python_path: str,
    *,
    kind: str,
    aliases: Iterable[str] = (),
    codec: str | None = None,
    mutability: str = "value",
    constructors: Iterable[Mapping[str, Any]] = (),
    fields: Iterable[Mapping[str, Any]] = (),
    methods: Iterable[str] = (),
    ownership: Mapping[str, Any] | None = None,
    values: Iterable[Mapping[str, Any] | str] = (),
) -> dict:
    if kind not in OBJECT_KINDS:
        raise ValueError(f"unsupported object kind: {kind!r}")
    if mutability not in MUTABILITY_KINDS:
        raise ValueError(f"unsupported mutability: {mutability!r}")
    out = {
        "python_path": str(python_path),
        "kind": kind,
        "aliases": [str(item) for item in aliases],
        "mutability": mutability,
        "constructors": [dict(item) for item in constructors],
        "fields": [dict(item) for item in fields],
        "methods": [str(item) for item in methods],
    }
    if codec:
        out["codec"] = str(codec)
    if ownership:
        out["ownership"] = _json_safe(dict(ownership), f"ownership for {python_path}")
    if values:
        out["values"] = [
            dict(item) if isinstance(item, Mapping) else {"name": str(item), "value": str(item)}
            for item in values
        ]
    return out


def build_schema(
    *,
    device_type: str,
    client_class: str,
    driver_version: str,
    native_api: Mapping[str, Any],
    hardware_profiles: Iterable[str],
    objects: Iterable[Mapping[str, Any]],
    methods: Iterable[Mapping[str, Any]],
    errors: Iterable[Mapping[str, Any]],
    capability_fields: Iterable[str],
    coverage: Mapping[str, str],
    deprecations: Iterable[Mapping[str, Any]] = (),
) -> dict:
    body = {
        "schema_version": SCHEMA_VERSION,
        "device_type": str(device_type),
        "client_class": str(client_class),
        "driver_version": str(driver_version),
        "native_api": dict(native_api),
        "hardware_profiles": [str(item) for item in hardware_profiles],
        "protocols": {
            "control": [CONTROL_PROTOCOL_VERSION],
            "streaming": [STREAMING_PROTOCOL_VERSION],
        },
        "objects": [dict(item) for item in objects],
        "methods": [dict(item) for item in methods],
        "errors": [dict(item) for item in errors],
        "capability_fields": [str(item) for item in capability_fields],
        "deprecations": [dict(item) for item in deprecations],
        "coverage": {str(key): str(value) for key, value in coverage.items()},
    }
    validate_schema(body)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["schema_hash"] = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
    return body


def validate_schema(schema: Mapping[str, Any]) -> None:
    if schema.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION!r}")
    device_type = str(schema.get("device_type") or "")
    client_class = str(schema.get("client_class") or "")
    if (
        not device_type.isidentifier()
        or keyword.iskeyword(device_type)
        or not client_class.isidentifier()
        or keyword.iskeyword(client_class)
    ):
        raise ValueError("device_type and client_class must be identifiers")

    object_paths: set[str] = set()
    for entry in schema.get("objects", ()):
        if entry.get("kind") not in OBJECT_KINDS:
            raise ValueError(f"invalid object kind for {entry.get('python_path')!r}")
        path = str(entry.get("python_path") or "")
        if not path or path in object_paths:
            raise ValueError(f"duplicate or missing object python_path: {path!r}")
        if any(
            not part.isidentifier() or keyword.iskeyword(part)
            for part in path.split(".")
        ):
            raise ValueError(f"invalid object python_path: {path!r}")
        for alias in entry.get("aliases", ()):
            if any(
                not part.isidentifier() or keyword.iskeyword(part)
                for part in str(alias).split(".")
            ):
                raise ValueError(f"invalid object alias: {alias!r}")
        object_paths.add(path)

    method_keys: set[tuple[str, str]] = set()
    for entry in schema.get("methods", ()):
        if entry.get("execution") not in EXECUTION_KINDS:
            raise ValueError(f"invalid execution kind for {entry.get('name')!r}")
        key = (str(entry.get("owner") or ""), str(entry.get("name") or ""))
        if not all(key) or key in method_keys:
            raise ValueError(f"duplicate or missing method: {key!r}")
        if (
            any(
                not part.isidentifier() or keyword.iskeyword(part)
                for part in key[0].split(".")
            )
            or not key[1].isidentifier()
            or keyword.iskeyword(key[1])
        ):
            raise ValueError(f"invalid method identifier: {key!r}")
        method_keys.add(key)
        overload_ids: set[str] = set()
        for candidate in entry.get("overloads", ()):
            overload_id = str(candidate.get("id") or "")
            if not overload_id or overload_id in overload_ids:
                raise ValueError(f"duplicate or missing overload id for {key!r}")
            overload_ids.add(overload_id)
            parameter_names: set[str] = set()
            for arg in candidate.get("parameters", ()):
                parameter_name = str(arg.get("name") or "")
                if (
                    not parameter_name.isidentifier()
                    or keyword.iskeyword(parameter_name)
                    or parameter_name in parameter_names
                ):
                    raise ValueError(f"invalid parameter name in {key!r}")
                parameter_names.add(parameter_name)
                if arg.get("kind") not in PARAMETER_KINDS:
                    raise ValueError(f"invalid parameter kind in {key!r}")
                if arg.get("direction") not in PARAMETER_DIRECTIONS:
                    raise ValueError(f"invalid parameter direction in {key!r}")

    coverage = dict(schema.get("coverage") or {})
    valid_coverage = {
        "implemented",
        "implemented_with_documented_remote_difference",
        "unsupported_by_hardware_native_equivalent",
        "policy_disabled",
        "deferred",
    }
    bad = {key: value for key, value in coverage.items() if value not in valid_coverage}
    if bad:
        raise ValueError(f"invalid coverage classifications: {bad!r}")
    _json_safe(dict(schema), "schema")
