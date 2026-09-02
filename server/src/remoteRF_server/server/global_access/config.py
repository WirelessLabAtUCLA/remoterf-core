# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
global.yaml loader/validator.

Follows the same manual-validation style as serverrf_cli.py's devices.yml
handling (yaml.safe_load + explicit ValueError on any structural problem) —
no schema library is introduced.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

DEFAULT_HEARTBEAT_SECONDS = 30
DEFAULT_OFFLINE_SECONDS = 90
DEFAULT_LOCAL_SESSION_MINUTES = 60
SUPPORTED_ROUTE_KINDS = frozenset({"tcp-relay"})
SUPPORTED_VISIBILITIES = frozenset({"public"})


class GlobalConfigError(ValueError):
    """Raised for any structurally or semantically invalid global.yaml."""


def _xdg_config_home() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))


def _cfg_dir() -> Path:
    return Path(os.getenv("REMOTERF_CONFIG_DIR", _xdg_config_home() / "remoterf"))


def default_global_config_path() -> Path:
    override = os.getenv("REMOTERF_GLOBAL_CONFIG_PATH")
    if override:
        return Path(override).expanduser()
    return _cfg_dir() / "global" / "global.yaml"


def default_global_state_dir() -> Path:
    return _cfg_dir() / "global"


def _require_str(d: dict, key: str, *, where: str) -> str:
    if key not in d:
        raise GlobalConfigError(f"{where}: missing required key '{key}'")
    v = d[key]
    if not isinstance(v, str) or not v.strip():
        raise GlobalConfigError(f"{where}: '{key}' must be a non-empty string")
    return v.strip()


def _require_https_url(d: dict, key: str, *, where: str, allow_insecure: bool) -> str:
    v = _require_str(d, key, where=where)
    if v.startswith("https://"):
        return v
    if allow_insecure and v.startswith("http://"):
        return v
    raise GlobalConfigError(
        f"{where}: '{key}' must use https:// (got {v!r})"
    )


def _require_positive_int(d: dict, key: str, *, where: str, default: Optional[int] = None) -> int:
    if key not in d:
        if default is not None:
            return default
        raise GlobalConfigError(f"{where}: missing required key '{key}'")
    try:
        n = int(d[key])
    except (TypeError, ValueError) as exc:
        raise GlobalConfigError(f"{where}: '{key}' must be an integer") from exc
    if n <= 0:
        raise GlobalConfigError(f"{where}: '{key}' must be > 0 (got {n})")
    return n


def _reject_unknown_keys(d: dict, allowed: set, *, where: str) -> None:
    unknown = set(d.keys()) - allowed
    if unknown:
        raise GlobalConfigError(
            f"{where}: unknown key(s) {sorted(unknown)!r} (allowed: {sorted(allowed)!r})"
        )


@dataclass(frozen=True)
class RelayIngressConfig:
    trusted_peer_cidrs: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "RelayIngressConfig":
        if d is None:
            return cls()
        _reject_unknown_keys(d, {"trusted_peer_cidrs"}, where="global.relay_ingress")
        raw = d.get("trusted_peer_cidrs") or []
        if not isinstance(raw, list):
            raise GlobalConfigError("global.relay_ingress.trusted_peer_cidrs must be a list")
        cidrs: list[str] = []
        for entry in raw:
            entry = str(entry).strip()
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise GlobalConfigError(
                    f"global.relay_ingress.trusted_peer_cidrs: invalid CIDR {entry!r}"
                ) from exc
            cidrs.append(entry)
        return cls(trusted_peer_cidrs=tuple(cidrs))


@dataclass(frozen=True)
class RouteConfig:
    kind: str
    grpc_endpoint: str
    certificate_endpoint: str
    tls_server_name: str

    @classmethod
    def from_dict(cls, d: dict) -> "RouteConfig":
        where = "global.route"
        _reject_unknown_keys(
            d,
            {"kind", "grpc_endpoint", "certificate_endpoint", "tls_server_name"},
            where=where,
        )
        kind = _require_str(d, "kind", where=where)
        if kind not in SUPPORTED_ROUTE_KINDS:
            raise GlobalConfigError(
                f"{where}: unsupported kind {kind!r} (supported: {sorted(SUPPORTED_ROUTE_KINDS)!r})"
            )
        grpc_endpoint = _require_str(d, "grpc_endpoint", where=where)
        certificate_endpoint = _require_str(d, "certificate_endpoint", where=where)
        tls_server_name = _require_str(d, "tls_server_name", where=where)
        for label, endpoint in (("grpc_endpoint", grpc_endpoint), ("certificate_endpoint", certificate_endpoint)):
            _reject_internal_endpoint(endpoint, where=f"{where}.{label}")
        return cls(
            kind=kind,
            grpc_endpoint=grpc_endpoint,
            certificate_endpoint=certificate_endpoint,
            tls_server_name=tls_server_name,
        )


def _reject_internal_endpoint(endpoint: str, *, where: str) -> None:
    host = endpoint.rsplit(":", 1)[0].strip("[]")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return  # a hostname, not a literal IP — fine
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        raise GlobalConfigError(
            f"{where}: must not publish an internal address ({host}); "
            "use the public relay hostname instead"
        )


@dataclass(frozen=True)
class ReservationPolicy:
    max_duration_minutes: int
    max_active_reservations: int
    max_daily_minutes: int

    @classmethod
    def from_dict(cls, d: dict, *, where: str) -> "ReservationPolicy":
        _reject_unknown_keys(
            d,
            {"max_duration_minutes", "max_active_reservations", "max_daily_minutes"},
            where=where,
        )
        max_duration = _require_positive_int(d, "max_duration_minutes", where=where)
        max_active = _require_positive_int(d, "max_active_reservations", where=where)
        max_daily = _require_positive_int(d, "max_daily_minutes", where=where)
        if max_daily < max_duration:
            raise GlobalConfigError(
                f"{where}: max_daily_minutes ({max_daily}) must be >= "
                f"max_duration_minutes ({max_duration})"
            )
        return cls(
            max_duration_minutes=max_duration,
            max_active_reservations=max_active,
            max_daily_minutes=max_daily,
        )


@dataclass(frozen=True)
class OperationPolicy:
    default: str
    allow_operations: tuple[str, ...]
    allow_client_sample_upload: bool

    @classmethod
    def from_dict(cls, d: dict, *, where: str) -> "OperationPolicy":
        _reject_unknown_keys(
            d,
            {"default", "allow_operations", "allow_client_sample_upload"},
            where=where,
        )
        default = str(d.get("default", "deny")).strip().lower()
        if default != "deny":
            raise GlobalConfigError(
                f"{where}: 'default' must be 'deny' (fail-closed is mandatory for "
                f"Global public exports); got {default!r}"
            )
        raw_ops = d.get("allow_operations") or []
        if not isinstance(raw_ops, list):
            raise GlobalConfigError(f"{where}: 'allow_operations' must be a list")
        ops: list[str] = []
        for op in raw_ops:
            op = str(op).strip()
            if not op or any(c.isspace() for c in op):
                raise GlobalConfigError(f"{where}: invalid operation identifier {op!r}")
            ops.append(op)
        allow_upload = bool(d.get("allow_client_sample_upload", False))
        return cls(
            default=default,
            allow_operations=tuple(ops),
            allow_client_sample_upload=allow_upload,
        )

    def allows(self, operation: str) -> bool:
        return operation in self.allow_operations


@dataclass(frozen=True)
class ExportConfig:
    local_device_id: str
    display_name: str
    device_type: str
    visibility: str
    reservation_policy: ReservationPolicy
    operation_policy: OperationPolicy

    @classmethod
    def from_dict(cls, d: dict, *, index: int) -> "ExportConfig":
        where = f"global.exports[{index}]"
        _reject_unknown_keys(
            d,
            {
                "local_device_id",
                "display_name",
                "device_type",
                "visibility",
                "reservation_policy",
                "operation_policy",
            },
            where=where,
        )
        local_device_id = _require_str(d, "local_device_id", where=where)
        display_name = _require_str(d, "display_name", where=where)
        device_type = _require_str(d, "device_type", where=where)
        visibility = _require_str(d, "visibility", where=where)
        if visibility not in SUPPORTED_VISIBILITIES:
            raise GlobalConfigError(
                f"{where}: unsupported visibility {visibility!r} "
                f"(supported: {sorted(SUPPORTED_VISIBILITIES)!r})"
            )
        if "reservation_policy" not in d or not isinstance(d["reservation_policy"], dict):
            raise GlobalConfigError(f"{where}: 'reservation_policy' must be a mapping")
        if "operation_policy" not in d or not isinstance(d["operation_policy"], dict):
            raise GlobalConfigError(f"{where}: 'operation_policy' must be a mapping")
        reservation_policy = ReservationPolicy.from_dict(
            d["reservation_policy"], where=f"{where}.reservation_policy"
        )
        operation_policy = OperationPolicy.from_dict(
            d["operation_policy"], where=f"{where}.operation_policy"
        )
        return cls(
            local_device_id=local_device_id,
            display_name=display_name,
            device_type=device_type,
            visibility=visibility,
            reservation_policy=reservation_policy,
            operation_policy=operation_policy,
        )


@dataclass(frozen=True)
class GlobalConfig:
    enabled: bool
    base_url: str
    issuer: str
    jwks_url: str
    deployment_state_path: Path
    deployment_private_key_path: Path
    heartbeat_seconds: int
    offline_seconds: int
    relay_ingress: RelayIngressConfig
    public_group: str
    route: RouteConfig
    exports: tuple[ExportConfig, ...] = field(default_factory=tuple)

    def export_for(self, local_device_id: str) -> Optional[ExportConfig]:
        for export in self.exports:
            if export.local_device_id == str(local_device_id):
                return export
        return None


_TOP_LEVEL_ALLOWED_KEYS = {
    "enabled",
    "base_url",
    "issuer",
    "jwks_url",
    "deployment_state_path",
    "deployment_private_key_path",
    "heartbeat_seconds",
    "offline_seconds",
    "relay_ingress",
    "public_group",
    "route",
    "exports",
}


def parse_global_config(
    data: dict,
    *,
    allow_insecure_transport: bool = False,
) -> GlobalConfig:
    if not isinstance(data, dict):
        raise GlobalConfigError("global.yaml: top-level document must be a mapping")

    section = data.get("global")
    if section is None:
        raise GlobalConfigError("global.yaml: missing top-level 'global' key")
    if not isinstance(section, dict):
        raise GlobalConfigError("global.yaml: 'global' must be a mapping")

    _reject_unknown_keys(section, _TOP_LEVEL_ALLOWED_KEYS, where="global")

    enabled = bool(section.get("enabled", False))
    base_url = _require_https_url(
        section, "base_url", where="global", allow_insecure=allow_insecure_transport
    )
    issuer = _require_https_url(
        section, "issuer", where="global", allow_insecure=allow_insecure_transport
    )
    jwks_url = _require_https_url(
        section, "jwks_url", where="global", allow_insecure=allow_insecure_transport
    )

    deployment_state_path = Path(
        _require_str(section, "deployment_state_path", where="global")
    ).expanduser()
    deployment_private_key_path = Path(
        _require_str(section, "deployment_private_key_path", where="global")
    ).expanduser()

    heartbeat_seconds = _require_positive_int(
        section, "heartbeat_seconds", where="global", default=DEFAULT_HEARTBEAT_SECONDS
    )
    offline_seconds = _require_positive_int(
        section, "offline_seconds", where="global", default=DEFAULT_OFFLINE_SECONDS
    )
    if offline_seconds < heartbeat_seconds:
        raise GlobalConfigError(
            "global: offline_seconds must be >= heartbeat_seconds "
            f"({offline_seconds} < {heartbeat_seconds})"
        )

    relay_ingress = RelayIngressConfig.from_dict(section.get("relay_ingress"))
    public_group = _require_str(section, "public_group", where="global")

    if "route" not in section or not isinstance(section["route"], dict):
        raise GlobalConfigError("global: 'route' must be a mapping")
    route = RouteConfig.from_dict(section["route"])

    raw_exports = section.get("exports") or []
    if not isinstance(raw_exports, list):
        raise GlobalConfigError("global: 'exports' must be a list")

    exports: list[ExportConfig] = []
    seen_ids: set[str] = set()
    for i, raw_export in enumerate(raw_exports):
        if not isinstance(raw_export, dict):
            raise GlobalConfigError(f"global.exports[{i}]: must be a mapping")
        export = ExportConfig.from_dict(raw_export, index=i)
        if export.local_device_id in seen_ids:
            raise GlobalConfigError(
                f"global.exports[{i}]: duplicate local_device_id "
                f"{export.local_device_id!r}"
            )
        seen_ids.add(export.local_device_id)
        exports.append(export)

    return GlobalConfig(
        enabled=enabled,
        base_url=base_url,
        issuer=issuer,
        jwks_url=jwks_url,
        deployment_state_path=deployment_state_path,
        deployment_private_key_path=deployment_private_key_path,
        heartbeat_seconds=heartbeat_seconds,
        offline_seconds=offline_seconds,
        relay_ingress=relay_ingress,
        public_group=public_group,
        route=route,
        exports=tuple(exports),
    )


def load_global_config(
    path: Optional[Path] = None,
    *,
    allow_insecure_transport: bool = False,
) -> GlobalConfig:
    path = Path(path) if path is not None else default_global_config_path()
    if not path.exists():
        raise GlobalConfigError(f"global config not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise GlobalConfigError(f"invalid YAML in {path}: {exc}") from exc
    try:
        return parse_global_config(data, allow_insecure_transport=allow_insecure_transport)
    except GlobalConfigError as exc:
        raise GlobalConfigError(f"invalid global config {path}: {exc}") from exc


def validate_against_known_devices(
    cfg: GlobalConfig, known_device_ids: set
) -> list:
    """
    Cross-check exports against the caller-supplied set of known local device
    ids (as strings). Returns a list of human-readable error strings (empty
    if everything checks out) rather than raising, so callers (CLI
    validate-config, catalog builder) can report every problem at once.
    """
    known = {str(d) for d in known_device_ids}
    errors: list[str] = []
    for export in cfg.exports:
        if export.local_device_id not in known:
            errors.append(
                f"exports: local_device_id {export.local_device_id!r} "
                "does not match any configured local device"
            )
    return errors
