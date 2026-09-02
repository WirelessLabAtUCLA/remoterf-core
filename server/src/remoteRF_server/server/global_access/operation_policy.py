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
Deny-by-default operation policy for RemoteRF Global public sessions.

Catalog metadata is not enforcement — this module is what actually blocks a
disallowed operation before it reaches a device driver. It is only ever
consulted for accounts whose auth_type is 'remoterf_global'; ordinary LAN
accounts never call into this module (see the call sites in rpc_manager.py
and dynamic_v2.py, which check `is_global_principal` first and return
immediately for local accounts).
"""

from __future__ import annotations

from typing import Optional

from .config import ExportConfig, GlobalConfig


def is_global_principal(username: Optional[str]) -> bool:
    if not username:
        return False
    from ..reservation import reservation_handler

    return reservation_handler.get_auth_type(username) == "remoterf_global"

def export_for_device(cfg: GlobalConfig, device_id) -> Optional[ExportConfig]:
    return cfg.export_for(str(device_id))


def check_legacy_rpc_operation(cfg: GlobalConfig, *, device_id, prop: str, verb: str) -> None:
    """Raises RemoteRFPolicyError (caught by rpc_manager._handle_device_rpc's
    existing `except Exception`, so the legacy-RPC response shape is
    unchanged) if this prop:verb pair is not on the export's allowlist."""
    from ..v2_errors import RemoteRFPolicyError

    operation = f"{prop}:{verb}"
    export = export_for_device(cfg, device_id)
    if export is None or not export.operation_policy.allows(operation):
        raise RemoteRFPolicyError(
            f"operation {operation!r} is not allowed for RemoteRF Global public "
            f"sessions on device {device_id}",
            details={"reason": "global_operation_denied", "operation": operation, "device_id": str(device_id)},
            method=operation,
        )


def check_dynamic_v2_operation(cfg: GlobalConfig, *, device_id, method: str) -> None:
    """Same enforcement for DynamicControlV2.Invoke — raises
    RemoteRFPolicyError, which already flows through error_envelope() into
    the response's existing ErrorEnvelope field."""
    from ..v2_errors import RemoteRFPolicyError

    export = export_for_device(cfg, device_id)
    if export is None or not export.operation_policy.allows(method):
        raise RemoteRFPolicyError(
            f"method {method!r} is not allowed for RemoteRF Global public "
            f"sessions on device {device_id}",
            details={"reason": "global_operation_denied", "operation": method, "device_id": str(device_id)},
            method=method,
        )


def sample_upload_allowed(cfg: GlobalConfig, *, device_id) -> bool:
    export = export_for_device(cfg, device_id)
    return bool(export is not None and export.operation_policy.allow_client_sample_upload)


def _global_enabled() -> bool:
    import os

    return (os.getenv("REMOTERF_GLOBAL_ENABLED", "false") or "").strip().lower() in (
        "1", "true", "yes",
    )


def _load_cfg_or_none() -> Optional[GlobalConfig]:
    from .config import GlobalConfigError, load_global_config

    try:
        return load_global_config()
    except GlobalConfigError:
        return None


def enforce_for_legacy_rpc(*, api_token: str, device_id, function_name: str) -> None:
    """
    Single entry point for rpc_manager._handle_device_rpc: a complete no-op
    (zero overhead beyond one env check) unless Global is enabled AND the
    token resolves to a Global-principal account. Raises RemoteRFPolicyError
    (caught by the existing `except Exception` in _handle_device_rpc) when
    the operation is not on that export's allowlist.
    """
    if not _global_enabled():
        return

    from ..reservation import reservation_handler

    username = reservation_handler.get_username_for_active_token(api_token)
    if not is_global_principal(username):
        return

    cfg = _load_cfg_or_none()
    if cfg is None:
        from ..v2_errors import RemoteRFPolicyError

        raise RemoteRFPolicyError(
            "RemoteRF Global is enabled but misconfigured; denying all operations "
            "for Global public sessions until it is fixed",
            details={"reason": "global_misconfigured"},
        )

    parts = function_name.split(":", 2)
    if len(parts) != 3:
        return
    _, prop, verb = parts
    check_legacy_rpc_operation(cfg, device_id=device_id, prop=prop, verb=verb)


def enforce_for_dynamic_v2(*, username: Optional[str], device_id, method: str) -> None:
    """Same enforcement point for DynamicControlV2.Invoke."""
    if not _global_enabled():
        return
    if not is_global_principal(username):
        return

    cfg = _load_cfg_or_none()
    if cfg is None:
        from ..v2_errors import RemoteRFPolicyError

        raise RemoteRFPolicyError(
            "RemoteRF Global is enabled but misconfigured; denying all operations "
            "for Global public sessions until it is fixed",
            details={"reason": "global_misconfigured"},
        )
    check_dynamic_v2_operation(cfg, device_id=device_id, method=method)


def sample_upload_allowed_for(*, username: Optional[str], device_id) -> bool:
    """
    Used by SampleDataV1's existing RX/TX direction check: returns True
    (no additional restriction) for anything that isn't a Global-principal
    session; for a Global principal, defers to that export's
    allow_client_sample_upload flag (default False — TX denied by default).
    """
    if not _global_enabled():
        return True
    if not is_global_principal(username):
        return True

    cfg = _load_cfg_or_none()
    if cfg is None:
        return False
    return sample_upload_allowed(cfg, device_id=device_id)
