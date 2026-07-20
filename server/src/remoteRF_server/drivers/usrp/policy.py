"""Compatibility shim for unrestricted USRP access.

USRP policy enforcement is currently disabled. ``USRPPolicy`` remains importable
so older integrations do not fail at import time, but every supported control,
streaming, property-tree, GPIO, and register operation passes through without
policy checks.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping


class USRPPolicy:
    """No-op policy retained for protocol and integration compatibility."""

    def __init__(self, config: Mapping[str, Any] | None = None, *, source: str = ""):
        self.config = dict(config or {})
        self.source = source

    @classmethod
    def load(cls, *, gid: int, serial: str = "", path: Path | None = None) -> "USRPPolicy":
        del gid, serial, path
        return cls()

    @property
    def tx_enabled(self) -> bool:
        return True

    @property
    def restrictions(self) -> dict[str, Any]:
        return {}

    def check_control(self, method: str, args: Mapping[str, Any]) -> None:
        del method, args

    def check_tx_duration(self, duration: float) -> None:
        del duration

    def check_handle_call(self, type_id: str, method: str, args: Mapping[str, Any]) -> None:
        del type_id, method, args
