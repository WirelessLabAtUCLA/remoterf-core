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
