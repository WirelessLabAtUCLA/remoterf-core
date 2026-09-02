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
Safe, structured audit events for RemoteRF Global activity — reuses the
existing printf/Sty console logging rather than adding a new sink.

NEVER pass: JWT strings, assertions, bearer/deployment tokens, private
keys, password hashes, enrollment tokens, reservation tokens, certificate
private keys, raw IQ, or full device arguments as a field value here. Only
stable identifiers (deployment id, global subject, local account/device/
reservation id, request id, event type) belong in `fields`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ...common.utils.ansi_codes import Sty, printf

_FORBIDDEN_FIELD_NAMES = {
    "jwt", "token", "assertion", "private_key", "password", "password_hash",
    "enrollment_token", "reservation_token", "bearer", "session_token",
}


def audit_event(event_type: str, **fields) -> None:
    bad = _FORBIDDEN_FIELD_NAMES & set(fields.keys())
    if bad:
        raise ValueError(f"refusing to audit-log sensitive field name(s): {sorted(bad)!r}")

    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rendered = ", ".join(f"{k}={v}" for k, v in fields.items())
    printf(f"[remoterf-global] {ts} {event_type}: {rendered}", Sty.GRAY)
