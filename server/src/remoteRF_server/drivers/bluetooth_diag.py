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

"""`diag` tests for a Bluetooth adapter (contrib/drivers/bluetooth_schema.py)."""

from __future__ import annotations

SCAN_S = 5


def powered(ctx):
    schema = ctx["schema"]
    if not schema.get_powered():
        raise RuntimeError("adapter is not powered")
    return f"{schema.get_address()} powered", {"address": str(schema.get_address())}


def scan(ctx):
    summary = ctx["schema"].call_scan_summary(timeout=SCAN_S)
    if not isinstance(summary, dict):
        raise RuntimeError("scan returned nothing")
    count = summary.get("total_devices", "?")
    return f"{SCAN_S} s scan, {count} devices nearby", {"devices": count}


TESTS = [
    ("adapter", 1, 10, powered),
    ("scan", SCAN_S, SCAN_S + 15, scan),
]


def teardown(ctx):
    """The next holder must not read diag's scan of nearby devices."""
    native = ctx["schema"].device
    native.device_cache = {}
    native.last_scan_time = 0.0


TEARDOWN_S = (0, 5)
