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

"""`diag` tests for an RFbeam K-MD7 radar (contrib/drivers/rfbeam_kmd7_schema.py).
Read-only: nothing is written to the sensor's parameters."""

from __future__ import annotations

import time

DONE = 0x20  # GNFD flag for the frame counter packet (K-MD7_APP-RFB-0205)


def version(ctx):
    found = str(ctx["schema"].get_version())
    if not found.startswith("K-MD7"):
        raise RuntimeError(f"firmware reports {found!r}, not a K-MD7")
    return found, {"version": found}


def parameters(ctx):
    raw = bytes(ctx["schema"].get_parameters())
    if not raw.startswith(ctx["schema"].get_version().encode()):
        raise RuntimeError(f"RPST does not start with the firmware version ({len(raw)} bytes)")
    return f"RPST {len(raw)} bytes", {"rpst_hex": raw.hex()}


def frame(ctx):
    started = time.monotonic()
    packets = ctx["schema"].call_frame(DONE)
    ms = round((time.monotonic() - started) * 1000)
    if "DONE" not in packets:
        raise RuntimeError(f"GNFD 0x20 returned {sorted(packets) or 'no packets'}, expected DONE")
    count = int.from_bytes(bytes(packets["DONE"])[:4], "little")
    return f"frame {count} in {ms} ms", {"ms": ms, "frame": count}


# (name, typical s, timeout s, fn); the first is the gate.
TESTS = [
    ("version", 1, 10, version),
    ("parameters", 1, 10, parameters),
    ("frame", 1, 10, frame),
]
