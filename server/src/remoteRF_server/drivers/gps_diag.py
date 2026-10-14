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

"""`diag` tests for an NMEA GPS receiver (contrib/drivers/gps_schema.py)."""

from __future__ import annotations

import time
from functools import reduce

from remoteRF_server.server.diag import Skip

LISTEN_S = 6


def _checksum_ok(line: str) -> bool:
    body, _, given = line.strip().lstrip("$").partition("*")
    try:
        return reduce(lambda a, c: a ^ ord(c), body, 0) == int(given[:2], 16)
    except ValueError:
        return False


def liveness(ctx):
    schema = ctx["schema"]
    first = list(schema.call_read_raw(50))
    end = time.monotonic() + LISTEN_S
    while time.monotonic() < end:
        time.sleep(0.5)
        now = list(schema.call_read_raw(50))
        if now and now != first:
            ctx["lines"] = now
            return f"new sentences within {LISTEN_S} s", {"sentences": len(now)}
    raise RuntimeError(f"no new NMEA sentence in {LISTEN_S} s")


def sentence_types(ctx):
    kinds = sorted({line.strip().lstrip("$").split(",")[0][2:] for line in ctx["lines"] if line.strip().startswith("$")})
    if not {"GGA", "RMC"} & set(kinds):
        raise RuntimeError(f"no GGA or RMC among {', '.join(kinds) or 'nothing'}")
    return ", ".join(kinds), {"types": kinds}


def parse(ctx):
    lines = [l for l in ctx["lines"] if "*" in l]
    good = sum(_checksum_ok(l) for l in lines)
    if not lines or good < 0.8 * len(lines):
        raise RuntimeError(f"{good} of {len(lines)} checksums valid")
    return f"{good}/{len(lines)} checksums valid", {"valid": good, "total": len(lines)}


def fix(ctx):
    schema = ctx["schema"]
    if not schema.get_has_fix():
        raise Skip("no fix yet (optional)")
    values = {"satellites": int(schema.get_satellites()), "quality": int(schema.get_fix_quality())}
    return f"fix, {values['satellites']} satellites", values


TESTS = [
    ("nmea liveness", LISTEN_S, LISTEN_S + 5, liveness),
    ("sentence types", 0, 5, sentence_types),
    ("checksums", 0, 5, parse),
    ("fix", 0, 5, fix),
]
