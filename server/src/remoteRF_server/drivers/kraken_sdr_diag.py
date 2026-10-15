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

"""`diag` tests for a KrakenSDR (contrib/drivers/kraken_sdr_schema.py), receive only."""

from __future__ import annotations

import numpy as np

SNAPSHOT = ("sample_rate", "center_freq")
N = 16384


def _close(got, want, tol, what):
    if abs(float(got) - float(want)) > tol:
        raise RuntimeError(f"{what}: set {want:.10g}, read back {float(got):.10g}")


def tuners(ctx):
    schema = ctx["schema"]
    ctx["snapshot"] = {name: getattr(schema, f"get_{name}")() for name in SNAPSHOT}
    ctx["snapshot"]["gain"] = schema.get_gain()[0]  # set_gain applies one gain to all five
    serials = list(schema.get_serials())
    if schema.get_num_channels() != 5:
        raise RuntimeError(f"{schema.get_num_channels()} of 5 tuners open")
    return f"5 x {schema.get_tuner_type()}, sn {', '.join(serials)}", {"serials": serials}


def tuning(ctx):
    schema = ctx["schema"]
    schema.set_sample_rate(2_048_000)
    _close(schema.get_sample_rate(), 2_048_000, 20_480, "sample rate")
    for f in (100e6, 433.92e6, 915e6, 1.5e9):
        schema.set_center_freq(int(f))
        _close(schema.get_center_freq(), f, 10e3, "center frequency")
    return "2.048 MS/s, 100 MHz-1.5 GHz read back"


def gains(ctx):
    schema = ctx["schema"]
    valid = sorted(float(g) for g in schema.get_valid_gains_db())
    if not valid:
        raise RuntimeError("tuners report no gains")
    schema.set_gain(valid[len(valid) // 2])
    return f"{len(valid)} gains, {valid[0]:g}-{valid[-1]:g} dB", {"gains": len(valid)}


def samples(ctx):
    schema = ctx["schema"]
    schema.set_center_freq(100_000_000)
    reads = [np.asarray(ch) for ch in schema.call_read_samples(N)]
    if len(reads) != 5:
        raise RuntimeError(f"{len(reads)} channels came back, expected 5")
    dbfs = []
    for index, data in enumerate(reads):
        if data.size != N or not np.all(np.isfinite(data)) or float(data.std()) == 0:
            raise RuntimeError(f"channel {index}: short, non-finite or stuck IQ")
        dbfs.append(round(10 * np.log10(max(float(np.mean(np.abs(data) ** 2)), 1e-12)), 1))
    return f"5 x {N} IQ samples, {min(dbfs)} to {max(dbfs)} dBFS", {"dbfs": dbfs}


# (name, typical s, timeout s, fn); the first is the gate.
TESTS = [
    ("tuners", 1, 15, tuners),
    ("tuning", 2, 30, tuning),
    ("gain", 1, 15, gains),
    ("iq samples", 1, 20, samples),
]


def teardown(ctx):
    for name, value in ctx.get("snapshot", {}).items():
        getattr(ctx["schema"], f"set_{name}")(value)


TEARDOWN_S = (1, 10)
