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

"""`diag` tests for RTL-SDR (receive only)."""

from __future__ import annotations

import numpy as np

SNAPSHOT = ("sample_rate", "center_freq", "gain")


def _close(got, want, tol, what):
    if abs(float(got) - float(want)) > tol:
        raise RuntimeError(f"{what}: set {want:.10g}, read back {float(got):.10g}")


def tuner(ctx):
    schema = ctx["schema"]
    ctx["snapshot"] = {name: getattr(schema, f"get_{name}")() for name in SNAPSHOT}
    values = {"tuner": str(schema.get_tuner_type()), "serial": str(schema.get_serial_number() or "")}
    return f"tuner {values['tuner']}, sn {values['serial'] or '-'}", values


def sample_rates(ctx):
    schema = ctx["schema"]
    for rate in (1_024_000, 2_048_000, 2_400_000):
        schema.set_sample_rate(rate)
        _close(schema.get_sample_rate(), rate, rate * 0.01, "sample rate")
    return "1.024, 2.048, 2.4 MS/s read back"


def center_freqs(ctx):
    schema = ctx["schema"]
    for f in (100e6, 433.92e6, 915e6, 1.5e9):
        schema.set_center_freq(int(f))
        _close(schema.get_center_freq(), f, 10e3, "center frequency")
    return "100 MHz-1.5 GHz read back"


def gains(ctx):
    schema = ctx["schema"]
    valid = sorted(float(g) for g in schema.get_valid_gains_db())
    if not valid:
        raise RuntimeError("tuner reports no gains")
    unreported = 0
    for gain in (valid[0], valid[len(valid) // 2], valid[-1]):
        schema.set_gain(gain)
        got = schema.get_gain()
        if gain and not float(got):  # RTL-SDR Blog V4 (R828D) reads 0 for any manual gain
            unreported += 1
            continue
        _close(got, gain, 1, "gain")
    note = ", tuner does not report gain" if unreported else ""
    return f"{len(valid)} gains, {valid[0]:g}-{valid[-1]:g} dB set{note}", {"gains": len(valid)}


def byte_reads(ctx):
    schema = ctx["schema"]
    schema.set_sample_rate(2_048_000)
    schema.set_center_freq(100_000_000)
    try:
        schema.call_reset_buffer()
    except Exception:  # noqa: BLE001 - optional in pyrtlsdr; the server's reads never need it
        pass
    for n in (512, 512 * 32, 512 * 256):
        data = np.frombuffer(bytes(schema.call_read_bytes(n)), dtype=np.uint8)
        if data.size != n or data.size % 512:
            raise RuntimeError(f"asked {n} bytes, got {data.size}")
    mean = float(data.mean())
    if data.std() == 0:
        raise RuntimeError(f"every byte is {int(data[0])}")
    if not 64 < mean < 192:
        raise RuntimeError(f"bytes average {mean:.0f}, expected near 127.5")
    return f"512 / 16 KiB / 128 KiB reads, mean {mean:.1f}", {"byte_mean": round(mean, 1)}


def samples(ctx):
    data = np.asarray(ctx["schema"].call_read_samples(16384))
    if data.size != 16384 or not np.all(np.isfinite(data)):
        raise RuntimeError("short or non-finite IQ read")
    dc = float(abs(data.mean()))
    if dc > 0.5 or float(data.std()) == 0:
        raise RuntimeError(f"IQ looks stuck (dc {dc:.2f})")
    return f"16384 IQ samples, dc {dc:.3f}", {"dc": round(dc, 4)}


# (name, typical s, timeout s, fn); the first is the gate.
TESTS = [
    ("tuner", 1, 10, tuner),
    ("sample rate", 1, 15, sample_rates),
    ("center freq", 1, 15, center_freqs),
    ("gain", 1, 15, gains),
    ("byte reads", 1, 15, byte_reads),
    ("iq samples", 1, 15, samples),
]


def teardown(ctx):
    for name, value in ctx.get("snapshot", {}).items():
        getattr(ctx["schema"], f"set_{name}")(value)


TEARDOWN_S = (1, 10)
