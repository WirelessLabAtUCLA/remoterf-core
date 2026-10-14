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

"""`diag` tests for UHD USRPs (B2xx, NI 2901, N210). Receive only: never TX."""

from __future__ import annotations

import time

import numpy as np

from remoteRF_server.server.diag import Guard

STREAM_N = 200_000


def _uhd():
    import uhd  # not usrp_schema: importing it would re-register the "usrp" driver

    return uhd


def _close(got, want, tol, what):
    if abs(float(got) - float(want)) > tol:
        raise RuntimeError(f"{what}: set {want:.10g}, read back {float(got):.10g}")


def open_device(ctx):
    """The cold image loads out of process first (prepare_for_holder), as for a reservation."""
    schema = ctx["schema"]
    started = time.monotonic()
    if schema.device is None:
        schema.prepare_for_holder()
        live = schema.create_session_schema()
        if ctx["stop"].is_set():  # timed out meanwhile: restore already ran, close it here
            live.close_native_device()
            raise RuntimeError("opened after diag gave up on it")
        ctx["live"] = live
        usrp = live.device
    else:  # a v1 client's lazily opened adapter (--force): test it, put its RX settings back after
        usrp = schema.device
        ctx["saved"] = (usrp.get_rx_rate(0), usrp.get_rx_freq(0), usrp.get_rx_gain(0))
    ctx["usrp"] = Guard(usrp, ctx["stop"])
    info = dict(usrp.get_usrp_rx_info(0))
    values = {"mboard": str(info.get("mboard_id", "")), "serial": str(info.get("mboard_serial", "")),
              "open_s": round(time.monotonic() - started, 1)}
    return f"{values['mboard'] or 'USRP'} sn {values['serial'] or '-'} in {values['open_s']} s", values


def rx_rates(ctx):
    usrp = ctx["usrp"]
    for rate in (1e6, 5e6, 10e6):
        usrp.set_rx_rate(rate, 0)
        _close(usrp.get_rx_rate(0), rate, rate * 0.01, "RX rate")
    return "1, 5, 10 MS/s read back"


def rx_freqs(ctx):
    uhd, usrp = _uhd(), ctx["usrp"]
    span = usrp.get_rx_freq_range(0)
    lo, hi = float(span.start()), float(span.stop())
    freqs = sorted({min(max(f, lo + 1e6), hi - 1e6) for f in (100e6, 915e6, 2.4e9, 5.8e9)})
    for f in freqs:
        usrp.set_rx_freq(uhd.types.TuneRequest(f), 0)
        _close(usrp.get_rx_freq(0), f, 1e3, "RX frequency")
    return f"{len(freqs)} frequencies {freqs[0] / 1e6:g}-{freqs[-1] / 1e6:g} MHz read back"


def rx_gains(ctx):
    usrp = ctx["usrp"]
    span = usrp.get_rx_gain_range(0)
    lo, hi = float(span.start()), float(span.stop())
    for gain in (lo, (lo + hi) / 2, hi):
        usrp.set_rx_gain(gain, 0)
        _close(usrp.get_rx_gain(0), gain, 1, "RX gain")
    return f"RX gain {lo:g}-{hi:g} dB read back"


def rx_stream(ctx):
    uhd, usrp = _uhd(), ctx["usrp"]
    usrp.set_rx_rate(1e6, 0)
    usrp.set_rx_freq(uhd.types.TuneRequest(915e6), 0)
    usrp.set_rx_gain(20, 0)
    args = uhd.usrp.StreamArgs("fc32", "sc16")
    args.channels = [0]
    streamer = usrp.get_rx_stream(args)
    buf = np.zeros((1, streamer.get_max_num_samps()), dtype=np.complex64)
    meta = uhd.types.RXMetadata()
    cmd = uhd.types.StreamCMD(uhd.types.StreamMode.num_done)
    cmd.num_samps = STREAM_N
    cmd.stream_now = True
    streamer.issue_stream_cmd(cmd)
    got, chunks = 0, []
    end = time.monotonic() + 5
    while got < STREAM_N and time.monotonic() < end:
        n = streamer.recv(buf, meta, 1.0)
        if meta.error_code != uhd.types.RXMetadataErrorCode.none:
            raise RuntimeError(f"RX error: {meta.strerror()}")
        chunks.append(buf[0, :n].copy())
        got += n
    if got < STREAM_N:
        raise RuntimeError(f"received {got} of {STREAM_N} samples")
    data = np.concatenate(chunks)
    if not np.all(np.isfinite(data)) or not np.any(data):
        raise RuntimeError("samples are all zero or not finite")
    dbfs = round(float(10 * np.log10(max(np.mean(np.abs(data) ** 2), 1e-20))), 1)
    return f"{got} samples, {dbfs} dBFS", {"samples": got, "dbfs": dbfs}


def _open_s(schema):
    """A cold B2xx image loads in ~70 s; up to two 180 s pre-loads before giving up."""
    return 70 if schema.device is None else 5


# (name, typical s, timeout s, fn); the first is the gate.
TESTS = [
    ("open", _open_s, 400, open_device),
    ("rx rate", 2, 20, rx_rates),
    ("rx freq", 2, 20, rx_freqs),
    ("rx gain", 1, 15, rx_gains),
    ("rx stream", 2, 20, rx_stream),
]


def teardown(ctx):
    live = ctx.get("live")
    if live is not None:
        live.close_native_device()
    if "saved" in ctx:
        rate, freq, gain = ctx["saved"]
        usrp = ctx["schema"].device
        usrp.set_rx_rate(rate, 0)
        usrp.set_rx_freq(_uhd().types.TuneRequest(freq), 0)
        usrp.set_rx_gain(gain, 0)


TEARDOWN_S = (1, 15)
