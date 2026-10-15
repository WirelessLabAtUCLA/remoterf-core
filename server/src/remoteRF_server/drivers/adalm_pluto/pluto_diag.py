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

"""`diag` tests for ADALM-Pluto (USB, PoE, MIMO, Pluto+). Nothing radiates: the tone
tests use the AD936x internal digital loopback at the lowest TX gain, and a
Multi-Tap's coax loopback (init `multi_tap: true`) stays at TX <= -10 dB."""

from __future__ import annotations

import time

import numpy as np

from remoteRF_server.drivers.adalm_pluto.poe import PoePluto
from remoteRF_server.server.diag import Skip

TX_MIN_DB = -89.75
FS = 3_000_000
TONE_N = 6000  # FS / TONE_N = 500 Hz: every offset below is a whole number of cycles
RX_N = 8192
OFFSETS = (100_000, 250_000, -300_000)
MIN_SNR_DB = 20.0
COAX_TX_DB = (-40, -30, -20, -10)  # never above -10 dB
COAX_RX_DB = (10, 30, 50)
SNAPSHOT = ("sample_rate", "rx_lo", "tx_lo", "rx_rf_bandwidth", "tx_rf_bandwidth",
            "gain_control_mode_chan0", "rx_hardwaregain_chan0", "tx_hardwaregain_chan0", "rx_buffer_size",
            "tx_cyclic_buffer", "loopback")
MIMO_TYPES = ("adalm_pluto_mimo", "pluto_plus")
MIMO_SNAPSHOT = ("gain_control_mode_chan1", "rx_hardwaregain_chan1", "tx_hardwaregain_chan1",
                 "tx_enabled_channels", "rx_enabled_channels")


def _poe(ctx):
    native = ctx["schema"].device
    return native if isinstance(native, PoePluto) else None


def _rx(schema):
    data = schema.device.rx()
    return np.asarray(data[0] if isinstance(data, (list, tuple)) else data)


def _close(got, want, tol, what):
    if abs(float(got) - float(want)) > tol:
        raise RuntimeError(f"{what}: set {want:.10g}, read back {float(got):.10g}")


def power(ctx):
    schema = ctx["schema"]
    poe = _poe(ctx)
    ctx["was_on"] = poe is None or poe.power_state == "on"
    started = time.monotonic()
    if poe is not None and not ctx["was_on"]:
        poe.power_up()
    rate = int(schema.get_sample_rate())
    mimo = ctx.get("type") in MIMO_TYPES
    ctx["snapshot"] = {name: getattr(schema, f"get_{name}")() for name in SNAPSHOT + (MIMO_SNAPSHOT if mimo else ())}
    # Quiet the transmitter before anything retunes it: a boot-time DDS tone or a
    # previous holder's cyclic buffer would otherwise follow the LO sweep on air.
    schema.call_disable_dds()
    schema.call_tx_destroy_buffer()
    schema.set_tx_hardwaregain_chan0(TX_MIN_DB)
    if mimo:  # every tone test sends and reads channel 0 only
        schema.set_tx_hardwaregain_chan1(TX_MIN_DB)
        schema.set_tx_enabled_channels([0])
        schema.set_rx_enabled_channels([0])
    if ctx["was_on"]:
        return f"answering at {rate} S/s", {"sample_rate": rate}
    took = round(time.monotonic() - started, 1)
    return f"booted in {took} s", {"boot_s": took}


def context(ctx):
    attrs = dict(ctx["schema"].device._ctx.attrs)
    values = {k: str(attrs[k]) for k in ("hw_model", "hw_serial", "fw_version", "ad9361-phy,model") if k in attrs}
    if "hw_serial" not in values:
        raise RuntimeError("IIO context has no hw_serial")
    return f"{values.get('hw_model', 'Pluto')} fw {values.get('fw_version', '?')} sn {values['hw_serial']}", values


def temperature(ctx):
    dev = ctx["schema"].device
    try:
        celsius = float(dev._get_iio_attr("temp0", "input", False)) / 1000
    except Exception:
        raise Skip("no temperature sensor exposed")
    if not 0 < celsius < 95:
        raise RuntimeError(f"{celsius:.1f} °C is out of range")
    return f"{celsius:.1f} °C", {"celsius": celsius}


def sample_rates(ctx):
    schema = ctx["schema"]
    for rate in (1_000_000, 2_500_000, 10_000_000, 20_000_000, FS):
        schema.set_sample_rate(rate)
        _close(schema.get_sample_rate(), rate, rate * 0.01, "sample rate")
    return "1, 2.5, 10, 20, 3 MS/s read back"


def lo_tuning(ctx):
    schema = ctx["schema"]
    freqs = (400e6, 915e6, 2.4e9, 3.5e9)  # inside the stock AD9363 range
    for f in freqs:
        schema.set_rx_lo(int(f))
        schema.set_tx_lo(int(f))
        _close(schema.get_rx_lo(), f, 1e3, "RX LO")
        _close(schema.get_tx_lo(), f, 1e3, "TX LO")
    return "RX/TX LO 400 MHz-3.5 GHz read back"


def bandwidth(ctx):
    schema = ctx["schema"]
    for bw in (1_000_000, 5_000_000, 18_000_000):
        schema.set_rx_rf_bandwidth(bw)
        schema.set_tx_rf_bandwidth(bw)
        _close(schema.get_rx_rf_bandwidth(), bw, bw * 0.1, "RX bandwidth")
        _close(schema.get_tx_rf_bandwidth(), bw, bw * 0.1, "TX bandwidth")
    return "RX/TX 1, 5, 18 MHz read back"


def gains(ctx):
    schema = ctx["schema"]
    schema.call_disable_dds()  # nothing queued for TX while its gain moves
    for mode in ("slow_attack", "fast_attack", "manual"):
        schema.set_gain_control_mode_chan0(mode)
        if schema.get_gain_control_mode_chan0() != mode:
            raise RuntimeError(f"gain mode {mode} did not stick")
    for gain in (10, 30, 50):
        schema.set_rx_hardwaregain_chan0(gain)
        _close(schema.get_rx_hardwaregain_chan0(), gain, 1, "RX gain")
    for gain in (-60, -75, TX_MIN_DB):
        schema.set_tx_hardwaregain_chan0(gain)
        _close(schema.get_tx_hardwaregain_chan0(), gain, 0.5, "TX gain")
    return "3 gain modes, RX 10/30/50 dB, TX -60/-75/-89.75 dB"


def rx_buffers(ctx):
    schema = ctx["schema"]
    schema.set_sample_rate(FS)
    schema.set_gain_control_mode_chan0("manual")
    schema.set_rx_hardwaregain_chan0(30)
    schema.set_rx_buffer_size(RX_N)
    power = []
    for _ in range(3):
        data = _rx(schema)
        if data.size != RX_N:
            raise RuntimeError(f"read {data.size} samples, expected {RX_N}")
        if not np.all(np.isfinite(data)) or not np.any(data):
            raise RuntimeError("buffer is all zero or not finite")
        power.append(float(np.mean(np.abs(data) ** 2)))
    dbfs = round(10 * np.log10(max(np.mean(power), 1e-12) / 2**22), 1)
    return f"3 x {RX_N} samples, {dbfs} dBFS", {"rx_dbfs": dbfs}


def _tone(schema, offset, tx_db, rx_db):
    """Peak frequency and SNR (dB) of a tone at `offset` Hz sent TX -> RX."""
    schema.set_tx_hardwaregain_chan0(tx_db)
    schema.set_gain_control_mode_chan0("manual")
    schema.set_rx_hardwaregain_chan0(rx_db)
    n = np.arange(TONE_N)
    schema.call_tx_destroy_buffer()
    schema.set_tx_cyclic_buffer(True)
    schema.call_tx(0.5 * 2**14 * np.exp(2j * np.pi * offset * n / FS))
    try:
        schema.call_rx_destroy_buffer()
        for _ in range(2):  # the first buffers can predate the tone
            _rx(schema)
        data = _rx(schema)
    finally:
        schema.call_tx_destroy_buffer()
    spectrum = np.abs(np.fft.fftshift(np.fft.fft(data * np.hanning(data.size)))) ** 2
    freqs = np.fft.fftshift(np.fft.fftfreq(data.size, 1 / FS))
    peak = int(np.argmax(spectrum))
    snr = 10 * np.log10(max(float(spectrum[peak]), 1e-30) / max(float(np.median(spectrum)), 1e-30))
    return float(freqs[peak]), round(float(snr), 1)


def _prepare_tone(schema, lo):
    schema.set_sample_rate(FS)
    schema.set_rx_lo(int(lo))
    schema.set_tx_lo(int(lo))
    schema.set_rx_buffer_size(RX_N)


def loopback_tone(ctx):
    schema = ctx["schema"]
    _prepare_tone(schema, 915e6)
    values = {}
    schema.set_loopback(1)  # AD936x digital TX -> RX, inside the chip
    try:
        for offset in OFFSETS:
            peak, snr = _tone(schema, offset, TX_MIN_DB, 10)
            values[f"{offset // 1000:+d}kHz"] = {"peak_hz": peak, "snr_db": snr}
            if abs(peak - offset) > 5_000:
                raise RuntimeError(f"tone at {offset / 1e3:+g} kHz came back at {peak / 1e3:+.1f} kHz")
            if snr < MIN_SNR_DB:
                raise RuntimeError(f"tone at {offset / 1e3:+g} kHz: SNR {snr} dB < {MIN_SNR_DB}")
    finally:
        schema.set_loopback(0)
    worst = min(v["snr_db"] for v in values.values())
    return f"{len(OFFSETS)} offsets found, SNR >= {worst} dB", values


def channel_1(ctx):
    """MIMO boards (Pluto+, 2R2T): the loopback tone through the second RX/TX pair."""
    if ctx.get("type") not in MIMO_TYPES:
        raise Skip("single-channel Pluto")
    schema = ctx["schema"]
    _prepare_tone(schema, 915e6)
    schema.set_gain_control_mode_chan1("manual")
    schema.set_rx_hardwaregain_chan1(10)
    schema.set_tx_enabled_channels([1])
    schema.set_rx_enabled_channels([1])
    schema.set_loopback(1)
    try:
        peak, snr = _tone(schema, OFFSETS[0], TX_MIN_DB, 10)
    finally:
        schema.set_loopback(0)
        schema.set_tx_enabled_channels([0])
        schema.set_rx_enabled_channels([0])
    if abs(peak - OFFSETS[0]) > 5_000 or snr < MIN_SNR_DB:
        raise RuntimeError(f"channel 1: tone at {OFFSETS[0] / 1e3:+g} kHz came back at {peak / 1e3:+.1f} kHz, SNR {snr} dB")
    return f"tone found, SNR {snr} dB", {"peak_hz": peak, "snr_db": snr}


def coax_loopback(ctx):
    if not ctx["init"].get("multi_tap"):
        raise Skip("not a Multi-Tap")
    schema = ctx["schema"]
    _prepare_tone(schema, 915e6)
    schema.set_loopback(0)
    for tx_db in COAX_TX_DB:
        for rx_db in COAX_RX_DB:
            peak, snr = _tone(schema, OFFSETS[0], tx_db, rx_db)
            if abs(peak - OFFSETS[0]) <= 5_000 and snr >= MIN_SNR_DB:
                return f"tone at TX {tx_db} dB / RX {rx_db} dB, SNR {snr} dB", {
                    "tx_db": tx_db, "rx_db": rx_db, "snr_db": snr}
    raise RuntimeError(f"no tone over the coax up to TX {COAX_TX_DB[-1]} dB / RX {COAX_RX_DB[-1]} dB")


def _boot_s(schema):
    """A PoE Pluto in standby boots in ~30 s."""
    native = schema.device
    return 30 if isinstance(native, PoePluto) and native.power_state != "on" else 1


# (name, typical s, timeout s, fn); the first is the gate.
TESTS = [
    ("power", _boot_s, 100, power),
    ("iio context", 1, 10, context),
    ("temperature", 1, 10, temperature),
    ("sample rate", 5, 40, sample_rates),
    ("lo tuning", 3, 30, lo_tuning),
    ("bandwidth", 2, 20, bandwidth),
    ("gain", 2, 20, gains),
    ("rx buffers", 2, 20, rx_buffers),
    ("loopback tone", 4, 40, loopback_tone),
    ("channel 1", 2, 30, channel_1),
    ("coax loopback", 2, 60, coax_loopback),
]


def teardown(ctx):
    """Stop TX; a PoE Pluto that was in standby goes back to it unless now reserved,
    anything else gets its settings back."""
    schema = ctx["schema"]
    poe = _poe(ctx)
    if poe is not None and not ctx.get("was_on", True) and not ctx["reserved"]():
        schema.call_power_down()
        return
    schema.call_tx_destroy_buffer()
    schema.call_rx_destroy_buffer()
    schema.set_loopback(0)
    snapshot = dict(ctx.get("snapshot", {}))
    for chan in (0, 1):
        if snapshot.get(f"gain_control_mode_chan{chan}", "manual") != "manual":
            snapshot.pop(f"rx_hardwaregain_chan{chan}", None)  # an AGC mode owns it
    failed = []
    for name, value in snapshot.items():
        try:
            getattr(schema, f"set_{name}")(value)
        except Exception:
            failed.append(name)
    if failed:
        raise RuntimeError(f"could not restore {', '.join(failed)}")


TEARDOWN_S = (2, 30)
