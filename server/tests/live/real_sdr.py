#!/usr/bin/env python3
"""A real Pluto over the federated path: a HOME user reserves a partner's cabled
loopback Pluto, transmits a tone, and checks the tone comes back on RX.

register/enroll as soak_client.py -> reserve "<device> @<owner>" -> Pluto(token)
-> for each tone: tx cyclic, rx, peak bin == tone and SNR >= --min-snr
-> then rx() for --minutes, every buffer checked for the last tone.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from soak_client import acc, configure, log

FS = 1_000_000


def tone_check(iq, tone_hz, fs=FS):
    """(peak frequency, SNR dB of the peak over the median bin) of a buffer."""
    iq = np.asarray(iq)[-8192:]
    spec = np.abs(np.fft.fftshift(np.fft.fft(iq * np.hanning(iq.size)))) ** 2
    freqs = np.fft.fftshift(np.fft.fftfreq(iq.size, 1 / fs))
    k = int(np.argmax(spec))
    return float(freqs[k]), float(10 * np.log10(spec[k] / max(np.median(spec), 1e-20)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True)
    ap.add_argument("--cert-port", type=int, required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--device", default="Pluto SDR (loopback)")
    ap.add_argument("--owner", default="", help="partner display name; empty = the HOME's own device")
    ap.add_argument("--lo", type=float, default=2.4e9)
    ap.add_argument("--tx-gain", type=float, default=-10)
    ap.add_argument("--rx-gain", type=float, default=50)
    ap.add_argument("--tones", default="100e3,-200e3,250e3")
    ap.add_argument("--min-snr", type=float, default=50)
    ap.add_argument("--samples", type=int, default=65536)
    ap.add_argument("--minutes", type=float, default=2)
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    configure(args.home, args.cert_port)
    user, pw = args.user, args.password
    report = {"user": user, "home": args.home, "device": args.device, "owner": args.owner,
              "started": datetime.now().isoformat(), "tones": []}
    if "UC" not in acc("login", un=user, pw=pw):
        sys.exit("login failed")
    devices = acc("get_dev", un=user, pw=pw)
    wanted = sorted(int(k) for k, v in devices.items()
                    if str(v).startswith(args.device) and (f"@{args.owner}" in str(v) if args.owner else " @" not in str(v)) and "(online)" in str(v))
    log(f"candidates {[(k, devices[str(k)]) for k in wanted]}")
    for res_id, row in acc("get_res", un=user, pw=pw).items():
        if str(row).split(",")[0] == user:
            acc("cancel_res", un=user, pw=pw, res_id=int(res_id))
    start = datetime.now().replace(microsecond=0) - timedelta(minutes=1)
    end = start + timedelta(minutes=args.minutes + 10)
    token = alias = None
    for candidate in wanted:
        reply = acc("reserve_device", un=user, pw=pw, dd=candidate, st=int(start.timestamp()), et=int(end.timestamp()))
        if "Token" in reply:
            token, alias = reply["Token"], candidate
            break
        log(f"reserve {candidate} refused: {reply}")
    if token is None:
        sys.exit("no free device")
    log(f"reserved {alias} {devices[str(alias)]}")
    report["alias"], report["label"] = alias, devices[str(alias)]

    from remoterf.core import direct_path
    from remoterf.drivers.adalm_pluto import Pluto

    host, port = args.home.rsplit(":", 1)
    direct_path.start(username=user, secret=pw, route={"kind": "lan", "host": host, "port": int(port)})
    sdr = None
    try:
        sdr = Pluto(token)
        n = np.arange(2 ** 14)

        def setup(tone=None):
            """Settings, and the tone if given; also what a script re-applies after an owner restart."""
            sdr.sample_rate = FS
            sdr.rx_lo = sdr.tx_lo = int(args.lo)
            sdr.rx_rf_bandwidth = sdr.tx_rf_bandwidth = FS
            sdr.gain_control_mode_chan0 = "manual"
            sdr.rx_hardwaregain_chan0 = args.rx_gain
            sdr.tx_hardwaregain_chan0 = args.tx_gain
            sdr.rx_buffer_size = args.samples
            sdr.tx_destroy_buffer()
            sdr.tx_cyclic_buffer = True
            if tone is not None:
                sdr.tx((2 ** 14 * 0.5 * np.exp(2j * np.pi * tone / FS * n)).astype(np.complex64))

        setup()
        readback = {k: getattr(sdr, k) for k in ("sample_rate", "rx_lo", "tx_lo", "rx_hardwaregain_chan0",
                                                 "tx_hardwaregain_chan0", "gain_control_mode_chan0", "rx_buffer_size")}
        log(f"readback {readback}")
        report["readback"] = readback
        path = direct_path._partners.get(token)
        log(f"path {path.describe() if path else 'none'}")

        tone = 0.0
        for tone in (float(t) for t in args.tones.split(",")):
            setup(tone)
            for _ in range(3):  # flush buffers captured before the new tone
                sdr.rx()
            iq = np.asarray(sdr.rx())
            peak, snr = tone_check(iq, tone)
            level = float(np.abs(iq).mean())
            ok = abs(peak - tone) <= 2 * FS / 8192 and snr >= args.min_snr
            log(f"tone {tone/1e3:+.0f} kHz -> peak {peak/1e3:+.1f} kHz, SNR {snr:.1f} dB, mean |x| {level:.0f} counts {'OK' if ok else 'FAIL'}")
            report["tones"].append({"tone": tone, "peak": peak, "snr_db": round(snr, 1), "mean_abs": round(level, 1), "ok": ok})

        latencies, snrs, bad, errors, bad_samples, outages = [], [], 0, [], [], []
        outage_start = None
        last_reapply = [0.0]

        def reapply():
            if time.monotonic() - last_reapply[0] < 2:
                return
            last_reapply[0] = time.monotonic()
            try:
                setup(tone)
                log("re-applied settings and tone")
            except Exception as exc:  # noqa: BLE001
                log(f"re-apply failed: {type(exc).__name__}: {str(exc)[:120]}")

        deadline = time.monotonic() + args.minutes * 60
        while time.monotonic() < deadline:
            t1 = time.monotonic()
            try:
                iq = np.asarray(sdr.rx())
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {str(exc)[:160]}")
                log(f"rx error: {errors[-1]}")
                outage_start = outage_start or t1
                time.sleep(1)
                reapply()
                continue
            latencies.append(time.monotonic() - t1)
            peak, snr = tone_check(iq, tone)
            snrs.append(snr)
            good = iq.shape == (args.samples,) and abs(peak - tone) <= 2 * FS / 8192 and snr >= args.min_snr
            if good and outage_start:
                outages.append(round(time.monotonic() - outage_start, 1))
                log(f"recovered after {outages[-1]} s")
                outage_start = None
            if not good:
                outage_start = outage_start or t1
                reapply()
                bad += 1
                if args.report and not bad_samples:
                    np.save(Path(args.report).with_suffix(".bad.npy"), iq)
                bad_samples.append({"shape": iq.shape, "peak": round(peak), "snr_db": round(snr, 1),
                                    "call": len(latencies), "whole_buffer": tone_check(iq[:8192], tone)})
        path = direct_path._partners.get(token)
        report["soak"] = {
            "calls": len(latencies), "bad": bad, "bad_samples": bad_samples[:8], "errors": len(errors), "error_samples": errors[:5],
            "outages_s": outages + ([f"open {round(time.monotonic() - outage_start, 1)}"] if outage_start else []),
            "mb_per_s": round(len(latencies) * args.samples * 8 / 1e6 / max(sum(latencies), 1e-9), 2),
            "p50_ms": round(statistics.median(latencies) * 1000, 1) if latencies else None,
            "snr_db_min": round(min(snrs), 1) if snrs else None,
            "snr_db_median": round(statistics.median(snrs), 1) if snrs else None,
            "path_final": path.describe() if path else "none",
        }
        log(f"soak {report['soak']}")
    finally:
        if sdr is not None:
            try:
                sdr.tx_destroy_buffer()
            except Exception as exc:  # noqa: BLE001
                log(f"tx_destroy_buffer: {exc}")
        for res_id, row in acc("get_res", un=user, pw=pw).items():
            parts = str(row).split(",")
            if parts[0] == user and parts[1] == str(alias):
                acc("cancel_res", un=user, pw=pw, res_id=int(res_id))
        direct_path.stop()
        if args.report:
            Path(args.report).write_text(json.dumps(report, indent=2, default=str))
    soak = report.get("soak", {})
    ok = all(t["ok"] for t in report["tones"]) and soak.get("calls") and not soak.get("bad") and not soak.get("errors")
    sys.exit(0 if ok else 5)


if __name__ == "__main__":
    main()
