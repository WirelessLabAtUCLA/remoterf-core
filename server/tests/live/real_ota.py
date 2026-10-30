#!/usr/bin/env python3
"""Over the air between two real radios: one transmits a tone, the others
receive it. Pluto and USRP either side; partner devices with --owner.

reserve --tx and each --rx alias -> per LO, per tone: TX starts, each RX
captures -> the peak must move by exactly the tone step between two tones
(oscillator offsets cancel) with SNR >= --min-snr.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from real_sdr import FS, tone_check
from soak_client import acc, configure, log

N = 2 ** 14


def is_usrp(label):
    return "USRP" in label or "b205" in label


class PlutoRadio:
    def __init__(self, token, args):
        from remoterf.drivers.adalm_pluto import Pluto

        self.sdr = Pluto(token)
        self.sdr.sample_rate = FS
        self.sdr.rx_rf_bandwidth = self.sdr.tx_rf_bandwidth = FS
        self.sdr.gain_control_mode_chan0 = "manual"
        self.sdr.rx_hardwaregain_chan0 = args.rx_gain
        self.sdr.tx_hardwaregain_chan0 = args.pluto_tx_gain
        self.sdr.rx_buffer_size = 65536
        self.sdr.tx_cyclic_buffer = True

    def start_tx(self, lo, tone, seconds):
        self.sdr.tx_lo = int(lo)
        self.sdr.tx_destroy_buffer()
        self.sdr.tx((2 ** 14 * 0.5 * np.exp(2j * np.pi * tone / FS * np.arange(N))).astype(np.complex64))

    def stop_tx(self):
        self.sdr.tx_destroy_buffer()

    def capture(self, lo):
        self.sdr.rx_lo = int(lo)
        for _ in range(3):
            self.sdr.rx()
        return np.asarray(self.sdr.rx())


class UsrpRadio:
    def __init__(self, token, args):
        from remoterf.drivers.usrp import MultiUSRP

        self.usrp = MultiUSRP(token)
        self.args = args
        if args.usrp_rx_antenna:
            self.usrp.set_rx_antenna(args.usrp_rx_antenna, 0)
        self.thread = None

    def start_tx(self, lo, tone, seconds):
        wave = (0.5 * np.exp(2j * np.pi * tone / FS * np.arange(N))).astype(np.complex64)
        self.thread = threading.Thread(
            target=self.usrp.send_waveform, args=(wave, seconds, lo, FS, [0], self.args.usrp_tx_gain), daemon=True)
        self.thread.start()
        time.sleep(1.5)  # tune + stream start on the owner

    def stop_tx(self):
        if self.thread:
            self.thread.join()
            self.thread = None

    def capture(self, lo):
        return np.asarray(self.usrp.recv_num_samps(65536, lo, FS, [0], self.args.rx_gain)).reshape(-1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True)
    ap.add_argument("--cert-port", type=int, required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--tx", type=int, required=True, help="device alias as listed to this user")
    ap.add_argument("--rx", required=True, help="comma-separated aliases")
    ap.add_argument("--los", default="915e6,2.4e9")
    ap.add_argument("--tones", default="100e3,-150e3")
    ap.add_argument("--pluto-tx-gain", type=float, default=-10)
    ap.add_argument("--usrp-tx-gain", type=float, default=60)
    ap.add_argument("--usrp-rx-antenna", default="TX/RX", help="e.g. TX/RX or RX2 (UHD default RX2)")
    ap.add_argument("--rx-gain", type=float, default=50)
    ap.add_argument("--min-snr", type=float, default=15)
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    configure(args.home, args.cert_port)
    user, pw = args.user, args.password
    if "UC" not in acc("login", un=user, pw=pw):
        sys.exit("login failed")
    devices = acc("get_dev", un=user, pw=pw)
    aliases = [args.tx] + [int(x) for x in args.rx.split(",")]
    for res_id, row in acc("get_res", un=user, pw=pw).items():
        if str(row).split(",")[0] == user:
            acc("cancel_res", un=user, pw=pw, res_id=int(res_id))
    start = datetime.now().replace(microsecond=0) - timedelta(minutes=1)
    end = start + timedelta(minutes=20)
    tokens = {}
    for alias in aliases:
        reply = acc("reserve_device", un=user, pw=pw, dd=alias, st=int(start.timestamp()), et=int(end.timestamp()))
        if "Token" not in reply:
            sys.exit(f"reserve {alias} {devices.get(str(alias))} refused: {reply}")
        tokens[alias] = reply["Token"]
        log(f"reserved {alias} {devices[str(alias)]}")

    from remoterf.core import direct_path

    host, port = args.home.rsplit(":", 1)
    direct_path.start(username=user, secret=pw, route={"kind": "lan", "host": host, "port": int(port)})
    report = {"user": user, "home": args.home, "tx": [args.tx, devices[str(args.tx)]],
              "rx": [[a, devices[str(a)]] for a in aliases[1:]], "runs": []}
    radios = {}
    try:
        for alias in aliases:
            label = str(devices[str(alias)])
            radios[alias] = (UsrpRadio if is_usrp(label) else PlutoRadio)(tokens[alias], args)
            path = direct_path._partners.get(tokens[alias])
            log(f"{alias} {label}: {'usrp' if is_usrp(label) else 'pluto'}, path {path.describe() if path else 'none'}")
        tx = radios[args.tx]
        tones = [float(t) for t in args.tones.split(",")]
        for lo in (float(x) for x in args.los.split(",")):
            peaks = {a: [] for a in aliases[1:]}
            for tone in tones:
                tx.start_tx(lo, tone, seconds=4 + 3 * len(aliases))
                for a in aliases[1:]:
                    peak, snr = tone_check(radios[a].capture(lo), tone)
                    peaks[a].append((peak, snr))
                    log(f"LO {lo/1e6:.0f} MHz tone {tone/1e3:+.0f} kHz -> rx {a}: peak {peak/1e3:+.1f} kHz, SNR {snr:.1f} dB")
                tx.stop_tx()
            for a, got in peaks.items():
                step = got[1][0] - got[0][0]
                ok = abs(step - (tones[1] - tones[0])) <= 2 * FS / 8192 and min(s for _, s in got) >= args.min_snr
                offset = got[0][0] - tones[0]
                log(f"LO {lo/1e6:.0f} MHz rx {a}: step {step/1e3:+.1f} kHz, offset {offset/1e3:+.1f} kHz {'OK' if ok else 'FAIL'}")
                report["runs"].append({"lo": lo, "rx": a, "peaks": got, "step": step, "offset": offset, "ok": ok})
    finally:
        for radio in radios.values():
            try:
                radio.stop_tx()
            except Exception as exc:  # noqa: BLE001
                log(f"stop_tx: {exc}")
        for res_id, row in acc("get_res", un=user, pw=pw).items():
            if str(row).split(",")[0] == user:
                acc("cancel_res", un=user, pw=pw, res_id=int(res_id))
        direct_path.stop()
        if args.report:
            Path(args.report).write_text(json.dumps(report, indent=2, default=str))
    sys.exit(0 if report["runs"] and all(r["ok"] for r in report["runs"]) else 5)


if __name__ == "__main__":
    main()
