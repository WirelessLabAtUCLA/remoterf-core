#!/usr/bin/env python3
"""One federated soak worker: a native user of HOME drives a partner lab's
device, through the real Client library, and reports what happened.

register -> login -> cluster enroll -> reserve <device>@<owner> -> ensure_driver
-> rx() in a loop for --minutes, verifying every buffer (length, dtype, the
simulated tone at fs/8) and recording latency and which path carried it.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def acc(name, **kw):
    from remoterf.common.utils import map_arg, unmap_arg
    from remoterf.core.grpc_client import rpc_client

    response = rpc_client(function_name=f"ACC:{name}", args={k: map_arg(v) for k, v in kw.items()})
    return {k: unmap_arg(v) for k, v in response.results.items()}


def configure(home, cert_port):
    from remoterf.config.cert_fetcher import fetch_ca_bytes

    host = home.rsplit(":", 1)[0]
    cfg = Path.home() / ".config" / "remoterf-client"
    (cfg / "certs").mkdir(parents=True, exist_ok=True)
    ca = cfg / "certs" / "home.crt"
    ca.write_bytes(fetch_ca_bytes(host, cert_port, timeout_sec=10))
    (cfg / ".env").write_text(f"REMOTERF_ADDR={home}\nREMOTERF_CA_CERT={ca}\nREMOTERF_PROFILE=soak\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True, help="host:port of the HOME's gRPC listener")
    ap.add_argument("--cert-port", type=int, required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--register-code", default=None, help="a group enrollment code at HOME")
    ap.add_argument("--cluster-code", default=None, help="cluster.XXXX, single use")
    ap.add_argument("--device", default="SimSDR")
    ap.add_argument("--owner", default=None, help="partner display name, e.g. otheruni")
    ap.add_argument("--minutes", type=float, default=2.0)
    ap.add_argument("--samples", type=int, default=500_000)
    ap.add_argument("--reserve-minutes", type=int, default=25)
    ap.add_argument("--report", default=None)
    ap.add_argument("--keep-reservation", action="store_true")
    ap.add_argument("--idle-seconds", type=float, default=0, help="after 60 s of calls, sit idle this long, then resume")
    args = ap.parse_args()

    configure(args.home, args.cert_port)
    user, pw = args.user, args.password
    report = {"user": user, "home": args.home, "started": datetime.now().isoformat(), "events": []}

    def event(kind, **detail):
        report["events"].append({"t": time.time(), "kind": kind, **detail})
        log(f"{kind} {detail}")

    login = acc("login", un=user, pw=pw)
    if "UC" not in login and args.register_code:
        # Only a new user registers: the Client library prompts on a UE reply.
        event("register", reply=acc("create_user", un=user, pw=pw, em=f"{user}@soak.invalid", ec=args.register_code))
        login = acc("login", un=user, pw=pw)
    if "UC" not in login:
        event("login_failed", reply=login)
        sys.exit(2)
    devices = acc("get_dev", un=user, pw=pw)
    if args.cluster_code and not any(" @" in str(v) for v in devices.values()):
        event("enroll", reply=acc("set_enroll", un=user, pw=pw, ec=args.cluster_code))
        devices = acc("get_dev", un=user, pw=pw)
    partner = {k: v for k, v in devices.items() if " @" in str(v)}
    event("devices", partner=len(partner), local=len(devices) - len(partner))
    wanted = sorted(
        (int(k), v) for k, v in partner.items()
        if str(v).startswith(args.device) and "(online)" in str(v) and (args.owner is None or f"@{args.owner}" in str(v))
    )
    if not wanted:
        event("no_partner_device", listing=devices)
        sys.exit(3)

    # A rerun still holds yesterday's rows: clear my own first.
    for res_id, row in acc("get_res", un=user, pw=pw).items():
        parts = str(row).split(",")
        if parts[0] == user:
            event("cancel_stale", res_id=res_id, reply=acc("cancel_res", un=user, pw=pw, res_id=int(res_id)))
    start = datetime.now().replace(microsecond=0) - timedelta(minutes=1)
    end = start + timedelta(minutes=args.reserve_minutes + 1)
    token = alias = label = None
    for candidate, candidate_label in wanted:  # the first free one is mine
        reserved = acc("reserve_device", un=user, pw=pw, dd=candidate, st=int(start.timestamp()), et=int(end.timestamp()))
        if "Token" in reserved:
            token, alias, label = reserved["Token"], candidate, candidate_label
            break
        event("reserve_refused", alias=candidate, reply=reserved)
    if token is None:
        event("reserve_failed", tried=len(wanted))
        sys.exit(4)
    event("reserved", alias=alias, label=label)

    from remoterf.core import direct_path
    from remoterf.drivers import ensure_driver

    host, port = args.home.rsplit(":", 1)
    direct_path.start(username=user, secret=pw, route={"kind": "lan", "host": host, "port": int(port)})
    t0 = time.monotonic()
    ensure_driver(token=token)
    event("driver", seconds=round(time.monotonic() - t0, 3), partner_marked=direct_path.partner_of(token))

    import importlib

    import numpy as np

    module = importlib.import_module("remoterf.drivers.sim_sdr")
    cls = next(getattr(module, n) for n in dir(module) if n.lower() == "simsdr" or n == "SimSDR")
    dev = cls(token)
    api = [n for n in dir(dev) if not n.startswith("_")]
    event("api", names=api[:40])
    rx = dev.rx if hasattr(dev, "rx") else dev.call_rx

    def set_buffer():
        if hasattr(type(dev), "rx_buffer_size"):
            dev.rx_buffer_size = args.samples
        else:
            dev.set_rx_buffer_size(args.samples)

    set_buffer()
    latencies, states, errors, nbytes = [], {}, [], 0
    started = time.monotonic()
    deadline = started + args.minutes * 60
    last_progress = time.monotonic()
    calls = bad = resets = 0
    idled = False
    while time.monotonic() < deadline:
        if args.idle_seconds and not idled and time.monotonic() - started > 60:
            idled = True
            event("idle_start", seconds=args.idle_seconds, path=(direct_path._partners.get(token) or direct_path).describe())
            time.sleep(args.idle_seconds)
            deadline += args.idle_seconds
            event("idle_end", path=(direct_path._partners.get(token) or direct_path).describe())
        t1 = time.monotonic()
        try:
            iq = rx()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{type(exc).__name__}: {str(exc)[:160]}")
            log(f"rx error: {errors[-1]}")
            time.sleep(1.0)
            continue
        dt = time.monotonic() - t1
        iq = np.asarray(iq)
        if iq.shape != (args.samples,) and np.iscomplexobj(iq) and iq.size < args.samples:
            # A restarted owner has a fresh device: settings are gone, as on any restart.
            resets += 1
            log(f"short buffer {iq.shape}: re-applying rx_buffer_size")
            try:
                set_buffer()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"reset: {type(exc).__name__}: {str(exc)[:120]}")
                time.sleep(1.0)
            continue
        ok = iq.shape == (args.samples,) and np.iscomplexobj(iq)
        if ok and args.samples >= 4096:
            peak = int(np.argmax(np.abs(np.fft.fft(iq[:4096]))))
            ok = peak == 512  # the simulated tone sits at fs/8
        calls += 1
        bad += not ok
        latencies.append(dt)
        nbytes += iq.nbytes
        path = direct_path._partners.get(token)
        state = path.state if path is not None else "none"
        states[state] = states.get(state, 0) + 1
        if time.monotonic() - last_progress > 30:
            last_progress = time.monotonic()
            log(f"{calls} calls, {bad} bad, {len(errors)} errors, last {dt*1000:.0f} ms, "
                f"{iq.nbytes/dt/1e6:.1f} MB/s, path {state}"
                + (f" ({path.describe()})" if path else ""))

    path = direct_path._partners.get(token)
    summary = {
        "calls": calls, "bad_buffers": bad, "resets": resets, "errors": len(errors), "error_samples": errors[:5],
        "seconds": round(args.minutes * 60, 1), "mbytes": round(nbytes / 1e6, 1), "idle_seconds": args.idle_seconds,
        "mb_per_s": round(nbytes / 1e6 / max(1e-9, sum(latencies)), 2) if latencies else 0,
        "latency_ms": {
            "p50": round(statistics.median(latencies) * 1000, 1) if latencies else None,
            "p95": round(sorted(latencies)[int(len(latencies) * 0.95) - 1] * 1000, 1) if len(latencies) >= 20 else None,
            "max": round(max(latencies) * 1000, 1) if latencies else None,
        },
        "path_states": states, "path_final": path.describe() if path else "none", "path_calls": path.calls if path else 0,
    }
    report["summary"] = summary
    event("done", **summary)
    if not args.keep_reservation:
        for res_id, row in acc("get_res", un=user, pw=pw).items():
            parts = str(row).split(",")
            if parts[0] == user and parts[1] == str(alias):
                event("cancel", res_id=res_id, reply=acc("cancel_res", un=user, pw=pw, res_id=int(res_id)))
    direct_path.stop()
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2, default=str))
    sys.exit(0 if calls and not bad and len(errors) < max(3, calls // 20) else 5)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        sys.exit(1)
