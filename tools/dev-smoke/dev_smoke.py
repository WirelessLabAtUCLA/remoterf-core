#!/usr/bin/env python3
"""Smoke test of the dev stack with the real client: client -> dev Global -> test lab.

Checks, in order, exiting 1 at the first failure:
  (a) /ready on the Global origin, then login without prompts;
  (b) the account sees at least one online simulated SDR (device_type sim_sdr);
  (c) a short reservation on one and an rx() of N samples: complex, not all
      zero, the simulated tone at sample_rate/8 (FFT bin N/8).

Env: RRF_SMOKE_USER, RRF_SMOKE_PASSWORD (required);
     REMOTERF_GLOBAL_ORIGIN (default https://dev.global.remoterf.net).
--register creates the account first (dev Global signup; no email there).
"""
import os
import sys
import tempfile
import time
import urllib.request

ORIGIN = os.environ.setdefault("REMOTERF_GLOBAL_ORIGIN", "https://dev.global.remoterf.net").rstrip("/")
N = 4096


def check(ok, what):
    print(f"{'ok  ' if ok else 'FAIL'} {what}", flush=True)
    if not ok:
        sys.exit(1)


def main():
    user, password = os.environ["RRF_SMOKE_USER"], os.environ["RRF_SMOKE_PASSWORD"]
    # The client keeps its session and drivers under HOME: never the caller's.
    os.environ["HOME"] = tempfile.mkdtemp(prefix="rrf-smoke-")
    os.environ.pop("XDG_CONFIG_HOME", None)
    os.environ.setdefault("REMOTERF_DIRECT", "0")  # through Global, the path every client has

    import numpy as np
    from remoterf.deployment.backend import HttpsJsonAccountBackend
    from remoterf.deployment.state import origin, select_target

    with urllib.request.urlopen(ORIGIN + "/ready", timeout=15) as reply:
        check(reply.status == 200, f"{ORIGIN}/ready")

    backend = HttpsJsonAccountBackend(origin(ORIGIN))
    select_target({"origin": origin(ORIGIN), "transport": "https-json",
                   "deployment_id": backend.capabilities["deployment_id"]})
    if "--register" in sys.argv:
        backend.register(user, f"{user}@example.org", password)
        print(f"registered {user}")
    backend.login(user, password)
    check(True, f"login {user}")

    sims = [d for d in backend.devices()["devices"] if d.get("device_type") == "sim_sdr" and d.get("online")]
    check(bool(sims), f"online sim_sdr devices: {[(d['display_name'], d['deployment_name']) for d in sims]}")

    from remoterf.drivers.sim_sdr import SimSDR

    start = int(time.time()) // 60 * 60
    for dev in sims:  # the first free one
        try:
            reservation = backend.reserve(dev["device_id"], start, start + 600)
            break
        except Exception as exc:  # noqa: BLE001 - taken: try the next
            print(f"     {dev['display_name']}: {exc}")
    else:
        check(False, "reserve a sim_sdr")
    check(True, f"reserved {dev['display_name']}@{dev['deployment_name']}")
    try:
        sdr = SimSDR(reservation.get("token") or reservation["device_id"])
        sdr.rx_buffer_size = N
        iq = np.asarray(sdr.rx())
        peak = int(np.argmax(np.abs(np.fft.fft(iq)))) if iq.shape == (N,) else -1
        check(iq.shape == (N,) and np.iscomplexobj(iq) and np.any(iq) and peak == N // 8,
              f"rx {iq.shape} {iq.dtype}, FFT peak bin {peak} (want {N // 8})")
    finally:
        backend.cancel(reservation["reservation_id"])
    print("PASS")


if __name__ == "__main__":
    main()
