#!/usr/bin/env python3
"""Launch N soak workers against one direction and summarize their reports.

  soak_run.py fwd|rev --workers N --minutes M [--samples S] [--direct 0|1]

fwd: HOME rrf2 (ucla) -> owner otheruni.   rev: HOME otheruni -> owner ucla.
Workers register on first use (group code) and enroll with one cluster code
each; reruns tolerate "already exists" / "code used".
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

DIRECTIONS = {
    "fwd": {
        "home": "164.67.195.210:61005", "cert_port": 61006, "owner": "otheruni", "register": "SOAKREG1",
        "users": [f"soak{i}" for i in range(1, 8)],
        "codes": [],  # mint with `cluster codes create` (or cluster.mint_codes) and list them here
    },
    "rev": {
        "home": "164.67.195.207:61005", "cert_port": 61006, "owner": "ucla", "register": "SOAKREG2",
        "users": [f"soakr{i}" for i in range(1, 5)],
        "codes": [],  # mint with `cluster codes create` (or cluster.mint_codes) and list them here
    },
}
PYTHON = os.path.expanduser("~/remoterf-phase1-live/venv/bin/python")
ROOT = Path(os.path.expanduser("~/soak"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("direction", choices=DIRECTIONS)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--minutes", type=float, default=5)
    ap.add_argument("--samples", type=int, default=262144)
    ap.add_argument("--direct", default="1")
    ap.add_argument("--tag", default=time.strftime("%H%M%S"))
    ap.add_argument("--idle-seconds", type=float, default=0)
    args = ap.parse_args()
    d = DIRECTIONS[args.direction]
    run_dir = ROOT / f"run-{args.direction}-{args.tag}"
    run_dir.mkdir(parents=True)
    procs = []
    for i in range(args.workers):
        user = d["users"][i]
        home = ROOT / f"{args.direction}-home{i + 1}"
        home.mkdir(exist_ok=True)
        cmd = [PYTHON, str(ROOT / "soak_client.py"), "--home", d["home"], "--cert-port", str(d["cert_port"]),
               "--user", user, "--password", f"{user}-pass-2026", "--device", "SimSDR", "--owner", d["owner"],
               "--minutes", str(args.minutes), "--samples", str(args.samples),
               "--report", str(run_dir / f"{user}.json"), "--idle-seconds", str(args.idle_seconds)]
        if not (home / ".enrolled").exists() and i < len(d["codes"]):
            cmd += ["--register-code", d["register"], "--cluster-code", d["codes"][i]]
        env = {**os.environ, "HOME": str(home), "REMOTERF_DIRECT": args.direct}
        log = open(run_dir / f"{user}.log", "w")
        procs.append((user, home, subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT), log))
        time.sleep(1.5)  # stagger the offers a little, as real users would
    rows = []
    for user, home, proc, log in procs:
        rc = proc.wait()
        log.close()
        report = run_dir / f"{user}.json"
        summary = json.loads(report.read_text()).get("summary", {}) if report.exists() else {}
        if summary.get("calls"):
            (home / ".enrolled").touch()
        rows.append((user, rc, summary))
    print(f"\n== {args.direction} x{args.workers} {args.minutes} min, {args.samples} samples/call, direct={args.direct} ==")
    total_calls = total_mb = 0
    for user, rc, s in rows:
        lat = s.get("latency_ms", {})
        print(f"{user:8} rc={rc} calls={s.get('calls', 0):5} bad={s.get('bad_buffers', 0)} resets={s.get('resets', 0)} err={s.get('errors', 0)} "
              f"MB={s.get('mbytes', 0):8} {s.get('mb_per_s', 0):6} MB/s p50={lat.get('p50')} p95={lat.get('p95')} "
              f"max={lat.get('max')} paths={s.get('path_states')} final={s.get('path_final')}")
        total_calls += s.get("calls", 0)
        total_mb += s.get("mbytes", 0)
    print(f"total calls={total_calls} MB={total_mb:.0f} aggregate={total_mb / (args.minutes * 60):.1f} MB/s")
    for user, rc, s in rows:
        for e in s.get("error_samples", []):
            print(f"  {user}: {e}")
    sys.exit(0 if all(rc == 0 for _, rc, _ in rows) else 1)


if __name__ == "__main__":
    main()
