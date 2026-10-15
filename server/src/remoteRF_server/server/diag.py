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

"""`diag [--force] [--copy]`: the thorough version of the startup check.

Each device type with a diag script (DIAG_MODULES) runs that script's tests one
by one while diag holds the device's io_lock and device_manager refuses its
calls, sessions and new reservations. A device reserved now, in a live
session, or reserved to start before its tests would end is skipped unless
--force, which pauses every client's device traffic for the whole run.

A diag script is a module with TESTS = [(name, typical_s, timeout_s, fn)],
where typical_s may be a callable(schema); fn(ctx) returns a detail string or
(detail, values), raises Skip when the test does not apply, and anything else
fails it. The first test is the gate: when it fails nothing else runs.
Optional teardown(ctx) and TEARDOWN_S = (typical_s, timeout_s) put the device
back (a PoE Pluto to standby)."""

from __future__ import annotations

import importlib
import json
import os
import shutil
import sys
import threading
import time
import traceback
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path

from ..common.utils import Sty
from ..common.utils.panel import confirm, print_table
from . import device_manager as dm
from .startup_check import _Display, _flush_all, _log, _new_log, _redirected, _short, _start, _terminal, _wait

DIAG_MODULES = {
    "adalm_pluto": "remoteRF_server.drivers.adalm_pluto.pluto_diag",
    "adalm_pluto_mimo": "remoteRF_server.drivers.adalm_pluto.pluto_diag",
    "pluto_plus": "remoteRF_server.drivers.adalm_pluto.pluto_diag",
    "rtl_sdr": "remoteRF_server.drivers.rtl_sdr.rtl_sdr_diag",
    "usrp": "remoteRF_server.drivers.usrp.usrp_diag",
    "gps": "remoteRF_server.drivers.gps_diag",
    "bluetooth": "remoteRF_server.drivers.bluetooth_diag",
    "kraken_sdr": "remoteRF_server.drivers.kraken_sdr_diag",
    "rfbeam_kmd7": "remoteRF_server.drivers.rfbeam_kmd7_diag",
}
MARGIN_S = 60  # a reservation starting before a device's tests end + this skips it
LOCK_WAIT_S = 10
STRAY_WAIT_S = 15  # a timed-out or interrupted test gets this long to stop before restore runs


class Skip(Exception):
    """The test does not apply to this device (not counted as passed or failed)."""


class Guard:
    """A test's view of a device object: once `stop` is set (the test timed out or
    was interrupted) any access raises, so its abandoned thread cannot drive the
    device after restore and release."""

    def __init__(self, obj, stop: threading.Event):
        self._obj, self._stop = obj, stop

    def __getattr__(self, name):
        if self._stop.is_set():
            raise RuntimeError("diag stopped this test")
        return getattr(self._obj, name)


def _fmt(seconds: float) -> str:
    m, s = divmod(int(round(max(0.0, seconds))), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


def _typical(t, schema) -> float:
    return float(t(schema) if callable(t) else t)


def device_eta(mod, schema) -> float:
    return sum(_typical(t[1], schema) for t in mod.TESTS) + getattr(mod, "TEARDOWN_S", (0, 0))[0]


def _inits() -> dict:
    try:
        return {gid: rec.get("INIT") or {} for gid, rec in dm._load_device_records().items()}
    except Exception:  # noqa: BLE001 - only Multi-Tap detection needs it
        return {}


def _reservation_windows(gid: int) -> list:
    from .reservation import reservation_handler

    return reservation_handler.reservation_windows(gid)


def _live_session(gid: int) -> bool:
    from .dynamic_v2 import session_manager

    return session_manager.busy(gid)


def _busy(gid: int, st, eta: float, force: bool) -> str | None:
    """Why this device must not be tested now, or None."""
    if _live_session(gid):
        return "in a live session"  # its session holds the hardware, --force or not
    if force:
        return None
    if st.salt or st.hsh:
        return "reserved now"
    now = time.time()
    for start, end in _reservation_windows(gid):
        if start.timestamp() < now + eta + MARGIN_S and end.timestamp() > now:
            return f"reserved from {start:%H:%M}"
    return None


def _plan(force: bool):
    with dm._state_lock:
        states = sorted((gid, st) for gid, st in dm._devices.items() if st.origin == "local")
    rows = []
    for gid, st in states:
        row = {"device_id": gid, "name": st.name, "type": st.dtype, "tests": [], "st": st}
        mod = importlib.import_module(DIAG_MODULES[st.dtype]) if st.dtype in DIAG_MODULES else None
        if mod is None:
            row.update(status="no diag script")
        elif st.dev is None:
            row.update(status="issues", seconds=0, tests=[
                {"name": "open", "status": "fail", "detail": "the device did not open (see the startup log)"}])
        else:
            row.update(mod=mod, eta=device_eta(mod, st.dev))
            reason = _busy(gid, st, row["eta"], force)
            if reason:
                row.update(status=f"skipped: {reason}")
        rows.append(row)
    return rows


def _run_one(row: dict, init: dict, display: _Display, log_fd: int, left_after: float,
             force: bool = False) -> None:
    """Every test of one device, under its io_lock; fills row["tests"] and row["status"]."""
    st, mod, gid = row["st"], row["mod"], row["device_id"]
    label = f"[{gid}] {st.name}"
    if not st.io_lock.acquire(timeout=LOCK_WAIT_S):
        row["status"] = "skipped: busy"
        return
    stop = threading.Event()
    stray = []  # futures of tests abandoned on a timeout or Ctrl-C
    ctx = {"schema": Guard(st.dev, stop), "type": st.dtype, "init": init, "name": st.name, "stop": stop,
           "reserved": lambda: bool(st.salt and st.hsh)}
    teardown = getattr(mod, "teardown", None)
    restore_s = getattr(mod, "TEARDOWN_S", (1, 30))
    typical = [_typical(t[1], st.dev) for t in mod.TESTS] + ([restore_s[0]] if teardown else [])
    started_at = time.monotonic()
    ran = False

    def step(i: int, name: str, timeout: float, fn, step_ctx: dict) -> bool:
        """Run one test; True when it timed out."""
        _log(log_fd, f"\n--- {label} · {name}\n")
        t0 = time.monotonic()

        def spin():
            left = sum(typical[i + 1:]) + max(0.0, typical[i] - (time.monotonic() - t0)) + left_after
            return f"{label} · {name} ({i + 1}/{len(typical)}) · ~{_fmt(left)} left"

        entry = {"name": name, "status": "pass", "detail": "", "values": {}}
        timed_out = False
        fut = _start(fn, step_ctx)
        try:
            out = _wait(display, fut, t0 + timeout, spin)
            entry["detail"], entry["values"] = out if isinstance(out, tuple) else (out or "ok", {})
        except FutureTimeout:
            entry.update(status="fail", detail=f"no answer after {timeout} s")
            timed_out = True
            stray.append(fut)
            stop.set()
        except KeyboardInterrupt:
            stray.append(fut)
            stop.set()
            raise
        except Skip as exc:
            entry.update(status="skip", detail=str(exc))
        except Exception as exc:  # noqa: BLE001 - the device's failure, recorded
            entry.update(status="fail", detail=_short(exc, 120) or type(exc).__name__)
            _log(log_fd, "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
        entry["seconds"] = round(time.monotonic() - t0, 2)
        _log(log_fd, f"{label} {name}: {entry['status']} {entry['detail']}\n")
        row["tests"].append(entry)
        return timed_out

    try:
        dm.diag_hold(gid, time.time() + row["eta"] + MARGIN_S)
        # Again now that the hold refuses new sessions and reservations: the plan is minutes old.
        reason = _busy(gid, st, row["eta"], force)
        if reason:
            row["status"] = f"skipped: {reason}"
            return
        ran = True
        dm._reset_locked(st)
        halted = None
        for i, (name, _, timeout, fn) in enumerate(mod.TESTS):
            if not halted and not force and (st.salt or st.hsh):
                halted = "a reservation started"
            if halted:
                row["tests"].append({"name": name, "status": "skip", "detail": f"not run: {halted}"})
            elif step(i, name, timeout, fn, ctx):
                halted = f"{name} timed out"
            elif i == 0 and row["tests"][-1]["status"] == "fail":
                halted = f"{name} failed"
    finally:
        try:
            if stray:  # let the abandoned test see `stop` before restore touches the device
                try:
                    stray[-1].exception(timeout=STRAY_WAIT_S)
                except BaseException:  # noqa: BLE001 - a second Ctrl-C must not skip restore
                    pass
            if ran and teardown is not None:  # Ctrl-C included: a PoE Pluto must not stay on
                step(len(typical) - 1, "restore", restore_s[1], teardown, {**ctx, "schema": st.dev})
        finally:
            wedged = [f for f in stray if not f.done()]
            if wedged:  # its thread may still drive the device: keep refusing clients until it ends
                dm.diag_hold(gid, float("inf"))

                def _release(_f, fs=wedged):
                    if all(f.done() for f in fs):
                        dm.diag_release(gid)

                for f in wedged:
                    f.add_done_callback(_release)
                row["tests"].append({"name": "release", "status": "fail",
                                     "detail": "a test is still running; clients stay refused until it ends"})
            else:
                dm.diag_release(gid)
            st.io_lock.release()
            _flush_all()
    row["seconds"] = round(time.monotonic() - started_at, 1)
    row["status"] = "issues" if _failed(row) else "ok"


def _failed(row: dict) -> list[str]:
    return [t["name"] for t in row["tests"] if t["status"] == "fail"]


def _counts(row: dict) -> str:
    ran = [t for t in row["tests"] if t["status"] != "skip"]
    return f"{sum(t['status'] == 'pass' for t in ran)}/{len(ran)}" if row["tests"] else "-"


def _line(display: _Display, row: dict) -> None:
    label = f"[{row['device_id']}] {row['name']}"
    if row["status"] in ("ok", "issues"):
        failed = _failed(row)
        detail = f"{_counts(row)} passed · {_fmt(row['seconds'])}"
        if failed:
            detail += f" · failed: {', '.join(failed)}"
        display.result(not failed, label, detail)
        for t in row["tests"]:
            if t["status"] == "fail":
                display._print(f"    {t['name']}: {t['detail']}", Sty.GRAY)
    else:
        display._print(f"{'–' if display.uni else '-'} {label} · {row['status']}", Sty.GRAY)


def _text_report(rows: list[dict], header: str) -> str:
    out = [header, ""]
    for row in rows:
        out.append(f"[{row['device_id']}] {row['name']} ({row['type']}): {row['status']}, {_counts(row)} passed")
        for t in row["tests"]:
            out.append(f"    {t['status'].upper():<4}  {t['name']:<16} {t['detail']}")
        out.append("")
    return "\n".join(out)


def _save(rows: list[dict], log_path: Path, header: str) -> list[Path]:
    keep = ("device_id", "name", "type", "status", "seconds", "tests")
    data = {"header": header, "devices": [{k: r[k] for k in keep if k in r} for r in rows]}
    js, txt = log_path.with_suffix(".json"), log_path.with_suffix(".txt")
    js.write_text(json.dumps(data, indent=2, default=str) + "\n")
    txt.write_text(_text_report(rows, header) + "\n")
    return [txt, js]


def _copy(paths: list[Path]) -> None:
    dest = Path.home() / "Downloads"
    dest.mkdir(parents=True, exist_ok=True)
    for p in paths:
        shutil.copy2(p, dest / p.name)
    print(f"Copied {', '.join(p.name for p in paths)} to {dest}")


def run(*, force: bool = False, copy: bool = False, ask=None, cfg_dir: Path | None = None) -> int:
    """0 when every tested device passed; 1 otherwise (or cancelled)."""
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    rows = _plan(force)
    todo = [r for r in rows if "mod" in r and "status" not in r]
    total = sum(r["eta"] for r in todo)
    if force and todo:
        reserved = [r["name"] for r in todo if r["st"].salt or r["st"].hsh]
        print(f"diag --force pauses every client's device traffic for ~{_fmt(total)}"
              + (f" and tests reserved devices: {', '.join(reserved)}" if reserved else "") + ".")
        if interactive and not confirm("Continue?", default=False, ask=ask):
            print("Cancelled.")
            return 1
    try:
        log_path = _new_log(Path(cfg_dir or dm._cfg_dir()), "diag")
        log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    except OSError as exc:
        print(f"diag: cannot write its log: {exc}", file=sys.stderr)
        return 1
    header = (f"RemoteRF diag {log_path.stem[5:]} · {len(todo)} of {len(rows)} devices"
              + (" · --force" if force else ""))
    inits = _inits()
    _flush_all()
    display = _Display(_terminal())
    interrupted = False
    try:
        display._print(f"Diagnosing {len(todo)} of {len(rows)} devices", Sty.BOLD,
                       f" · ETA ~{_fmt(total)} · Ctrl-C cancels" if todo else "", Sty.GRAY)
        left = total
        try:
            if force:
                dm.diag_hold(None, time.time() + total + MARGIN_S)
            with _redirected(log_fd):
                for row in rows:
                    if "mod" in row and "status" not in row:
                        left -= row["eta"]
                        try:
                            _run_one(row, inits.get(row["device_id"], {}), display, log_fd, left, force)
                        except KeyboardInterrupt:
                            row["status"] = "interrupted"
                            interrupted = True
                    display.clear()
                    _line(display, row)
                    if interrupted:
                        break
        finally:
            if force:
                dm.diag_release(None)
            display.clear()
        tested = [(r["name"], r["status"] == "ok") for r in rows if r.get("status") in ("ok", "issues")]
        if tested:
            display.summary(tested, "passed")
        display._print(f"log: {log_path}", Sty.GRAY)
    finally:
        display.out.close()
        os.close(log_fd)
    if interrupted:
        header += " · interrupted"
    for row in rows:
        row.setdefault("status", "not run")
    print_table("Diagnostics", [
        {"device_id": r["device_id"], "name": r["name"], "type": r["type"], "tests": _counts(r),
         "status": r["status"], "failed": _short(", ".join(_failed(r)), 40) or "-"}
        for r in rows
    ], ["device_id", "name", "type", "tests", "status", "failed"], empty="No local devices.")
    saved = _save(rows, log_path, header)
    print(f"Results: {saved[0]}")
    if copy or (interactive and confirm("Copy diag results to your Downloads folder?", ask=ask)):
        _copy(saved)
    return 1 if interrupted or any(r["status"] == "issues" for r in rows) else 0
