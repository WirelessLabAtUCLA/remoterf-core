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

"""Startup device check: open every local device quietly, test each one, and
show one line per device plus a summary. Everything the drivers print,
C libraries writing straight to fd 1/2 included, goes to
<config>/logs/startup-<UTC>.log instead of the console."""

from __future__ import annotations

import ctypes
import os
import shutil
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from concurrent.futures import Future, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from pathlib import Path

from prompt_toolkit import print_formatted_text

from ..common.utils import Sty, stylize
from ..common.utils.ansi_codes import style
from ..common.utils.panel import supports_unicode
from ..drivers.adalm_pluto.poe import PoePluto
from . import device_manager as dm

DEADLINE_S = 120  # all device checks, counted from when opening finishes (opening is unbounded, as before)
POE_TIMEOUT_S = 90  # power off, OFF_S, boot (BOOT_TIMEOUT_S), IIO context
CHECK_TIMEOUT_S = 15
GPS_WAIT_S = 5
KEEP_LOGS = 10
MIN_FREE_BYTES = 16 << 20  # less than this: open the devices without capture
FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def enabled() -> bool:
    return os.getenv("REMOTERF_STARTUP_TEST", "1").strip().lower() not in ("0", "false", "no", "off")


def _start(fn, *args) -> Future:
    """fn(*args) on a daemon thread: one that never returns cannot hold up exit."""
    fut: Future = Future()

    def run():
        try:
            fut.set_result(fn(*args))
        except BaseException as exc:  # noqa: BLE001 - handed to the waiter
            fut.set_exception(exc)

    threading.Thread(target=run, daemon=True, name="remoterf-startup-check").start()
    return fut


def _short(text: str, limit: int = 72) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _log(fd: int, text: str) -> None:
    try:
        os.write(fd, text.encode())
    except OSError:  # a full disk must not fail opening or the check
        pass


def _restore_power(st) -> None:
    """A tested PoE Pluto goes back to standby unless a reservation holds it (pre-warm keeps it on)."""
    with dm._state_lock:
        reserved = bool(st.salt and st.hsh)
    if not reserved:
        st.dev.call_power_down()


def _check(st) -> None:
    """Raise unless the device answers. Holds io_lock, so a call cannot reach it mid-check."""
    with st.io_lock:
        dev = st.dev
        native = getattr(dev, "device", None)
        if isinstance(native, PoePluto):
            # Its own RLock across cycle, read and restore: a close() (quit) runs after the restore.
            with native._lock:
                try:
                    if native.power_state != "on":  # already on: its reservation pre-warm booted it
                        native.power_cycle()
                    int(native.sample_rate)
                finally:
                    try:
                        _restore_power(st)
                    except Exception as exc:  # noqa: BLE001 - the check's own result matters more
                        print(f"could not return {st.name} to standby: {exc}")
        elif st.dtype == "rtl_sdr":
            dev.call_read_bytes(512)
        elif st.dtype == "gps":
            end = time.monotonic() + GPS_WAIT_S
            while not dev.call_read_raw(1):
                if time.monotonic() > end:
                    raise RuntimeError(f"no NMEA sentence in {GPS_WAIT_S} s")
                time.sleep(0.2)
        elif st.dtype == "bluetooth":
            if not dev.get_powered():
                raise RuntimeError("adapter is not powered")
        # ponytail: USRPs and other drivers count as operational once they open;
        # add a dtype branch here when one gets a cheap probe.


def _timeout_for(st) -> float:
    return POE_TIMEOUT_S if isinstance(getattr(st.dev, "device", None), PoePluto) else CHECK_TIMEOUT_S


class _Display:
    def __init__(self, out):
        self.out = out
        self.tty = out.isatty()
        self.uni = supports_unicode(getattr(out, "encoding", None))
        self.frame = 0

    def _print(self, *pairs, end="\n") -> None:
        if self.tty:
            self.out.write("\r\x1b[2K")
        print_formatted_text(stylize(*pairs), style=style, file=self.out, end=end)

    def spin(self, text: str) -> None:
        """Gray spinner line, redrawn in place; nothing at all off a TTY."""
        if not self.tty:
            return
        frames = FRAMES if self.uni else "|/-\\"
        self.frame += 1
        self._print(f"{frames[self.frame % len(frames)]} {text}", Sty.GRAY, end="")

    def clear(self) -> None:
        if self.tty:
            self.out.write("\r\x1b[2K")
            self.out.flush()

    def result(self, ok: bool, label: str, detail: str) -> None:
        unavailable = detail.startswith("No driver registered")
        mark = ("✓" if ok else "✗") if self.uni else ("ok" if ok else "x")
        if unavailable:
            self._print("–" if self.uni else "-", Sty.GRAY,
                        f" {label} · driver unavailable; skipped", Sty.GRAY)
        else:
            self._print(mark, Sty.BRIGHT_GREEN if ok else Sty.BRIGHT_RED,
                        f" {label} · {detail}", Sty.GRAY)

    def summary(self, results, word: str) -> None:
        n = len(results)
        ok = sum(1 for r in results if r[1])
        noun = "device" if n == 1 else "devices"
        if ok == n:
            self._print(f"All {n} {noun} {word}", Sty.BRIGHT_GREEN)
            return
        issues = ", ".join(r[0] for r in results if not r[1])
        self._print(f"{ok} of {n} {noun} {word}", Sty.YELLOW if ok else Sty.BRIGHT_RED,
                    f" · issues: {issues}", Sty.GRAY)


def _wait(display: _Display, fut: Future, until: float, text):
    """fut's result while a spinner shows `text` (a str or a callable); FutureTimeout once `until` passes."""
    while True:
        try:
            return fut.result(timeout=max(0.0, min(0.1, until - time.monotonic())))
        except FutureTimeout:
            if time.monotonic() >= until:
                raise
            display.spin(text() if callable(text) else text)


def _new_log(cfg_dir: Path, prefix: str = "startup") -> Path:
    logs = cfg_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    # A run's .log/.json/.txt share a stem: keep the newest runs whole.
    stems = sorted({path.name.split(".")[0] for path in logs.glob(f"{prefix}-*")})
    for stem in stems[: -(KEEP_LOGS - 1)]:
        for old in logs.glob(f"{stem}.*"):
            old.unlink(missing_ok=True)
    return logs / f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.log"


def _flush_all() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:  # noqa: BLE001
            pass
    try:
        ctypes.CDLL(None).fflush(None)  # C stdio buffers (librtlsdr, UHD) before fd 1/2 move
    except Exception:  # noqa: BLE001
        pass


def run(open_devices, *, cfg_dir: Path | None = None) -> None:
    """open_devices(on_device) opens the hardware (device_manager.reload_devices);
    its errors propagate as before. A failure of the check itself never does."""
    log_fd = -1
    try:
        log_path = _new_log(Path(cfg_dir or dm._cfg_dir()))
        if shutil.disk_usage(log_path.parent).free < MIN_FREE_BYTES:
            raise OSError("low disk space")
        log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.write(log_fd, b"remoterf startup check\n")
    except Exception as exc:  # noqa: BLE001 - no log: open the devices the old way
        if log_fd >= 0:
            os.close(log_fd)
        print(f"Warning: startup check log unavailable ({exc}); opening devices without it")
        open_devices(None)
        return

    _flush_all()
    display = _Display(_terminal())
    results = None
    try:
        try:
            with _redirected(log_fd):
                results = _run_captured(open_devices, display, log_fd, log_path)
        finally:
            display.clear()
            if results:
                display.summary(results, "operational" if enabled() else "opened")
            elif results == []:
                display._print("No local devices opened", Sty.YELLOW)
            display._print(f"log: {log_path}", Sty.GRAY)
    finally:
        display.out.close()
        os.close(log_fd)


def _terminal():
    """A writer on the real fd 1, which keeps reaching the terminal while _redirected() runs."""
    return os.fdopen(os.dup(1), "w", encoding=getattr(sys.stdout, "encoding", None) or "utf-8",
                     errors="replace")


@contextmanager
def _redirected(log_fd: int):
    """fd 1/2 (prints, C libraries) into log_fd for the block."""
    _flush_all()
    saved = (os.dup(1), os.dup(2))
    try:
        os.dup2(log_fd, 1)
        os.dup2(log_fd, 2)
        yield
    finally:
        _flush_all()
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        for fd in saved:
            os.close(fd)


def _run_captured(open_devices, display: _Display, log_fd: int, log_path: Path):
    marks: dict[int, int] = {}  # gid -> where its open output starts in the log
    breaks: list[int] = []  # where each device's "--- open" line starts
    current = {"name": "devices"}

    def on_device(gid: int, name: str) -> None:
        _flush_all()  # the previous device's buffered prints land in its own slice
        current["name"] = name
        breaks.append(os.fstat(log_fd).st_size)
        _log(log_fd, f"\n--- [{gid}] {name} · open\n")
        marks[gid] = os.fstat(log_fd).st_size

    # Opening has no deadline: no device is served before it finishes, as before.
    _wait(display, _start(open_devices, on_device), float("inf"), lambda: f"opening {current['name']}…")
    _flush_all()
    opened_end = os.fstat(log_fd).st_size

    try:
        with dm._state_lock:
            states = sorted((gid, st) for gid, st in dm._devices.items() if st.origin == "local")
        if not states:
            return []
        captured = log_path.read_bytes()

        def open_error(gid: int) -> str:
            """The last line its driver printed while opening it."""
            start = marks.get(gid)
            if start is None:
                return "not opened"
            end = min([b for b in breaks if b >= start] + [opened_end])
            lines = [l for l in captured[start:end].decode("utf-8", "replace").splitlines() if l.strip()]
            return _short(lines[-1]) if lines else "not found"

        test = enabled()
        checks = {}
        launched = time.monotonic()
        deadline = launched + DEADLINE_S
        for gid, st in states:
            if st.dev is not None and test:
                _log(log_fd, f"\n--- [{gid}] {st.name} · test\n")
                checks[gid] = _start(_check, st)

        results = []
        for gid, st in states:
            label = f"[{gid}] {st.name}"
            if st.dev is None:
                ok, detail = False, open_error(gid)
            elif gid not in checks:
                ok, detail = True, "operational" if test else "opened"
            else:
                until = min(launched + _timeout_for(st), deadline)
                try:
                    _wait(display, checks[gid], until, f"{label} · testing…")
                    ok, detail = True, "operational"
                except FutureTimeout:
                    ok, detail = False, f"no answer after {int(time.monotonic() - launched)} s"
                except Exception as exc:  # noqa: BLE001 - the device's failure, shown on its line
                    ok, detail = False, _short(exc) or type(exc).__name__
                    _log(log_fd, "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
            _flush_all()
            display.result(ok, label, detail)
            results.append((st.name, ok))
            _log(log_fd, f"[{gid}] {st.name}: {'ok' if ok else 'ISSUE'} {detail}\n")
        return results
    except Exception as exc:  # noqa: BLE001 - never stops the server
        _log(log_fd, f"startup check failed: {type(exc).__name__}: {exc}\n")
        display.result(False, "startup check", _short(f"failed: {exc}"))
        return None
