from __future__ import annotations

import os
import sys
import threading
import time
import traceback
from typing import Dict

_DEFAULT_LOG_MODE = "WARN"
_LOG_PRI: Dict[str, int] = {"INFO": 10, "WARN": 20, "ERROR": 30}
_MODE_MIN_PRI: Dict[str, int] = {"ALL": 10, "WARN": 20, "OFF": 10**9}


def _ts() -> str:
    t = time.time()
    sec = int(t)
    ms = int((t - sec) * 1000)
    lt = time.localtime(sec)
    return time.strftime("%H:%M:%S", lt) + f".{ms:03d}"


def _log_mode() -> str:
    raw = str(os.getenv("HOSTRF_LOG_MODE", _DEFAULT_LOG_MODE) or _DEFAULT_LOG_MODE).strip().upper()
    if raw not in _MODE_MIN_PRI:
        return _DEFAULT_LOG_MODE
    return raw


def _should_log(level: str) -> bool:
    return _LOG_PRI.get(level, 30) >= _MODE_MIN_PRI[_log_mode()]


def _emit(level: str, msg: str, *, component: str, include_thread: bool) -> None:
    prefix = f"{_ts()} {level:<6}"
    if include_thread:
        thread_name = threading.current_thread().name
        prefix = f"{prefix} [{thread_name}] {component}: "
    else:
        prefix = f"{prefix} {component}: "
    print(f"{prefix}{msg}", file=sys.stderr, flush=True)


def info(msg: str, *, component: str = "hostrf") -> None:
    if _should_log("INFO"):
        _emit("INFO", msg, component=component, include_thread=True)


def warn(msg: str, *, component: str = "hostrf") -> None:
    if _should_log("WARN"):
        _emit("WARN", msg, component=component, include_thread=True)


def error(msg: str, *, component: str = "hostrf") -> None:
    if _should_log("ERROR"):
        _emit("ERROR", msg, component=component, include_thread=True)


def status(msg: str, *, component: str = "hostrf") -> None:
    _emit("STATUS", msg, component=component, include_thread=False)


def exception(
    msg: str,
    *,
    component: str = "hostrf",
    traceback_limit: int = 50,
) -> None:
    error(msg, component=component)

    exc_type, exc, _ = sys.exc_info()
    if exc is None:
        return

    if str(os.getenv("HOSTRF_TRACEBACKS", "") or "").strip().lower() in {"1", "true", "yes", "on"}:
        traceback.print_exc(limit=traceback_limit, file=sys.stderr)
        return

    if _log_mode() == "ALL":
        traceback.print_exc(limit=traceback_limit, file=sys.stderr)
        return

    error(f"{exc_type.__name__}: {exc}", component=component)
