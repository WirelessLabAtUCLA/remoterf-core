# remoteRF_server/tools/gist_status.py

from __future__ import annotations

import json
import os
import sys
import time
import threading
from pathlib import Path
from typing import Dict, Optional

import requests


def _xdg_config_home() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))


def _cfg_dir() -> Path:
    return Path(os.getenv("REMOTERF_CONFIG_DIR", _xdg_config_home() / "remoterf"))


def _read_env_kv(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _load_gist_env() -> tuple[str, str, str]:
    p = _cfg_dir() / "gist.env"
    kv = _read_env_kv(p)

    gist_id = kv.get("STATUS_GIST_ID", "").strip()
    token = kv.get("GITHUB_TOKEN", "").strip()
    filename = kv.get("STATUS_GIST_FILENAME", "").strip()

    missing = []
    if not gist_id:
        missing.append("STATUS_GIST_ID")
    if not token:
        missing.append("GITHUB_TOKEN")
    if not filename:
        missing.append("STATUS_GIST_FILENAME")

    if missing:
        print(f"[gist_status] Missing {', '.join(missing)} in {p}", file=sys.stderr)
        print(
            "[gist_status] Fix: run:\n"
            "  serverrf --gist --set --id <gist_id> --file <filename>\n"
            "Or manually create gist.env with those keys.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    return gist_id, token, filename


def build_status() -> dict:
    payload = {
        "updated_unix": int(time.time()),
        "reservation_history_days": 90,
        "reservations": [],
    }

    from ..server.reservation import reservation_handler
    payload["reservations"] = reservation_handler.get_obfuscated_device_reservations_grouped_past_days(90)
    payload["usage"] = reservation_handler.get_obfuscated_usage_summary()

    return payload


def push_gist(*, gist_id: str, gh_token: str, filename: str, payload: dict) -> None:
    url = f"https://api.github.com/gists/{gist_id}"
    headers = {
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = {
        "files": {
            filename: {
                "content": json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
            }
        }
    }
    r = requests.patch(url, headers=headers, json=body, timeout=10)
    r.raise_for_status()


def _publisher_loop(period_sec: int) -> None:
    gist_id, gh_token, filename = _load_gist_env()

    try:
        push_gist(gist_id=gist_id, gh_token=gh_token, filename=filename, payload=build_status())
        print("[gist_status] initial publish ok", file=sys.stderr)
    except Exception as e:
        print(f"[gist_status] initial publish failed: {e}", file=sys.stderr)

    while True:
        try:
            push_gist(gist_id=gist_id, gh_token=gh_token, filename=filename, payload=build_status())
        except Exception as e:
            print(f"[gist_status] publish failed: {e}", file=sys.stderr)
        time.sleep(period_sec)


_publisher_thread: Optional[threading.Thread] = None
_publisher_lock = threading.Lock()


def start_status_publisher(*, period_sec: int = 60) -> None:
    global _publisher_thread
    with _publisher_lock:
        if _publisher_thread is not None and _publisher_thread.is_alive():
            return

        t = threading.Thread(
            target=_publisher_loop,
            args=(int(period_sec),),
            name="gist-status-publisher",
            daemon=True,
        )
        t.start()
        _publisher_thread = t
        print(f"[gist_status] started (period={period_sec}s)", file=sys.stderr)


if __name__ == "__main__":
    start_status_publisher(period_sec=120)
    while True:
        time.sleep(3600)