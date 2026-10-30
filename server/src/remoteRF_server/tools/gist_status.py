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

# remoteRF_server/tools/gist_status.py

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests


def _note(message: str) -> None:
    """Gray status line; plain stderr if the console styling is unavailable."""
    try:
        from remoteRF_server.common.utils.ansi_codes import Sty, printf

        printf(message, Sty.GRAY)
    except Exception:  # noqa: BLE001
        print(message, file=sys.stderr)


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


def _load_gist_env() -> Optional[Tuple[str, str, str]]:
    p = _cfg_dir() / "gist.env"
    kv = _read_env_kv(p)

    gist_id = kv.get("STATUS_GIST_ID", "").strip()
    token = kv.get("GITHUB_TOKEN", "").strip()
    filename = kv.get("STATUS_GIST_FILENAME", "").strip()

    if not gist_id or not token or not filename:
        return None

    return (gist_id, token, filename)


PUSH_PERIOD_SEC = 300
DEFAULT_PUSH_KEY = "/etc/remoterf/status_key"
DEFAULT_PUSH_FILE = "status.json"


def _load_push_env() -> Optional[Tuple[str, str, str]]:
    kv = _read_env_kv(_cfg_dir() / "status_push.env")
    host = kv.get("STATUS_PUSH_HOST", "").strip()
    if not host:
        return None
    key = kv.get("STATUS_PUSH_KEY", "").strip() or DEFAULT_PUSH_KEY
    remote = kv.get("STATUS_PUSH_FILE", "").strip() or DEFAULT_PUSH_FILE
    return (host, key, remote)


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


def push_status(*, host: str, key: str, remote: str, payload: dict) -> bool:
    """Write status.json atomically, rsync it to the VPS. Never raises; False on failure."""
    try:
        path = _cfg_dir() / "status.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".status.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({**payload, "generated_at": int(time.time())}, f, separators=(",", ":"), sort_keys=True)
                f.write("\n")
            # mkstemp is 0600 and rsync carries that to a new remote file; nginx must read it.
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except BaseException:
            os.unlink(tmp)
            raise
        ssh = f"ssh -i {shlex.quote(key)} -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
        subprocess.run(
            ["rsync", "-e", ssh, str(path), f"statuspush@{host}:/{remote}"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        return True
    except subprocess.CalledProcessError as e:
        _note(f"[status_push] rsync failed ({e.returncode}): {(e.stderr or '').strip()}")
    except Exception as e:
        _note(f"[status_push] publish failed: {e}")
    return False


def _publisher_loop(period_sec: int) -> None:
    gist = _load_gist_env()
    push = _load_push_env()
    last_push = float("-inf")

    if gist is not None:
        try:
            push_gist(gist_id=gist[0], gh_token=gist[1], filename=gist[2], payload=build_status())
            _note("[gist_status] initial publish ok")
        except Exception as e:
            _note(f"[gist_status] initial publish failed: {e}")

    while True:
        # Only a successful push resets the clock, so a failed one retries next tick.
        push_due = push is not None and time.monotonic() - last_push >= PUSH_PERIOD_SEC
        if gist is not None or push_due:
            try:
                payload = build_status()
            except Exception as e:
                _note(f"[gist_status] publish failed: {e}")
                payload = None
            if payload is not None and gist is not None:
                try:
                    push_gist(gist_id=gist[0], gh_token=gist[1], filename=gist[2], payload=payload)
                except Exception as e:
                    _note(f"[gist_status] publish failed: {e}")
            if payload is not None and push_due and push_status(host=push[0], key=push[1], remote=push[2], payload=payload):
                last_push = time.monotonic()
        time.sleep(period_sec)


_publisher_thread: Optional[threading.Thread] = None
_publisher_lock = threading.Lock()


def start_status_publisher() -> None:
    global _publisher_thread
    with _publisher_lock:
        if _publisher_thread is not None and _publisher_thread.is_alive():
            return

        gist, push = _load_gist_env(), _load_push_env()
        if gist is None and push is None:
            # _note("[gist_status] off (not configured; see README gist docs)")
            return

        t = threading.Thread(
            target=_publisher_loop,
            args=(int(120),),
            name="gist-status-publisher",
            daemon=True,
        )
        t.start()
        _publisher_thread = t
        if gist is not None:
            _note(f"[gist_status] started (period={120}s)")
        if push is not None:
            _note(f"[status_push] started (statuspush@{push[0]}:/{push[2]}, period={PUSH_PERIOD_SEC}s)")


# if __name__ == "__main__":
#     start_status_publisher(period_sec=120)
#     while True:
#         time.sleep(3600)
