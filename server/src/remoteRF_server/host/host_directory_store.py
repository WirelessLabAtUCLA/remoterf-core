# src/remoteRF_host/host/host_directory_store.py

from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from typing import Dict, List, Optional

_ENV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def now_ms() -> int:
    import time
    return int(time.time() * 1000)


def repo_root_from_file(file: str) -> Path:
    """
    Find repo root by locating 'src' in parents.
    Fallback: go up 3 levels.
    """
    p = Path(file).resolve()
    for parent in p.parents:
        if parent.name == "src":
            return parent.parent
    return p.parents[3]


def cfg_dir_from_file(file: str) -> Path:
    return repo_root_from_file(file) / ".config"


def sanitize_env_key(s: str) -> str:
    s = (s or "").strip().upper()
    s = re.sub(r"[^A-Z0-9_]", "_", s)
    s = re.sub(r"_+", "_", s)
    return s[:120]


def strip_quotes(v: str) -> str:
    v = (v or "").strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        return v[1:-1]
    return v


def csv_split(v: str) -> List[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


class DeviceIdConflictError(RuntimeError):
    def __init__(self, *, device_id: str, existing_host: str, new_host: str) -> None:
        super().__init__(
            f"device_id '{device_id}' already owned by host '{existing_host}', rejecting host '{new_host}'"
        )
        self.device_id = device_id
        self.existing_host = existing_host
        self.new_host = new_host


class EnvStore:
    """
    Minimal .env store:
      - append_to_csv_list(): append-only semantics for CSV list keys
      - upsert_kv(): update/insert scalar keys (never deletes)
      - set_kv_if_absent(): only writes if key doesn't exist
    """
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read_lines(self) -> List[str]:
        if not self.path.exists():
            return []
        return self.path.read_text(encoding="utf-8").splitlines()

    def _write_lines(self, lines: List[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def read_kv(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for raw in self._read_lines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = _ENV_LINE.match(line)
            if not m:
                continue
            k = m.group(1).strip()
            v = strip_quotes(m.group(2))
            out[k] = v
        return out

    def append_to_csv_list(self, key: str, value: str) -> None:
        key = sanitize_env_key(key)
        value = (value or "").strip()
        if not value:
            return

        with self._lock:
            lines = self._read_lines()
            idx: Optional[int] = None
            cur = ""

            for i, ln in enumerate(lines):
                if ln.startswith(key + "="):
                    idx = i
                    cur = ln[len(key) + 1:].strip()
                    break

            existing = csv_split(cur)
            if value in existing:
                return

            existing.append(value)
            new_line = f"{key}=" + ",".join(existing)

            if idx is None:
                lines.append(new_line)
            else:
                lines[idx] = new_line

            self._write_lines(lines)

    def upsert_kv(self, key: str, value: str) -> None:
        key = sanitize_env_key(key)
        value = (value or "").strip()

        with self._lock:
            lines = self._read_lines()
            idx: Optional[int] = None
            for i, ln in enumerate(lines):
                if ln.startswith(key + "="):
                    idx = i
                    break

            new_line = f"{key}={value}"
            if idx is None:
                lines.append(new_line)
            else:
                lines[idx] = new_line

            self._write_lines(lines)

    def set_kv_if_absent(self, key: str, value: str) -> None:
        key = sanitize_env_key(key)
        value = (value or "").strip()
        if not value:
            return

        with self._lock:
            lines = self._read_lines()
            for ln in lines:
                if ln.startswith(key + "="):
                    return
            lines.append(f"{key}={value}")
            self._write_lines(lines)
