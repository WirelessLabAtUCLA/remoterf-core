"""Small non-secret connector cursor, separate from disposable v1 identity DB."""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path


class CatalogState:
    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir) / "connector-catalog-state.json"
        self._lock = threading.RLock()

    def load(self) -> tuple[int, str | None]:
        with self._lock:
            if not self.path.exists():
                return 0, None
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if type(value) is not dict or set(value) != {"version", "content_hash"}:
                raise RuntimeError("invalid connector catalog state")
            version, content_hash = value["version"], value["content_hash"]
            if type(version) is not int or version < 0:
                raise RuntimeError("invalid connector catalog version")
            if content_hash is not None and not re.fullmatch(r"[0-9a-f]{64}", content_hash):
                raise RuntimeError("invalid connector catalog hash")
            return version, content_hash

    def save(self, *, version: int, content_hash: str) -> None:
        if type(version) is not int or version < 0:
            raise ValueError("invalid connector catalog version")
        if not re.fullmatch(r"[0-9a-f]{64}", content_hash):
            raise ValueError("invalid connector catalog hash")
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = self.path.with_name(self.path.name + ".tmp")
            payload = json.dumps(
                {"version": version, "content_hash": content_hash},
                sort_keys=True,
                separators=(",", ":"),
            )
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
