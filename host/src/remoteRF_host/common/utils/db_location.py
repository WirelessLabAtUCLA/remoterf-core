import os
from pathlib import Path

APP_NAME = "remoterf-host"

def get_remoterf_root() -> Path:
    # Linux-only: XDG_CONFIG_HOME or ~/.config
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME
    root.mkdir(parents=True, exist_ok=True)

    # ensure sibling folders exist
    (root / "certs").mkdir(parents=True, exist_ok=True)
    (root / "db").mkdir(parents=True, exist_ok=True)

    return root

def get_certs_dir() -> Path:
    return get_remoterf_root() / "certs"

def get_db_dir() -> Path:
    return get_remoterf_root() / "db"

def get_drivers_dir() -> Path:
    p = get_remoterf_root() / "drivers"
    p.mkdir(parents=True, exist_ok=True)
    return p
