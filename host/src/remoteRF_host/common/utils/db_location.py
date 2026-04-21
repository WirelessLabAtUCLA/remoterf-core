import os
from pathlib import Path

APP_NAME = "remoterf"
HOST_CONFIG_DIRNAME = "host"


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_remoterf_root() -> Path:
    # Linux-only: XDG_CONFIG_HOME or ~/.config
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")).expanduser() / APP_NAME
    return _ensure_dir(root)


def get_host_config_dir() -> Path:
    override = os.environ.get("REMOTERF_CONFIG_DIR")
    if override:
        return _ensure_dir(Path(override).expanduser())
    return _ensure_dir(get_remoterf_root() / HOST_CONFIG_DIRNAME)

def get_certs_dir() -> Path:
    return _ensure_dir(get_host_config_dir() / "certs")

def get_db_dir() -> Path:
    return _ensure_dir(get_host_config_dir() / "db")

def get_drivers_dir() -> Path:
    override = os.environ.get("REMOTERF_DRIVERS_DIR")
    if override:
        return _ensure_dir(Path(override).expanduser())
    return _ensure_dir(get_remoterf_root() / "drivers")
