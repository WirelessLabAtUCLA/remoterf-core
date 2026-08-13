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

import os
from pathlib import Path

APP_NAME = "remoterf"
HOST_CONFIG_DIRNAME = "host"
EMPTY_DEVICES_CONFIG = '{\n  "devices": []\n}\n'


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

def get_devices_config_path(*, create: bool = False) -> Path:
    host_dir = get_host_config_dir()
    devices_yml = host_dir / "devices.yml"
    if devices_yml.exists():
        return devices_yml

    legacy_devices_yaml = host_dir / "devices.yaml"
    if legacy_devices_yaml.exists():
        return legacy_devices_yaml

    if create:
        try:
            with devices_yml.open("x", encoding="utf-8") as f:
                f.write(EMPTY_DEVICES_CONFIG)
        except FileExistsError:
            pass
    return devices_yml

def get_certs_dir() -> Path:
    return _ensure_dir(get_host_config_dir() / "certs")

def get_db_dir() -> Path:
    return _ensure_dir(get_host_config_dir() / "db")

def get_drivers_dir() -> Path:
    override = os.environ.get("REMOTERF_DRIVERS_DIR")
    if override:
        return _ensure_dir(Path(override).expanduser())
    return _ensure_dir(get_remoterf_root() / "drivers")
