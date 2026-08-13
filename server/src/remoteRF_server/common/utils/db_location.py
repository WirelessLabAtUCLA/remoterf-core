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
    return get_remoterf_root() / "drivers"