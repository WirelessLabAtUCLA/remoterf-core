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

import re

from .api_token import validate_token, generate_token, hash_token
from .list_string import list_to_str, str_to_list
from .db_connection import db_connection
from .db_location import get_devices_config_path, get_drivers_dir, get_host_config_dir, get_remoterf_root


def device_name_key(name: str) -> str:
    """A device's handle: its name with whitespace/'_' runs as one '_' (same regex as Server and Client)."""
    return re.sub(r"[\s_]+", "_", name).strip("_")


def _missing_dependency(name: str, exc: Exception):
    message = f"{name} is unavailable because an optional dependency failed to import: {exc}"

    def _raiser(*args, _exc: Exception = exc, _message: str = message, **kwargs):
        raise RuntimeError(_message) from _exc
    return _raiser


try:
    from .process_arg import unmap_arg, map_arg
except Exception as exc:  # pragma: no cover - exercised indirectly in lean CLI envs
    unmap_arg = _missing_dependency("unmap_arg", exc)
    map_arg = _missing_dependency("map_arg", exc)


try:
    from .ansi_codes import printf, stylize, Sty
except Exception as exc:  # pragma: no cover - exercised indirectly in lean CLI envs
    printf = _missing_dependency("printf", exc)
    stylize = _missing_dependency("stylize", exc)

    class Sty:  # type: ignore[no-redef]
        pass
