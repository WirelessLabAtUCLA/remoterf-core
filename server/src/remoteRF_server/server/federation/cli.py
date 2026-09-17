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

"""`serverrf federation`: deployment-group administration (docs/deployment-groups.md §8)."""

from __future__ import annotations

import sys
from pathlib import Path

from .identity import load_state
from .runtime import federation_enabled, load_config


def cmd_groups() -> int:
    try:
        config = load_config()
        if not federation_enabled():
            raise RuntimeError("REMOTERF_FEDERATION_ENABLED is not set")
    except RuntimeError as exc:
        print(f"Federation is not enabled: {exc}")
        return 1
    state = load_state(Path(config["identity_dir"]))
    print(f"Deployment: {config['display_name']} ({state.deployment_id})")
    # Slice 2 adds the owned/joined queries (schema 8); until then there is
    # nothing a deployment can own or join.
    print("Owned groups: none")
    print("Joined groups: none")
    return 0


_COMMANDS = {"groups": cmd_groups}


def main(argv) -> int:
    if len(argv) != 1 or argv[0] not in _COMMANDS:
        print("Usage: serverrf federation groups", file=sys.stderr)
        return 2
    return _COMMANDS[argv[0]]()
