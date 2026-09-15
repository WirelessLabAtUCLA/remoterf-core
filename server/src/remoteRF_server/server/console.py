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

"""`serverrf -s` as a single long-lived server with an attachable console.

    serverrf -s   -> the console of the running server, or starts one
    Ctrl-C        -> leaves the console; the server keeps running
    quit          -> stops the server

The mechanism is tmux on a private socket with its own bare config (no status
bar, no prefix key), so nothing tmux-like is ever visible and a tmux the
operator uses for other things is never touched. Without tmux installed the
server simply runs in the foreground, as before.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

SOCKET = "remoterf-server"   # private tmux server, never the operator's own
SESSION = "server"
ATTACHED_ENV = "REMOTERF_CONSOLE_ATTACHED"

# Bare: the console must look like the plain shell it replaces.
TMUX_CONF = """\
set -g status off
set -g prefix None
unbind C-b
set -g mouse off
set -g history-limit 5000
set -g remain-on-exit off
set -g default-terminal "screen-256color"
"""


def available() -> bool:
    return shutil.which("tmux") is not None


def attached() -> bool:
    """Whether this process is the server running inside the console."""
    return os.environ.get(ATTACHED_ENV) == "1"


def _tmux(*args: str, capture: bool = False):
    command = ["tmux", "-L", SOCKET, *args]
    if capture:
        return subprocess.run(command, capture_output=True, text=True, check=False)
    return subprocess.run(command, check=False)


def running() -> bool:
    return available() and _tmux("has-session", "-t", SESSION, capture=True).returncode == 0


def _conf_path(config_dir: Path) -> Path:
    path = config_dir / "console.tmux.conf"
    if not path.exists() or path.read_text(encoding="utf-8") != TMUX_CONF:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(TMUX_CONF, encoding="utf-8")
    return path


def attach_or_start(config_dir: Path, serve_argv: list[str]) -> int:
    """Replace this process with the console: attach if running, else start."""
    if running():
        os.execvp("tmux", ["tmux", "-L", SOCKET, "attach-session", "-t", SESSION])
    env = {**os.environ, ATTACHED_ENV: "1"}
    conf = _conf_path(config_dir)
    # The session's process is the server itself, so `quit` ends the session
    # and the next `serverrf -s` starts fresh.
    os.execvpe(
        "tmux",
        ["tmux", "-L", SOCKET, "-f", str(conf), "new-session", "-s", SESSION, "-n", "server",
         sys.executable, "-m", "remoteRF_server.serverrf_cli", *serve_argv],
        env,
    )
    return 0  # unreachable: exec replaced the process


def start_detached(config_dir: Path, serve_argv: list[str]) -> bool:
    """Start the server in the background console (for a service or a script)."""
    if running():
        return True
    env = {**os.environ, ATTACHED_ENV: "1"}
    conf = _conf_path(config_dir)
    result = subprocess.run(
        ["tmux", "-L", SOCKET, "-f", str(conf), "new-session", "-d", "-s", SESSION, "-n", "server",
         sys.executable, "-m", "remoteRF_server.serverrf_cli", *serve_argv],
        env=env, check=False,
    )
    return result.returncode == 0


def detach() -> None:
    """Leave the console; the server keeps running."""
    _tmux("detach-client", "-s", SESSION, capture=True)
