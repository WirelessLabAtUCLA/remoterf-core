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

"""The running server's local control channel.

`serverrf <command>` from a shell and the same command typed at the console
prompt run the same code; commands that need the live server (device state,
host tunnels, reload, restart) reach it over this Unix socket. Owner-only by
file mode, never on the network, one JSON line each way:

    {"argv": ["devices", "status"]}   ->   {"rc": 0, "out": "..."}
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import threading
from pathlib import Path

SOCKET_NAME = "serverrf.sock"
_MAX_LINE = 64 * 1024


def socket_path() -> Path:
    from .global_onboarding import cfg_dir

    return cfg_dir() / SOCKET_NAME


def call(argv: list[str], *, timeout: float = 30.0, path: Path | None = None):
    """Run argv in the running server. None when no server is listening."""
    path = path or socket_path()
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect(str(path))
    except OSError:
        return None
    with conn:
        conn.sendall((json.dumps({"argv": list(argv)}) + "\n").encode("utf-8"))
        chunks = []
        while True:
            data = conn.recv(65536)
            if not data:
                break
            chunks.append(data)
    reply = json.loads(b"".join(chunks).decode("utf-8"))
    return int(reply["rc"]), str(reply["out"])


def running(path: Path | None = None) -> bool:
    return call(["ping"], timeout=2.0, path=path) is not None


class ControlServer:
    """Accept loop on a daemon thread; `handler(argv) -> int` runs one command
    at a time with its stdout captured into the reply."""

    def __init__(self, handler, path: Path | None = None):
        self.handler = handler
        self.path = path or socket_path()
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.path))
        os.chmod(self.path, 0o600)
        sock.listen(4)
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, name="serverrf-control", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()

    def _serve(self) -> None:
        while self._sock is not None:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                try:
                    self._handle(conn)
                except Exception:  # noqa: BLE001 - one bad client must not stop the loop
                    pass

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        raw = conn.makefile("rb").readline(_MAX_LINE)
        request = json.loads(raw.decode("utf-8"))
        argv = [str(item) for item in request["argv"]]
        if argv == ["ping"]:
            rc, out = 0, ""
        else:
            from prompt_toolkit.application import create_app_session
            from prompt_toolkit.output.plain_text import PlainTextOutput

            buffer = io.StringIO()
            # Styled output (printf/print_panel) goes through prompt_toolkit's
            # per-context app session, so it lands in this buffer even when the
            # server's own console is headless or on a real terminal.
            # ponytail: redirect_stdout is process-wide, so a plain print from
            # another thread can land in the reply during the milliseconds a
            # command runs; per-command output objects if that ever matters.
            with self._lock, create_app_session(output=PlainTextOutput(buffer)), contextlib.redirect_stdout(buffer):
                try:
                    rc = int(self.handler(argv) or 0)
                except SystemExit as exc:
                    rc = int(exc.code or 0)
            out = buffer.getvalue().replace("\r\n", "\n")
        conn.sendall(json.dumps({"rc": rc, "out": out}).encode("utf-8"))
