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
file mode, never on the network, JSON lines:

    {"argv": ["devices", "status"]}   ->   {"rc": 0, "out": "..."}

A command that prompts (`users manage`, `diag`, `stats purge` without -y)
asks over the same connection -- the prompt bridge -- and the caller answers
at its own terminal:

    <- {"ask": "Enter username: ", "secret": false, "out": "<output so far>"}
    -> {"answer": "jdoe"}
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import sys
import threading
from pathlib import Path

SOCKET_NAME = "serverrf.sock"
_MAX_LINE = 64 * 1024
ASK_TIMEOUT = 600.0
_bridge = threading.local()


def socket_path() -> Path:
    from .global_onboarding import cfg_dir

    return cfg_dir() / SOCKET_NAME


def _ask_here(text: str, secret: bool) -> str:
    import getpass

    return getpass.getpass(text) if secret else input(text)


def call(argv: list[str], *, timeout: float = 30.0, path: Path | None = None, ask=None):
    """Run argv in the running server. None when no server is listening.
    `ask(text, secret) -> str` answers the command's prompts (default: this terminal)."""
    path = path or socket_path()
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect(str(path))
    except OSError:
        return None
    with conn:
        conn.sendall((json.dumps({"argv": list(argv)}) + "\n").encode("utf-8"))
        reader = conn.makefile("rb")
        while True:
            line = reader.readline()
            if not line:
                return None
            reply = json.loads(line.decode("utf-8"))
            if "ask" not in reply:
                return int(reply["rc"]), str(reply["out"])
            sys.stdout.write(reply.get("out", ""))
            sys.stdout.flush()
            answer = (ask or _ask_here)(str(reply["ask"]), bool(reply.get("secret")))
            conn.sendall((json.dumps({"answer": str(answer)}) + "\n").encode("utf-8"))


def bridged() -> bool:
    """Whether the command running in this thread arrived over the socket."""
    return getattr(_bridge, "current", None) is not None


def ask(text: str, *, secret: bool = False) -> str:
    """A prompt in a command that arrived over the socket, asked at the caller's
    terminal. EOFError when the caller went away (or cancelled with Ctrl-C)."""
    return _bridge.current.ask(text, secret)


def prompt(text: str, *, secret: bool = False) -> str:
    """input()/getpass() that follows a command which arrived over the socket."""
    return ask(text, secret=secret) if bridged() else _ask_here(text, secret)


class _Bridge:
    def __init__(self, conn, reader, buffer, console_stdout):
        self.conn, self.reader, self.buffer, self.console_stdout = conn, reader, buffer, console_stdout

    def ask(self, text: str, secret: bool) -> str:
        out = self.buffer.getvalue()
        self.buffer.seek(0)
        self.buffer.truncate()
        captured, sys.stdout = sys.stdout, self.console_stdout  # the console's prints are not the caller's
        try:
            self.conn.sendall((json.dumps({"ask": text, "secret": secret, "out": out.replace("\r\n", "\n")}) + "\n").encode("utf-8"))
            self.conn.settimeout(ASK_TIMEOUT)
            line = self.reader.readline(_MAX_LINE)
        except OSError:
            line = b""
        finally:
            sys.stdout = captured
        try:
            return str(json.loads(line.decode("utf-8"))["answer"])
        except (ValueError, KeyError, TypeError):
            raise EOFError("the caller went away") from None


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
            # A thread each: a command waiting on a prompt must not keep `ping`
            # (and so `running()`) from being answered.
            threading.Thread(target=self._serve_one, args=(conn,), name="serverrf-control-conn", daemon=True).start()

    def _serve_one(self, conn: socket.socket) -> None:
        with conn:
            try:
                self._handle(conn)
            except Exception:  # noqa: BLE001 - one bad client must not stop the loop
                pass

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        reader = conn.makefile("rb")
        raw = reader.readline(_MAX_LINE)
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
            # another thread can land in the reply while a command runs (not
            # while it waits on a prompt); per-command output objects if that
            # ever matters. The lock also makes a second command wait while
            # one sits at a prompt.
            with self._lock:
                console_stdout = sys.stdout
                with create_app_session(output=PlainTextOutput(buffer)), contextlib.redirect_stdout(buffer):
                    _bridge.current = _Bridge(conn, reader, buffer, console_stdout)
                    try:
                        rc = int(self.handler(argv) or 0)
                    except SystemExit as exc:
                        rc = int(exc.code or 0)
                    finally:
                        _bridge.current = None
            out = buffer.getvalue().replace("\r\n", "\n")
        conn.sendall((json.dumps({"rc": rc, "out": out}) + "\n").encode("utf-8"))
