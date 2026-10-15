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

"""The remote-admin tunnel: SSH (paramiko, server side) inside a gRPC byte pipe.

    service remote_rf.RemoteAdminV1 {
      rpc Tunnel(stream bytes) returns (stream bytes);   // the SSH connection
      rpc HostKey(bytes) returns (bytes);                // public, for pairing
    }

Raw-bytes messages through a generic handler, so neither side needs generated
code (and no protobuf runtime bump). There is no listening SSH socket: each
Tunnel call is one SSH connection over a socketpair. Both RPCs answer
UNAVAILABLE until someone is pinned, so a lab that never uses this exposes no
SSH parser. Login is the device key (publickey, partial success) and then
keyboard-interactive: the remote-admin password, plus a code for a new device.
Pairing logs in as `<user>#<code>`: the console's code rides inside SSH, after
the client checked the host key against the fingerprint that code carries.
"""

from __future__ import annotations

import collections
import contextlib
import fcntl
import json
import os
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import uuid

import grpc

from . import remote_admin as ra

SERVICE = "remote_rf.RemoteAdminV1"
MD_LABEL = "x-remoterf-device-label"   # the admin machine's hostname, for codes and the audit

AUTH_SECONDS = 30
CODE_WAIT_SECONDS = 600   # once a code is emailed, the admin has its lifetime to type it
IDLE_SECONDS = 15 * 60
MAX_SECONDS = 8 * 3600
MAX_SESSIONS = 2
LOCK_AFTER = 5
LOCK_SECONDS = 15 * 60
OPENS_PER_MINUTE = 10
CHECK_SECONDS = 1.0

_lock = threading.Lock()
_sessions: dict[str, "_Session"] = {}
_failures: dict[int, list] = {}            # admin_id -> [count, locked_until]
_opens: dict[str, collections.deque] = {}  # peer host -> recent Tunnel opens


def _notice(text: str) -> None:
    try:
        from ..common.utils.ansi_codes import Sty, printf

        printf(f"[remote] {text}", Sty.GRAY)
    except Exception:  # noqa: BLE001
        print(f"[remote] {text}")


def register(server) -> None:
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(SERVICE, {
        "Tunnel": grpc.stream_stream_rpc_method_handler(_tunnel),
        "HostKey": grpc.unary_unary_rpc_method_handler(_host_key),
    }),))


def _peer_host(peer: str) -> str:
    host = peer.split(":", 1)[1] if peer.startswith(("ipv4:", "ipv6:")) else peer
    return host.rsplit(":", 1)[0].strip("[]")


def _allow_open(peer: str, relayed: bool) -> bool:
    # ponytail: every relayed client arrives from the tunnel's own address, so
    # they share one (larger) bucket; per-client needs the relay to say who.
    now = time.monotonic()
    with _lock:
        recent = _opens.setdefault(_peer_host(peer), collections.deque())
        while recent and now - recent[0] > 60:
            recent.popleft()
        if len(recent) >= OPENS_PER_MINUTE * (6 if relayed else 1):
            return False
        recent.append(now)
        if len(_opens) > 1000:
            for key in [k for k, q in _opens.items() if not q]:
                del _opens[key]
        return True


def _host_key(request, context):
    if not ra.any_active_pin():
        context.abort(grpc.StatusCode.UNAVAILABLE, "remote admin is off at this lab")
    key = ra.host_key()
    if key is None:
        context.abort(grpc.StatusCode.UNAVAILABLE, "remote admin is off at this lab")
    return ra.public_line(key).encode()


def _tunnel(request_iterator, context):
    from .global_onboarding import is_relayed

    if not ra.any_active_pin():
        context.abort(grpc.StatusCode.UNAVAILABLE, "remote admin is off at this lab")
    relayed = is_relayed(context.peer())
    if relayed and ra.policy()["relay"] == "off":
        context.abort(grpc.StatusCode.PERMISSION_DENIED, "remote admin at this lab works only on its own network")
    if not _allow_open(context.peer(), relayed):
        context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "too many remote-admin connections; wait a minute")
    metadata = dict(context.invocation_metadata())
    label = re.sub(r"[^A-Za-z0-9._-]", "", str(metadata.get(MD_LABEL, "")))[:40] or "unnamed"
    ours, theirs = socket.socketpair()
    threading.Thread(target=_serve_ssh, args=(theirs, "relay" if relayed else "lan", label),
                     name="remote-admin-ssh", daemon=True).start()

    def pump_in():
        try:
            for chunk in request_iterator:
                ours.sendall(chunk)
        except Exception:  # noqa: BLE001 - the client went away
            pass
        with contextlib.suppress(OSError):
            ours.shutdown(socket.SHUT_WR)

    threading.Thread(target=pump_in, name="remote-admin-in", daemon=True).start()
    context.add_callback(ours.close)
    while True:
        try:
            data = ours.recv(65536)
        except OSError:
            return
        if not data:
            return
        yield data


# -----------------------------
# Authentication
# -----------------------------

def _locked(admin_id: int, known: bool) -> bool:
    with _lock:
        entry = _failures.get((admin_id, known))
        return bool(entry and entry[1] > time.monotonic())


def _failed_password(pin, known: bool) -> None:
    """Approved devices and unknown ones count apart: anyone can bring a key of
    their own, so their guesses must never lock the admin's own devices out."""
    with _lock:
        entry = _failures.setdefault((pin["admin_id"], known), [0, 0.0])
        entry[0] += 1
        locked = entry[0] >= LOCK_AFTER
        if locked:
            entry[0], entry[1] = 0, time.monotonic() + LOCK_SECONDS
    if locked:
        _notice(f"{ra.login_name(pin)}: {LOCK_AFTER} wrong remote-admin passwords from "
                f"{'an approved' if known else 'unapproved'} device(s); those are locked for {LOCK_SECONDS // 60} minutes")


def _server_interface():
    import paramiko

    class AdminServer(paramiko.ServerInterface):
        """publickey proves the device key; keyboard-interactive then asks the
        password (and a code for a device this admin has not approved)."""

        def __init__(self, route: str, label: str):
            self.route, self.label = route, label
            self.login = self.pair_code = None
            self.session_id = uuid.uuid4().hex[:12]
            self.deadline = time.monotonic() + AUTH_SECONDS
            self.key = self.username = self.pin = None
            self.stage = None
            self.tries = 0
            self.authed = None  # the _Session, once in
            self.shell = threading.Event()
            self.channel = None
            self.term, self.size = "xterm-256color", (80, 24)
            self.master = None

        # -- auth --
        def get_allowed_auths(self, username):
            return "keyboard-interactive" if self.key is not None else "publickey"

        def check_auth_publickey(self, username, key):
            # paramiko asks this before it checks the signature (and for a
            # signature-less probe too): the key counts only once it verified one.
            verify = key.verify_ssh_sig

            def verified(blob, sig):
                ok = verify(blob, sig)
                if ok:
                    name, sep, code = username.rpartition("#")
                    self.key, self.login = key, username
                    self.username, self.pair_code = (name, code) if sep else (username, None)
                return ok

            key.verify_ssh_sig = verified
            return paramiko.AUTH_PARTIALLY_SUCCESSFUL

        def check_auth_interactive(self, username, submethods):
            if self.key is None or username != self.login:
                return paramiko.AUTH_FAILED
            if self.pair_code is not None:
                return self.check_auth_interactive_response([self.pair_code], stage="pair_code")
            return self._ask("password", (f"Password for remote admin {self.username}: ", False))

        def _ask(self, stage, *prompts, instructions=""):
            self.stage = stage
            query = paramiko.InteractiveQuery("", instructions)
            for text, echo in prompts:
                query.add_prompt(text, echo)
            return query

        def _say_and_fail(self, text):
            return self._ask("fail", instructions=text)

        def _who(self):
            return ra.login_name(self.pin) if self.pin is not None else self.username

        def _fail(self, reason):
            ra.audit("auth_fail", admin=self._who(), device_fp=self.key.fingerprint, route=self.route,
                     session_id=self.session_id, detail={"reason": reason})
            return paramiko.AUTH_FAILED

        def check_auth_interactive_response(self, responses, stage=None):
            stage, self.stage = stage or self.stage, None
            answers = list(responses)
            if stage == "fail" or self.key is None:
                return paramiko.AUTH_FAILED
            with contextlib.closing(ra.connect()) as conn:
                pin = self.pin = ra.find_pin(conn, self.username)
                problem = ra.pin_problem(pin)
                fp, pubkey = self.key.fingerprint, ra.public_line(self.key)
                if stage == "pair_code":
                    if problem or not ra.redeem_code(conn, pin["admin_id"], "pair", answers[0] if answers else ""):
                        conn.commit()
                        return self._fail(problem or "bad pairing code")
                    conn.commit()
                    self.tries = 0
                    return self._ask("new_password",
                                     (f"New remote-admin password for {self.username} (min {ra.MIN_PASSWORD}): ", False),
                                     ("Repeat it: ", False))
                if stage == "new_password":
                    first, second = (answers + ["", ""])[:2]
                    if first != second or len(first) < ra.MIN_PASSWORD:
                        self.tries += 1
                        if self.tries >= 3:
                            return self._fail("password not set")
                        return self._ask("new_password",
                                         (f"New remote-admin password (min {ra.MIN_PASSWORD}): ", False),
                                         ("Repeat it: ", False),
                                         instructions="Those did not match, or it is too short.")
                    if problem:
                        return self._fail(problem)
                    ra.set_password(conn, pin["admin_id"], first)
                    ra.approve_device(conn, pin["admin_id"], pubkey, fp, self.label, "pair")
                    ra.audit("device_approved", admin=self._who(), device_fp=fp, route=self.route,
                             session_id=self.session_id, detail={"via": "pair", "label": self.label}, conn=conn)
                    conn.commit()
                    _notice(f"{self._who()}: device {fp} ('{self.label}') paired over {self.route}")
                    return self._in(pin, fp)
                if stage == "password":
                    known = pin is not None and ra.device_for(conn, pin["admin_id"], pubkey) is not None
                    if pin is not None and _locked(pin["admin_id"], known):
                        return self._fail("locked")
                    if not ra.check_password(pin, answers[0] if answers else ""):
                        if pin is not None:
                            _failed_password(pin, known)
                        return self._fail("bad password")
                    with _lock:
                        _failures.pop((pin["admin_id"], known), None)
                    if problem:
                        return self._fail(problem)
                    return self._in(pin, fp) if known else self._new_device(conn, pin, fp)
                if stage == "device_code":
                    if problem or not ra.redeem_code(conn, pin["admin_id"], "device", answers[0] if answers else "",
                                                     device_fp=fp, session_id=self.session_id):
                        conn.commit()
                        return self._fail(problem or "bad device code")
                    ra.approve_device(conn, pin["admin_id"], pubkey, fp, self.label, "email")
                    ra.audit("device_approved", admin=self._who(), device_fp=fp, route=self.route,
                             session_id=self.session_id, detail={"via": "email", "label": self.label}, conn=conn)
                    conn.commit()
                    _notice(f"{self._who()}: new device {fp} ('{self.label}') approved by emailed code over {self.route}")
                    return self._in(pin, fp)
            return paramiko.AUTH_FAILED

        def _new_device(self, conn, pin, fp):
            console = (f"This device ({fp}) is not approved for {self.username}. Ask the lab console for a code "
                       f"(serverrf admins code {self.username}), then run the `remoterf --remote-admin pair` it prints.")
            if ra.policy(conn)["new_device"] != "email":
                return self._say_and_fail(console)
            code = ra.issue_code(conn, pin["admin_id"], "device", length=10, ttl=ra.DEVICE_CODE_TTL,
                                 device_fp=fp, session_id=self.session_id)
            conn.commit()
            try:
                masked = ra.email_device_code(pin, code, fp, self.label, self.route)
            except Exception as exc:  # noqa: BLE001 - Global down or refusing: the console path still works
                ra.audit("code_email_failed", admin=self._who(), device_fp=fp, route=self.route,
                         session_id=self.session_id, detail={"error": str(exc)[:200]})
                masked = None
            if not masked:
                return self._say_and_fail(console)
            self.deadline = time.monotonic() + CODE_WAIT_SECONDS
            return self._ask("device_code", ("Code: ", False),
                             instructions=f"New device. Code sent to {masked} (device {fp}, '{self.label}').")

        def _in(self, pin, fp):
            """Counted the moment it is in, so parallel logins cannot pass the cap together."""
            login = ra.login_name(pin)
            with _lock:
                if sum(1 for s in _sessions.values() if s.admin_id == pin["admin_id"]) >= MAX_SESSIONS:
                    full = True
                else:
                    full = False
                    self.authed = _sessions[self.session_id] = _Session(pin["admin_id"], login, fp, self.route,
                                                                        self.label)
            if full:
                return self._say_and_fail(f"{login} already has {MAX_SESSIONS} sessions open.")
            with contextlib.closing(ra.connect()) as conn:
                conn.execute("UPDATE remote_admin_devices SET last_used_at=? WHERE admin_id=? AND fingerprint=? "
                             "AND revoked_at IS NULL", (int(time.time()), pin["admin_id"], fp))
                ra.audit("auth_ok", admin=login, device_fp=fp, route=self.route, session_id=self.session_id, conn=conn)
                conn.commit()
            return paramiko.AUTH_SUCCESSFUL

        # -- channel --
        def check_channel_request(self, kind, chanid):
            if kind == "session" and self.authed and self.channel is None:
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
            term = term.decode(errors="replace") if isinstance(term, bytes) else str(term)
            self.term = term if re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", term) else "xterm-256color"
            self.size = _clamp(width, height)
            return True

        def check_channel_shell_request(self, channel):
            self.channel = channel
            self.shell.set()
            return True

        def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
            self.size = _clamp(width, height)
            if self.master is not None:
                _set_size(self.master, *self.size)
            return True

    return AdminServer


def _clamp(width, height) -> tuple[int, int]:
    return min(max(int(width or 80), 1), 1000), min(max(int(height or 24), 1), 1000)


def _set_size(fd: int, cols: int, rows: int) -> None:
    with contextlib.suppress(OSError):
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


# -----------------------------
# Sessions
# -----------------------------

class _Session:
    def __init__(self, admin_id, login, fp, route, label):
        self.admin_id, self.login, self.fp, self.route, self.label = admin_id, login, fp, route, label
        self.started, self.started_wall = time.monotonic(), time.time()
        self.last_input = self.started
        self.ended = None  # the reason, once the watchdog ends it


def _serve_ssh(sock, route: str, label: str) -> None:
    import paramiko

    key = ra.host_key()
    if key is None:
        sock.close()
        return
    transport = paramiko.Transport(sock)
    transport.add_server_key(key)
    server = _server_interface()(route, label)
    try:
        transport.start_server(server=server)
        while not transport.is_authenticated():
            if not transport.is_active() or time.monotonic() > server.deadline:
                return
            time.sleep(0.1)
        channel = transport.accept(10)
        if channel is None or not server.shell.wait(10):
            return
        _run_shell(server, channel, server.authed, transport)
    except Exception as exc:  # noqa: BLE001 - one broken connection must never touch the server
        if not isinstance(exc, (EOFError, paramiko.SSHException, OSError)):
            import logging

            logging.getLogger("remoteRF_server.remote_admin").warning("remote-admin session failed: %r", exc)
    finally:
        with _lock:
            _sessions.pop(server.session_id, None)
        transport.close()
        sock.close()


def _run_shell(server, channel, session: _Session, transport) -> None:
    sid = server.session_id
    ra.audit("session_start", admin=session.login, device_fp=session.fp, route=session.route, session_id=sid,
             detail={"label": session.label})
    _notice(f"{session.login} ({session.label}, {session.route}) connected")
    master = proc = None
    pumped = threading.Event()
    try:
        master, slave = pty.openpty()
        server.master = master
        _set_size(master, *server.size)
        env = {k: v for k, v in os.environ.items() if k != "REMOTERF_CONSOLE_ATTACHED"}
        env.update(TERM=server.term, REMOTERF_REMOTE_ADMIN=f"{session.admin_id}:{sid}",
                   REMOTERF_REMOTE_ADMIN_DEVICE=session.fp, REMOTERF_REMOTE_ADMIN_ROUTE=session.route,
                   REMOTERF_REMOTE_ADMIN_LABEL=session.label)
        try:
            proc = subprocess.Popen([sys.executable, "-m", "remoteRF_server.remote_admin_shell"], stdin=slave,
                                    stdout=slave, stderr=slave, env=env, start_new_session=True, close_fds=True)
        finally:
            os.close(slave)
        # The limits live apart from the pump: a client that stops reading (or a
        # shell that stops reading) blocks the pump, never the session's end.
        threading.Thread(target=_watchdog, args=(sid, session, proc, channel, transport, pumped),
                         name="remote-admin-watchdog", daemon=True).start()
        while session.ended is None:
            readable, _, _ = select.select([master, channel], [], [], CHECK_SECONDS)
            if channel in readable:
                data = channel.recv(4096)
                if not data:
                    break
                os.write(master, data)
                session.last_input = time.monotonic()
            if master in readable:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b""
                if not data:
                    break
                channel.sendall(data)
            if proc.poll() is not None and master not in readable:
                break
        if session.ended:
            with contextlib.suppress(Exception):
                channel.sendall(f"\r\n[remote admin session ended: {session.ended}]\r\n".encode())
    finally:
        pumped.set()
        if proc is not None:
            _stop(proc)
        if master is not None:
            with contextlib.suppress(OSError):
                os.close(master)
        server.master = None
        rc = proc.returncode if proc is not None and proc.returncode is not None and proc.returncode >= 0 else 1
        with contextlib.suppress(Exception):
            channel.send_exit_status(rc)
        channel.close()
        ra.audit("session_end", admin=session.login, device_fp=session.fp, route=session.route, session_id=sid,
                 detail={"reason": session.ended or "closed"})
        _notice(f"{session.login} ({session.label}) disconnected{f': {session.ended}' if session.ended else ''}")


def _watchdog(sid, session: _Session, proc, channel, transport, pumped) -> None:
    seen = _last_audit_id()
    while not pumped.wait(CHECK_SECONDS):
        now = time.monotonic()
        try:
            seen = _echo_commands(sid, session, seen)
            reason = (_still_allowed(session)
                      or ("idle for 15 minutes" if now - session.last_input > IDLE_SECONDS else None)
                      or ("8-hour limit" if now - session.started > MAX_SECONDS else None))
        except Exception as exc:  # noqa: BLE001 - cannot check: end it (fail closed)
            reason = f"check failed ({type(exc).__name__})"
        if reason:
            session.ended = reason
            _stop(proc)
            if not pumped.wait(3.0):
                transport.close()  # the pump is stuck on a peer that does not read
            return


def _stop(proc) -> None:
    if proc.poll() is not None:
        return
    for sig, wait in ((signal.SIGHUP, 2.0), (signal.SIGKILL, 2.0)):
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, sig)
        try:
            proc.wait(wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _still_allowed(session: _Session) -> str | None:
    with contextlib.closing(ra.connect()) as conn:
        pin = ra.pin_by_id(conn, session.admin_id)
        problem = ra.pin_problem(pin)
        if problem:
            return problem
        if pin["kicked_at"] is not None and pin["kicked_at"] >= int(session.started_wall):
            return "ended from the console"
        alive = conn.execute("SELECT 1 FROM remote_admin_devices WHERE admin_id=? AND fingerprint=? AND revoked_at IS NULL",
                             (session.admin_id, session.fp)).fetchone()
    return None if alive else "device revoked"


def _last_audit_id() -> int:
    with contextlib.closing(ra.connect()) as conn:
        return conn.execute("SELECT COALESCE(MAX(id), 0) FROM remote_admin_audit").fetchone()[0]


def _echo_commands(sid: str, session: _Session, seen: int) -> int:
    """The console's live view of a session: one gray line per command the
    shell logged (it is a separate process, so the audit table is the wire)."""
    with contextlib.closing(ra.connect()) as conn:
        rows = conn.execute("SELECT id, event, argv_json FROM remote_admin_audit WHERE id>? AND session_id=? "
                            "AND event IN ('command', 'refused') ORDER BY id", (seen, sid)).fetchall()
    for row in rows:
        what = (json.loads(row["argv_json"] or "{}") or {}).get("command", "?")
        _notice(f"{session.login} ({session.label}, {session.route}): {'refused: ' if row['event'] == 'refused' else ''}{what}")
        seen = row["id"]
    return seen
