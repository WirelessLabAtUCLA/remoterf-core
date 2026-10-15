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

"""The shell a remote admin lands in: `serverrf` commands, one policy check each.

Started by the lab's SSH server under a PTY (`python -m
remoteRF_server.remote_admin_shell`), with REMOTERF_REMOTE_ADMIN set. Each line
resolves against the same table as `serverrf <cmd>`, is checked against TIERS,
audited, and run with `dispatch(argv, in_daemon=False)` -- exactly as a shell
on the lab box would run it, so prompts and wizards work over the PTY and
daemon commands go through the control socket (its prompt bridge).
"""

from __future__ import annotations

import contextlib
import getpass
import os
import shlex
import signal
import subprocess
import sys
import time

from remoteRF_server.server import commands
from remoteRF_server.server import remote_admin as ra

READ, WRITE, DESTRUCTIVE, NEVER = "read", "write", "destructive", "never"

# Every command in commands._table(), by canonical name. A command missing here
# is refused remotely (and a unit test fails) until it is classified.
TIERS = {
    # read
    "help": READ, "status": READ, "devices list": READ, "users list": READ, "users perms": READ,
    "reservations list": READ, "groups list": READ, "codes list": READ, "hosts status": READ,
    "hosts tokens": READ, "certs list": READ, "config list": READ, "global status": READ,
    "cluster list": READ, "cluster info": READ, "gist list": READ, "users prune-proxies": READ,
    "cluster codes list": READ,
    # write
    "devices add": WRITE, "devices remove": WRITE, "devices rename": WRITE, "groups create": WRITE,
    "groups edit": WRITE, "groups public": WRITE, "groups share": WRITE, "codes create": WRITE,
    "codes remove": WRITE, "codes csv": WRITE, "groups csv": WRITE, "hosts token": WRITE,
    "cluster create": WRITE, "cluster invite": WRITE, "cluster join": WRITE, "cluster kick": WRITE,
    "cluster cap": WRITE, "cluster peers": WRITE, "restart": WRITE, "reload devices": WRITE,
    "db export": WRITE, "cluster groups": WRITE, "cluster codes create": WRITE, "cluster accept": WRITE,
    "global cluster": WRITE,
    # write, interactive in the daemon: through the control socket's prompt bridge
    "users manage": WRITE, "diag": WRITE,
    # destructive: password again, a typed word, an automatic backup, then -y
    "groups remove": DESTRUCTIVE, "devices wipe": DESTRUCTIVE, "reservations purge": DESTRUCTIVE,
    "stats purge": DESTRUCTIVE, "hosts wipe": DESTRUCTIVE, "hosts forget": DESTRUCTIVE,
    "certs reset": DESTRUCTIVE, "certs wipe": DESTRUCTIVE, "config ports": DESTRUCTIVE,
    "cluster remove": DESTRUCTIVE, "gist set": DESTRUCTIVE, "gist wipe": DESTRUCTIVE,
    # never remote: they cut remote access, nuke everything, or pin admins
    "stop": NEVER, "detach": NEVER, "clear": NEVER, "wipe": NEVER, "users purge": NEVER, "db purge": NEVER,
    "global leave": NEVER, "global join": NEVER, "global verify": NEVER, "config wipe": NEVER,
    "admins list": NEVER, "admins add": NEVER, "admins code": NEVER, "admins remove": NEVER,
    "admins devices": NEVER, "admins revoke": NEVER, "admins log": NEVER, "admins hostkey": NEVER,
    "admins policy": NEVER, "admins kick": NEVER,
}
DENY_FLAGS = {"--secrets"}
# Destructive commands whose own confirmation -y answers (the step-up asked already).
TAKES_YES = {"devices wipe", "stats purge", "hosts wipe", "certs wipe", "gist wipe", "users prune-proxies",
             "hosts tokens", "certs reset"}
KEEP_BACKUPS = 10
BUILTINS = ("help", "me", "revoke", "passwd", "log", "clear", "exit")


def tier_for(command, rest: list[str]) -> str:
    name = command.names[0]
    if name == "users prune-proxies" and {"-y", "--yes"} & set(rest):
        return DESTRUCTIVE
    if name == "hosts tokens" and "wipe" in rest:
        return DESTRUCTIVE
    return TIERS.get(name, NEVER)


def allowed(tier: str, read_only: bool) -> bool:
    return tier == READ or (tier in (WRITE, DESTRUCTIVE) and not read_only)


class Shell:
    def __init__(self):
        admin, _, self.session_id = os.environ["REMOTERF_REMOTE_ADMIN"].partition(":")
        self.admin_id = int(admin)
        self.fp = os.environ.get("REMOTERF_REMOTE_ADMIN_DEVICE", "")
        self.route = os.environ.get("REMOTERF_REMOTE_ADMIN_ROUTE", "")
        with contextlib.closing(ra.connect()) as conn:
            pin = ra.pin_by_id(conn, self.admin_id)
        self.login = ra.login_name(pin)

    def pin(self):
        with contextlib.closing(ra.connect()) as conn:
            return ra.pin_by_id(conn, self.admin_id)

    def audit(self, event, **kw):
        ra.audit(event, admin=self.login, device_fp=self.fp, route=self.route, session_id=self.session_id, **kw)

    # -- one line --
    def run_line(self, line: str) -> bool:
        """False when the admin leaves."""
        try:
            argv = shlex.split(line)
        except ValueError:
            argv = line.split()
        if not argv:
            return True
        word = argv[0].lower()
        if word in ("exit", "quit", "logout", "q"):
            return False
        if word in ("help", "h", "?"):
            self.help(argv[1:])
            return True
        if word in ("me", "revoke", "passwd", "log", "clear"):
            getattr(self, "do_" + word)(argv[1:])
            return True
        self.command(argv)
        return True

    def command(self, argv: list[str]) -> None:
        command, rest = commands.resolve(argv)
        if command is None:
            print(f"Unknown command: {' '.join(argv)}. Type `help`.", file=sys.stderr)
            return
        name = command.names[0]
        tier = tier_for(command, rest)
        pin = self.pin()
        refusal = None
        if tier == NEVER:
            refusal = "console only"
        elif DENY_FLAGS & set(rest):
            refusal = f"{sorted(DENY_FLAGS & set(rest))[0]} is console only"
        elif not allowed(tier, bool(pin["read_only"])):
            refusal = "read-only remote admin"
        detail = {"command": name, "argv": [*name.split(), *rest], "tier": tier}
        if refusal:
            self.audit("refused", detail={**detail, "reason": refusal})
            print(f"`{name}`: {refusal}. Run it at the lab console.", file=sys.stderr)
            return
        if tier == DESTRUCTIVE:
            if not self.step_up(pin, name):
                self.audit("refused", detail={**detail, "reason": "step-up not completed"})
                return
            if name in TAKES_YES and not {"-y", "--yes"} & set(rest):
                rest = [*rest, "-y"]
                detail["argv"].append("-y")
        if name == "restart":
            print("The server restarts and this session ends; reconnect in a few seconds.")
        self.audit("command", detail=detail)
        started = time.monotonic()
        rc = None
        try:
            rc = commands.dispatch([*name.split(), *rest], in_daemon=False)
        except KeyboardInterrupt:
            print("\nCancelled.")
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
        except Exception as exc:  # noqa: BLE001 - a broken command must not end the session
            print(f"That command failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            rc = 1
        self.audit("command_end", detail={**detail, "ms": int((time.monotonic() - started) * 1000)}, rc=rc)

    def step_up(self, pin, name: str) -> bool:
        print(f"`{name}` is destructive: password again, then a typed confirmation; a backup is made first.")
        try:
            password = getpass.getpass("Remote-admin password: ")
            if not ra.check_password(pin, password):
                self.audit("stepup_fail", detail={"command": name})
                print("Wrong password.", file=sys.stderr)
                return False
            if input(f"Type '{name}' to confirm: ").strip().lower() != name:
                print("Aborted.")
                return False
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return False
        return backup()

    # -- built-ins --
    def help(self, argv):
        read_only = bool(self.pin()["read_only"])
        rows = [c for c in commands.commands()
                if not c.hidden and allowed(TIERS.get(c.names[0], NEVER), read_only)]
        if argv:
            section = commands.section_for(argv[0])
            rows = [c for c in rows if c.section == section]
            if not rows:
                print(f"Nothing in {argv[0]} you can run remotely.")
                return
        else:
            sections = list(dict.fromkeys(c.section for c in rows))
            print("Remote admin" + (" (read-only)" if read_only else "") + ". Lab commands by group:")
            for s in sections:
                print(f"  help {s.lower().split()[0]:<14} {commands._SECTION_BLURB.get(s, '')}")
            print("Here: me, revoke <fingerprint>, passwd, log [N], clear, exit.")
            print("Destructive commands ask your password again and back up first; some stay console only.")
            return
        width = max(len(c.names[0]) for c in rows)
        for c in rows:
            mark = " *" if TIERS[c.names[0]] == DESTRUCTIVE else ""
            print(f"  {c.names[0]:<{width}}  {c.help}{mark}")
        if any(TIERS[c.names[0]] == DESTRUCTIVE for c in rows):
            print("  * destructive: password again, typed confirmation, automatic backup")

    def do_me(self, argv):
        pin = self.pin()
        print(f"{self.login}: {'read-only' if pin['read_only'] else 'full'} remote admin, "
              f"this session over {self.route} from {self.fp}")
        with contextlib.closing(ra.connect()) as conn:
            for d in conn.execute("SELECT * FROM remote_admin_devices WHERE admin_id=? AND revoked_at IS NULL",
                                  (self.admin_id,)):
                here = "  <- this device" if d["fingerprint"] == self.fp else ""
                print(f"  {d['fingerprint']}  {d['label'] or ''}  approved {ra._when(d['approved_at'])} "
                      f"({d['approved_via']}), last used {ra._when(d['last_used_at'])}{here}")

    def do_revoke(self, argv):
        if len(argv) != 1:
            print("Usage: revoke <fingerprint>   (`me` lists your devices)", file=sys.stderr)
            return
        with contextlib.closing(ra.connect()) as conn:
            n = ra.revoke_devices(conn, self.admin_id, argv[0]) if argv[0] != "all" else 0
            if n == 1:
                conn.commit()
        if n != 1:
            print("No single device of yours matches that fingerprint.", file=sys.stderr)
            return
        self.audit("device_revoked", detail={"device": argv[0], "by": "self"})
        print("Revoked. A session on that device ends within seconds.")

    def do_passwd(self, argv):
        try:
            old = getpass.getpass("Current remote-admin password: ")
            if not ra.check_password(self.pin(), old):
                self.audit("stepup_fail", detail={"command": "passwd"})
                print("Wrong password.", file=sys.stderr)
                return
            new = getpass.getpass(f"New password (min {ra.MIN_PASSWORD}): ")
            if len(new) < ra.MIN_PASSWORD or new != getpass.getpass("Repeat it: "):
                print("Too short, or they did not match. Nothing changed.", file=sys.stderr)
                return
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
        with contextlib.closing(ra.connect()) as conn:
            ra.set_password(conn, self.admin_id, new)
            conn.commit()
        self.audit("password_changed")
        print("Remote-admin password changed.")

    def do_log(self, argv):
        """The console's last N lines (a snapshot; there is no live view)."""
        from remoteRF_server.server import console

        try:
            n = max(1, min(1000, int(argv[0]))) if argv else 50
        except ValueError:
            print("Usage: log [N]", file=sys.stderr)
            return
        if not console.running():
            print("The server is not running in the console, so there is no console to show.")
            return
        out = subprocess.run(["tmux", "-L", console.SOCKET, "capture-pane", "-p", "-t", console.SESSION, "-S", f"-{n}"],
                             capture_output=True, text=True, check=False).stdout
        print("\n".join(out.rstrip("\n").splitlines()[-n:]))

    def do_clear(self, argv):
        print("\033[2J\033[H", end="", flush=True)

    # -- loop --
    def loop(self) -> int:
        from prompt_toolkit import PromptSession

        session = PromptSession()
        lab = _lab_name()
        print(f"RemoteRF remote admin: {self.login} at {lab}. Type `help`; `exit` leaves.")
        while True:
            try:
                line = session.prompt(f"{self.login}@{lab}> ")
            except KeyboardInterrupt:
                continue
            except EOFError:
                return 0
            if not self.run_line(line):
                return 0


def backup() -> bool:
    """`db export` into the remote-admin backups folder, keeping the last few."""
    from remoteRF_server.serverrf_cli import cmd_db_export

    folder = ra.backups_dir()
    folder.mkdir(parents=True, exist_ok=True)
    try:
        if cmd_db_export([str(folder)]) != 0:
            raise RuntimeError("db export failed")
    except Exception as exc:  # noqa: BLE001 - no backup, no destructive command
        print(f"Backup failed ({exc}); nothing changed.", file=sys.stderr)
        return False
    for old in sorted(folder.glob("remoterf-export-*.tgz"))[:-KEEP_BACKUPS]:
        old.unlink()
    return True


def _lab_name() -> str:
    from remoteRF_server.server import global_onboarding as g

    return g.lab_slug() or "lab"


def main() -> int:
    for sig in (signal.SIGTSTP, signal.SIGQUIT):
        signal.signal(sig, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.default_int_handler)  # even if the server ignores it: Ctrl-C cancels a command
    # Started with setsid: take the PTY as the controlling terminal, so Ctrl-C
    # reaches the command that is running (and not the session).
    with contextlib.suppress(OSError):
        import fcntl
        import termios

        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    if not os.environ.get("REMOTERF_REMOTE_ADMIN"):
        print("This is the lab's remote-admin shell; it runs only inside a remote-admin session.", file=sys.stderr)
        return 2
    return Shell().loop()


if __name__ == "__main__":
    raise SystemExit(main())
