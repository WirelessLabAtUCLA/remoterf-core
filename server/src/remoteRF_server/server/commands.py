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

"""One command table for both doors: the shell (`serverrf devices add …`)
and the console prompt inside `serverrf -s` (`devices add …`).

A command declares where it can run. `any` commands touch files or the
databases and run in whichever process typed them; `daemon` commands need the
live server and, from a shell, are sent to it over the control socket. After
a command that changes devices, certificates or ports, the running server
reloads or restarts itself.
"""

from __future__ import annotations

import sys
import textwrap
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from . import control


class RestartRequested(Exception):
    """Raised inside the server process when a command needs a restart."""


class StopRequested(Exception):
    """Raised inside the server process by `stop`/`quit`."""


@dataclass(frozen=True)
class Command:
    names: tuple[str, ...]          # first is canonical, the rest are aliases
    help: str
    run: Callable[[list[str]], Optional[int]]
    section: str
    where: str = "any"              # "any" | "daemon"
    after: Optional[str] = None     # "reload_devices" | "restart"
    interactive: bool = False       # daemon + interactive: needs the console's prompt
    console_only: bool = False      # meaningless from a shell (clear, detach)
    hidden: bool = False


# Plural/singular and old spellings people type first.
_SYNONYMS = {
    "device": "devices", "dev": "devices", "d": "devices",
    "user": "users", "u": "users", "accounts": "users", "account": "users",
    "group": "groups", "g": "groups",
    "code": "codes", "c": "codes",
    "reservation": "reservations", "res": "reservations", "r": "reservations",
    "host": "hosts",
    "clusters": "cluster",
    "cert": "certs", "certificate": "certs", "certificates": "certs",
    "ls": "list", "show": "list", "rm": "remove", "del": "remove", "delete": "remove",
    "mk": "create", "add": "add", "new": "create",
}


def _lazy(module: str, name: str):
    def run(argv):
        import importlib

        return getattr(importlib.import_module(module, __package__), name)(argv)
    return run


def _daemon(name: str):
    return _lazy(".grpc_server", name)


def _shell(name: str):
    return _lazy("remoteRF_server.serverrf_cli", name)


def _global(verb: str):
    return lambda argv: _shell("cmd_global")([verb, *argv])


def _federation(verb: str):
    return lambda argv: _shell("cmd_federation")([*verb.split(), *argv])


def _table() -> list[Command]:
    S, D = "any", "daemon"
    return [
        # ---- server ----
        Command(("help", "h", "?"), "This list", _lazy(".commands", "cmd_help"), "Server"),
        Command(("status",), "What the server is doing", _daemon("cmd_status"), "Server", where=D),
        Command(("restart",), "Restart the server", _daemon("cmd_restart"), "Server", where=D),
        Command(("stop", "quit", "exit", "q", "kill"), "Stop the server", _daemon("cmd_stop"), "Server", where=D),
        Command(("detach",), "Leave the console; the server keeps running", _daemon("cmd_detach"), "Server", where=D, console_only=True),
        Command(("clear", "cls"), "Clear the screen", _daemon("cmd_clear"), "Server", where=D, console_only=True),
        Command(("reload devices",), "", _daemon("cmd_reload_devices"), "Server", where=D, hidden=True),
        # ---- devices ----
        Command(("devices list",), "Configured devices", _shell("cmd_devices_list"), "Devices"),
        Command(("devices status",), "Live device online/last_seen/route", _daemon("cmd_devices_status"), "Devices", where=D),
        Command(("devices add",), "Add a device (asks type, name, serial)", _shell("cmd_devices_add"), "Devices", after="reload_devices", hidden=True),
        Command(("devices remove",), "Remove a device by id", _shell("cmd_devices_remove"), "Devices", after="reload_devices"),
        Command(("devices rename",), "Rename a device: devices rename <id> <name>", _shell("cmd_devices_rename"), "Devices", after="reload_devices"),
        Command(("devices wipe",), "Remove ALL devices [-y]", _shell("cmd_devices_wipe"), "Devices", after="reload_devices"),
        # ---- users ----
        Command(("users list",), "List accounts", _daemon("cmd_users_list"), "Users", where=D),
        Command(("users manage",), "Change a user's role (interactive)", _daemon("cmd_users_manage"), "Users", where=D, interactive=True),
        Command(("users perms",), "Show permissions", _daemon("cmd_users_perms"), "Users", where=D),
        Command(("users purge",), "Remove ALL accounts", _daemon("cmd_users_purge"), "Users", where=D),
        # ---- reservations ----
        Command(("reservations list",), "List reservations", _daemon("cmd_reservations_list"), "Reservations", where=D),
        Command(("reservations purge",), "Remove ALL reservations", _daemon("cmd_reservations_purge"), "Reservations", where=D),
        # ---- groups ----
        Command(("groups list",), "List user groups", _shell("cmd_groups_list"), "Groups"),
        Command(("groups create",), "Create a user group (interactive)", _shell("cmd_groups_create"), "Groups"),
        Command(("groups edit",), "Edit a user group (interactive)", _shell("cmd_groups_edit"), "Groups"),
        Command(("groups remove",), "Delete a user group (interactive)", _shell("cmd_groups_remove"), "Groups"),
        Command(("groups public",), "Share a group with anyone on RemoteRF Global, or stop: groups public <group> on|off", _federation("public"), "Groups"),
        Command(("groups share",), "Where a group is shared, or change it: groups share <group> [<cluster> on|off]", _federation("share"), "Groups"),
        Command(("groups csv",), "Export ALL user groups as CSV to Downloads", _shell("cmd_groups_csv"), "Groups"),
        # ---- enrollment codes ----
        Command(("codes list",), "List enrollment codes", _shell("cmd_codes_list"), "Enrollment codes"),
        Command(("codes create",), "Create enrollment codes for a group or a cluster (interactive)", _shell("cmd_codes_create"), "Enrollment codes"),
        Command(("codes remove",), "Delete an enrollment code (interactive)", _shell("cmd_codes_remove"), "Enrollment codes"),
        Command(("codes csv",), "Export ALL enrollment codes as CSV to Downloads", _shell("cmd_codes_csv"), "Enrollment codes"),
        # ---- hosts ----
        Command(("hosts status",), "Live host online/last_seen/devices", _daemon("cmd_hosts_status"), "Hosts", where=D),
        Command(("hosts wipe",), "Wipe persisted host directory state [-y]", _daemon("cmd_hosts_wipe"), "Hosts", where=D),
        Command(("hosts token",), "Create a host token: hosts token <id> [--force]", _shell("cmd_hosts_token"), "Hosts"),
        Command(("hosts tokens",), "List host tokens [--secrets] | hosts tokens wipe", _shell("cmd_hosts_tokens"), "Hosts"),
        Command(("hosts forget",), "Delete a host token: hosts forget <host_id>", _shell("cmd_hosts_forget"), "Hosts"),
        # ---- certificates / config ----
        Command(("certs list",), "Show the certificates [-v]", _shell("cmd_certs_show"), "Certificates"),
        Command(("certs reset",), "New CA + server cert: certs reset [ip] [--dns …]", _shell("cmd_certs_reset"), "Certificates", after="restart"),
        Command(("certs wipe",), "Delete the certs [-y]; reissued at next start", _shell("cmd_certs_wipe"), "Certificates", after="restart"),
        Command(("config list",), "Show ports and address", _shell("cmd_config_show"), "Config"),
        Command(("config ports",), "Set ports: config ports <grpc> [cert]", _shell("cmd_config_ports"), "Config", after="restart"),
        Command(("config wipe",), "Forget ports/address [-y]; asked at next start", _shell("cmd_config_wipe"), "Config", after="restart"),
        # ---- global / federation ----
        Command(("global status",), "Participation state", _global("status"), "Global"),
        Command(("global join",), "Request a public address", _global("join"), "Global"),
        Command(("global verify",), "Redeem the emailed code [code]", _global("verify"), "Global"),
        Command(("global leave",), "Stop participating", _global("leave"), "Global"),
        # ---- clusters (sharing devices with other labs) ----
        Command(("cluster list",), "Clusters shared with other labs", _federation("list"), "Clusters"),
        Command(("cluster info",), "Every lab, shared group and device in a cluster", _federation("info"), "Clusters"),
        Command(("cluster create",), "Start a cluster: cluster create <name>", _federation("create"), "Clusters"),
        Command(("cluster invite",), "Invite code for a lab: cluster invite <name>", _federation("invite"), "Clusters"),
        Command(("cluster join",), "Join with a code: cluster join <code>", _federation("join"), "Clusters"),
        Command(("cluster remove",), "Leave or disband: cluster remove <name>", _federation("remove"), "Clusters"),
        Command(("cluster kick",), "Put one lab out of your cluster: cluster kick <name> <lab>", _federation("kick"), "Clusters"),
        Command(("cluster cap",), "Reservations one lab may hold here at a time: cluster cap <name> <n> (0 = no cap)", _federation("cap"), "Clusters"),
        # Sharing and codes live under `groups` / `codes`; these spellings still work.
        Command(("cluster groups",), "", _federation("groups"), "Clusters", hidden=True),
        Command(("cluster codes create",), "", _federation("codes create"), "Clusters", hidden=True),
        Command(("cluster codes list",), "", _federation("codes list"), "Clusters", hidden=True),
        Command(("cluster peers",), "Partner listeners this lab dials directly: cluster peers [add <id> <host:port> --ca <ca.crt> | remove <id>]", _federation("peers"), "Clusters"),
        Command(("cluster accept",), "", _federation("accept"), "Clusters", hidden=True),
        Command(("global cluster",), "", _federation("cluster"), "Global", hidden=True),
        # ---- gist ----
        Command(("gist list",), "Show gist status settings [--secrets]", _shell("cmd_gist_show"), "Gist status"),
        Command(("gist set",), "gist set <gist_id> <file> [--token-stdin]", _shell("cmd_gist_set"), "Gist status"),
        Command(("gist wipe",), "Forget the gist settings [-y]", _shell("cmd_gist_wipe"), "Gist status"),
        # ---- database ----
        Command(("db export",), "Archive DBs, devices, keys, certs to ~/Downloads [dir]", _shell("cmd_db_export"), "Database"),
        Command(("stats purge",), "Delete the activity log (reservation stats) [-y]", _daemon("cmd_stats_purge"), "Database", where=D),
        Command(("db purge",), "Remove all database entries", _daemon("cmd_db_purge"), "Database", where=D),
        Command(("wipe",), "Factory reset: delete all config and data [-y]", _shell("cmd_wipe"), "Database"),
    ]


_COMMANDS: list[Command] | None = None


def commands() -> list[Command]:
    global _COMMANDS
    if _COMMANDS is None:
        _COMMANDS = _table()
    return _COMMANDS


def normalize(argv: Iterable[str]) -> list[str]:
    words = [w for w in (str(a).strip() for a in argv) if w]
    if words:
        words[0] = _SYNONYMS.get(words[0].lower(), words[0].lower())
    if len(words) > 1:
        words[1] = _SYNONYMS.get(words[1].lower(), words[1].lower())
    return words


def resolve(argv: list[str]) -> tuple[Optional[Command], list[str]]:
    """Longest phrase match wins: `devices add pluto` → ("devices add", ["pluto"])."""
    words = normalize(argv)
    for length in (3, 2, 1):
        phrase = " ".join(words[:length]).lower()
        for command in commands():
            if phrase in command.names:
                return command, words[length:]
    return None, words


_SECTION_BLURB = {
    "Server": "status, restart, stop",
    "Devices": "the radios this server offers",
    "Users": "accounts and roles",
    "Reservations": "who has what, and until when",
    "Groups": "user groups: devices, quotas, time limits",
    "Enrollment codes": "codes new users register with",
    "Hosts": "remote host machines and their tokens",
    "Certificates": "TLS certs clients trust",
    "Config": "ports and address",
    "Global": "public address and relay",
    "Clusters": "sharing devices with other labs",
    "Gist status": "publishing status to a GitHub gist",
    "Database": "export, or wipe everything",
}


def _visible(in_daemon: bool) -> list[Command]:
    return [c for c in commands() if not c.hidden and (in_daemon or not c.console_only)]


def help_text(*, in_daemon: bool, section: Optional[str] = None) -> list[str]:
    """No section: the groups. A section (any case, singular ok): its commands."""
    rows = _visible(in_daemon)
    if section is None:
        keys = list(dict.fromkeys(c.section for c in rows))
        width = max(len(k) for k in keys)
        return [f"  {k:<{width}}  {_SECTION_BLURB.get(k, '')}" for k in keys]
    rows = [c for c in rows if c.section.lower() == section.lower()]
    width = max(len(c.names[0]) for c in rows)
    return [f"  {c.names[0]:<{width}}  {c.help}" for c in rows]


def section_for(word: str) -> Optional[str]:
    """`help devices`, `help device`, `help codes` → the section name."""
    word = _SYNONYMS.get(word.lower(), word.lower())
    for c in _visible(True):
        first = c.names[0].split()[0]
        if word in (first, c.section.lower(), c.section.lower().split()[0]):
            return c.section
    return None


DEVICE_TYPES = "pluto, pluto-mimo, rtl-sdr, hackrf, ti-mmwave, usrp-2901, usrp-b205-mini, usrp-n210, usrp-profile"


def _columns(rows: list[tuple[str, str]], indent: str = "  ") -> list[str]:
    from ..common.utils.panel import MAX_CONTENT_WIDTH, _terminal_columns

    width = max(len(left) for left, _ in rows)
    # Wrap under the right column: a literal panel clips, and the usage sits at the end.
    room = max(20, min(MAX_CONTENT_WIDTH, _terminal_columns() - 4) - len(indent) - width - 2)
    out = []
    for left, right in rows:
        first, *rest = textwrap.wrap(right, room) or [""]
        out.append(f"{indent}{left:<{width}}  {first}")
        out += [f"{indent}{'':<{width}}  {piece}" for piece in rest]
    return out


def cmd_help(argv: list[str]) -> int:
    from ..common.utils.panel import print_panel

    prefix = "" if _IN_DAEMON else "serverrf "
    if argv:
        section = section_for(argv[0])
        if section is None:
            print(f"No such group: {argv[0]}. Try `{prefix}help`.", file=sys.stderr)
            return 2
        rows = [c for c in _visible(_IN_DAEMON) if c.section == section]
        lines = [_SECTION_BLURB.get(section, ""), ""] + _columns([(prefix + c.names[0], c.help) for c in rows])
        print_panel(section, lines, literal=True)
        return 0
    lines: list[str] = []
    if not _IN_DAEMON:
        lines += _columns([("serverrf -s", "The console (attach, or start the server)"),
                           ("serverrf --serve --daemon", "Start in the background")], indent="")
        lines.append("")
    sections = list(dict.fromkeys(c.section for c in _visible(_IN_DAEMON)))
    lines += _columns([(f"{prefix}help {k.lower().split()[0]}", _SECTION_BLURB.get(k, "")) for k in sections], indent="")
    if not _IN_DAEMON:
        lines += ["", "Every command also works at the console prompt."]
    print_panel("RemoteRF Server", lines, literal=True)
    return 0


_IN_DAEMON = False


def dispatch(argv: list[str], *, in_daemon: bool) -> int:
    """Run one command from either door. Returns the exit code."""
    global _IN_DAEMON
    _IN_DAEMON = in_daemon
    command, rest = resolve(argv)
    if command is None and len(argv) == 1 and section_for(argv[0]):
        return cmd_help([argv[0]])
    if command is None:
        print(f"Unknown command: {' '.join(argv)}", file=sys.stderr)
        print("Type `help` to see the commands.", file=sys.stderr)
        return 2
    if command.where == "daemon" and not in_daemon:
        return _run_in_daemon(command, rest)
    rc = int(command.run(rest) or 0)
    if rc == 0 and command.after:
        _after(command.after, in_daemon=in_daemon)
    return rc


def _run_in_daemon(command: Command, rest: list[str]) -> int:
    from . import console

    if not control.running():
        if command.names[0] == "restart":
            from .global_onboarding import cfg_dir

            ok = console.start_detached(cfg_dir(), ["--serve"]) if console.available() else False
            print("Server started." if ok else "The server is not running. Start it with: serverrf -s")
            return 0 if ok else 1
        print("The server is not running. Start it with: serverrf -s", file=sys.stderr)
        return 1
    if command.interactive or command.console_only:
        # Prompts need the console's terminal: type it there and attach.
        return console.run_in_console([*command.names[0].split(), *rest])
    reply = control.call([*command.names[0].split(), *rest])
    if reply is None:
        print("The server stopped answering.", file=sys.stderr)
        return 1
    rc, out = reply
    sys.stdout.write(out)
    return rc


def _after(what: str, *, in_daemon: bool) -> None:
    if in_daemon:
        if what == "reload_devices":
            from . import device_manager

            device_manager.reload_devices()
            print("Devices reloaded.")
        elif what == "restart":
            raise RestartRequested()
        return
    if not control.running():
        print("The server is not running; this takes effect when it starts.")
        return
    if what == "reload_devices":
        reply = control.call(["reload", "devices"], timeout=120.0)
        print("Devices reloaded on the running server." if reply and reply[0] == 0 else "Reload failed; restart the server.")
    elif what == "restart":
        reply = control.call(["restart"])
        print("Server restarting." if reply and reply[0] == 0 else "Could not restart the server; do it with: serverrf restart")
