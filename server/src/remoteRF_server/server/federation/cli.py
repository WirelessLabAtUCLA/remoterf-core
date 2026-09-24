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

"""`serverrf cluster …`: cluster (deployment-group) administration (docs/deployment-groups.md §8)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from remoterf_federation_core import ContractError

from .identity import load_state
from .runtime import federation_enabled, load_config


def _print(text: str, style=None) -> None:
    from ...common.utils.ansi_codes import Sty, printf

    printf(text, style or Sty.DEFAULT)


def _lab(party: dict) -> str:
    short = party["deployment_id"][:8]
    return f"{party['display_name']} ({short}…)" if party.get("display_name") else party["deployment_id"]


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def _day(epoch) -> str:
    import datetime

    return datetime.datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d")


def cmd_clusters() -> int:
    from ...common.utils.panel import marker, print_panel
    from . import cluster

    try:
        config = load_config()
        if not federation_enabled():
            raise RuntimeError("REMOTERF_FEDERATION_ENABLED is not set")
    except RuntimeError as exc:
        print(f"Federation is not enabled: {exc}")
        return 1
    state = load_state(Path(config["identity_dir"]))
    rows = [f"{marker()} {config['display_name']} ({state.deployment_id})", ""]
    items = cluster.list_clusters()
    if not items:
        rows.append("No clusters. Start one with `cluster create <name>`.")
    me = {"display_name": config["display_name"], "deployment_id": state.deployment_id}
    for index, item in enumerate(items):
        if index:
            rows.append("")
        owner_row = None
        if item["role"] == "owner":
            invites = item["open_invites"]
            rows.append(f"{item['name']}  (yours)" + (f"  {invites} open invite{'s' if invites != 1 else ''}" if invites else ""))
            labs = [(me, "admin", "", None)] + [
                (m, "member", m["state"] or "joining", m.get("joined_at")) for m in item["members"]]
            if not item["members"] and not invites:
                rows.append(f"    nobody yet: `cluster invite {item['name']}`")
        else:
            owner_row = owner = {"display_name": item.get("peer_name"), "deployment_id": item["peer"]}
            rows.append(f"{item['name']}  {item['state']}")
            labs = [(owner, "admin", "", None), (me, "member", "", None)] + [
                (p, "member", p["state"] or "joining", None) for p in item.get("peers", [])]
        for lab, role, lab_state, since in labs:
            you = lab["deployment_id"] == me["deployment_id"]
            line = f"    {_lab(lab)}  {role}" + ("  (you)" if you else "")
            if lab_state and lab_state != "active":
                line += f"  {lab_state}"
            if since:
                line += f"  since {_day(since)}"
            rows.append(line)
            if you:
                rows.append("        sharing: " + (", ".join(
                    f"{g['group_name']} ({_n(len(g['devices']), 'device')})" for g in item["groups"]) or "nothing"))
            else:
                sharing = lab.get("sharing") if lab is not owner_row else item.get("peer_sharing")
                if sharing:
                    rows.append(f"        sharing {_n(sharing['groups'], 'group')}, {_n(sharing['devices'], 'device')}")
        rows.append(f"    {item['students']} of your users enrolled, {item['visitors']} visiting")
    print()
    print_panel("Clusters", rows, literal=True)
    print()
    return 0


def cmd_cluster_info(name: str) -> int:
    """Every lab in the cluster, each shared group with its limits, each device."""
    from ...common.utils.panel import print_panel
    from ..device_manager import describe_devices
    from ..user_group_cli import _fmt_duration
    from . import cluster

    config = load_config()
    state = load_state(Path(config["identity_dir"]))
    item = {i["name"]: i for i in cluster.list_clusters()}.get(name)
    if item is None:
        raise cluster.ClusterError(f"no cluster named {name}")
    me = {"display_name": config["display_name"], "deployment_id": state.deployment_id}
    mine = {"groups": len(item["groups"]), "detail": [
        {"name": g["group_name"], "max_reservation_time_sec": g["max_reservation_time_sec"],
         "max_reservations": g["max_reservations"], "lifetime_sec": g["lifetime_sec"],
         "devices": describe_devices(g["devices"])}
        for g in item["groups"]]}
    if item["role"] == "owner":
        labs = [(me, "admin", mine)] + [(m, "member", m.get("sharing")) for m in item["members"]]
    else:
        owner = {"display_name": item.get("peer_name"), "deployment_id": item["peer"]}
        labs = [(owner, "admin", item.get("peer_sharing")), (me, "member", mine)] + [
            (p, "member", p.get("sharing")) for p in item.get("peers", [])]
    rows = []
    for index, (lab, role, sharing) in enumerate(labs):
        if index:
            rows.append("")
        rows.append(f"{_lab(lab)}  {role}" + ("  (you)" if lab["deployment_id"] == me["deployment_id"] else ""))
        if sharing is None:
            rows.append("    (no details from this lab yet)")
            continue
        if not sharing.get("detail"):
            rows.append("    shares nothing")
        for group in sharing["detail"]:
            rows.append(f"    {group['name']}  —  {_n(len(group['devices']), 'device')}")
            rows.append("        " + " · ".join([
                f"up to {_fmt_duration(group['max_reservation_time_sec'])} per reservation",
                f"{_n(group['max_reservations'], 'reservation')} at once",
                "no expiry" if group["lifetime_sec"] <= 0 else f"expires after {_fmt_duration(group['lifetime_sec'])}",
            ]))
            width = max([len(d["name"]) for d in group["devices"]] + [4])
            for device in group["devices"]:
                rows.append(f"        {device['id']:>6}  {device['name']:<{width}}  {device['type'] or '?':<12}  "
                            + ("online" if device["online"] else "offline"))
    print()
    print_panel(f"Cluster {name}", rows, literal=True)
    print()
    return 0


def _ask_for(verb: str) -> str:
    """Prompt for the missing cluster name (or invite code), offering the obvious default."""
    from . import cluster

    if verb == "join":
        return _input("Invite code from the other lab: ")
    names = [name for name, item in sorted(cluster.load().items()) if item.get("role") == "owner"]
    if verb in ("remove", "groups", "codes", "info"):
        names = sorted(cluster.load())
    if verb == "accept":
        names = [name for name, item in sorted(cluster.load().items()) if item.get("state") == "pending"]
    what = {"create": "Name for the new cluster (short slug, e.g. ucla-lab)",
            "invite": "Which cluster to invite a lab into",
            "accept": "Which cluster's pending join to accept",
            "groups": "Which cluster to share groups with",
            "info": "Which cluster to show",
            "codes": "Which cluster to make codes for",
            "remove": "Which cluster to leave (revokes the contract)"}[verb]
    if verb != "create" and names:
        print(f"  Your clusters: {', '.join(names)}")
    default = names[0] if verb != "create" and len(names) == 1 else ""
    return _input(f"{what}{f' [{default}]' if default else ''}: ") or default


def _share_groups(name: str) -> int:
    """Pick, by number, which of this server's groups the cluster shares.
    Toggling: a shared group chosen again is unshared."""
    from ...common.utils.ansi_codes import Sty
    from ..user_group_handler import user_group_handler
    from . import cluster

    all_groups = user_group_handler.get_all_user_groups(include_users=False) or []
    if not all_groups:
        _print("  No user groups yet: make one with `groups create`, then share it here.", Sty.WARNING)
        return 1
    shared = {g["group_id"] for g in cluster.groups(name)}
    print(f"  Groups on this server (shared with {name} are marked):")
    for index, group in enumerate(all_groups, 1):
        mark = "*" if int(group["group_id"]) in shared else " "
        devices = group.get("devices_whitelist") or []
        print(f"   {mark} {index:>2}  {group['group_name']}  ({len(devices)} device{'s' if len(devices) != 1 else ''})")
    answer = _input("Toggle by number, e.g. 2 or 1,3 (Enter to leave as is): ")
    picks = [part for part in re.split(r"[\s,]+", answer) if part]
    if not picks:
        return 0
    for pick in picks:
        if not pick.isdigit() or not 1 <= int(pick) <= len(all_groups):
            _print(f"  {pick} is not a number in the list.", Sty.WARNING)
            continue
        group = all_groups[int(pick) - 1]
        if int(group["group_id"]) in shared:
            _print(f"  {cluster.detach_group(name, str(group['group_id']))} is no longer shared with {name}.", Sty.GRAY)
        else:
            _print(f"  {cluster.attach_group(name, str(group['group_id']))} is now shared with {name}; "
                   "everyone in the cluster gets it.", Sty.GRAY)
    return 0


def _codes_create(name: str) -> int:
    """The `codes create` questions, bound to a cluster instead of a group."""
    from ...common.utils.ansi_codes import Sty
    from ...common.utils.panel import print_table
    from .. import global_onboarding as g
    from . import cluster

    if not name:
        return 2
    cluster._find(cluster.load(), name)

    def ask_int(prompt: str, default: int, minimum: int) -> int | None:
        while True:
            answer = _input(f"{prompt} [{default}] (c to cancel): ")
            if answer.lower() in ("c", "q", "cancel"):
                return None
            if not answer:
                return default
            if answer.isdigit() and int(answer) >= minimum:
                return int(answer)
            _print(f"  Enter a whole number of at least {minimum}.", Sty.WARNING)

    count = ask_int("How many codes?", 1, 1)
    uses = None if count is None else ask_int("Uses per code?", 1, 1)
    duration = None if uses is None else ask_int(
        "Duration in seconds? (0=never expires)", cluster.CODE_DAYS * 86400, 0)
    if duration is None:
        return 2
    codes = cluster.mint_codes(name, count=count, uses=uses, duration_sec=duration)
    rows = [{"invite": g.invite(code)} for code in codes]
    if rows[0]["invite"] == codes[0]:
        print(f"Hand these out as is; users connect first with: remoterf -c -a {g.lan_endpoint() or '<lan address>'}")
    else:
        print("Hand these out as is; new users enter one at: remoterf --register, "
              "existing users enroll with it in the Client.")
    print_table(f"Cluster {name} codes", rows, ["invite"])
    return 0


def _codes_list(name: str | None) -> int:
    from ...common.utils.panel import print_panel
    from .. import global_onboarding as g
    from ..user_group_cli import _fmt_duration
    from . import cluster

    if name:
        cluster._find(cluster.load(), name)
    rows = []
    codes = cluster.list_codes(name)
    if not codes:
        rows.append("No cluster codes. Make some with `cluster codes create`.")
    current = None
    for code in codes:
        if code["cluster_name"] != current:
            if current is not None:
                rows.append("")
            current = code["cluster_name"]
            rows.append(current)
        rows.append(f"    {g.invite(code['code_name'])}")
        rows.append(f"        {_n(code['uses'], 'use')} left  ·  {_fmt_duration(code['duration_sec'])}")
    print()
    print_panel("Cluster codes", rows, literal=True)
    print()
    return 0


def _input(prompt: str) -> str:
    # The console's own prompt session: a bare input() inside the running
    # server fights prompt_toolkit for the terminal and kills the process.
    from ...serverrf_cli import _prompt_session

    try:
        return _prompt_session().prompt(f"  {prompt}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


_USAGE = ("Usage: cluster list | cluster create|invite|remove <name> | cluster join <code> | "
          "cluster info [<name>] | cluster groups [<name>] | cluster codes create|list [<name>]")


def cmd_cluster(argv: list[str]) -> int:
    from ...common.utils.ansi_codes import Sty
    from . import cluster

    verb = argv[0] if argv else "list"
    flags = [a for a in argv[1:] if a.startswith("--")]
    words = [a for a in argv[1:] if not a.startswith("--")]
    if verb == "list" and not words:
        return cmd_clusters()
    if verb == "codes" and (not words or words[0] not in ("create", "list")):
        print("Usage: cluster codes create [<cluster>] | cluster codes list [<cluster>]", file=sys.stderr)
        return 2
    if not words and verb in ("create", "invite", "accept", "join", "remove", "groups", "info"):
        # Leaving the argument out asks for it (docs/deployment-groups.md §8).
        answer = _ask_for(verb)
        if not answer:
            return 2
        words = [answer]
    arg = words[0] if words else ""
    argv = [verb, *words, *flags]
    try:
        if verb == "create" and arg:
            cluster.create(arg)
            _print(f"  Created cluster {arg}. Hand out an invite with `cluster invite {arg}`.", Sty.GRAY)
        elif verb == "invite" and arg:
            code = cluster.invite(arg, auto="--manual" not in argv)
            _print("  On the other lab's server run (single use, 7 days):", Sty.GRAY)
            _print(f"    cluster join {code}", Sty.BOLD)
        elif verb == "join" and len(argv) > 1:
            # A code pasted from chat or email may arrive wrapped across lines.
            name = cluster.join("".join(argv[1:]))
            _print(f"  Joined {name}. Both servers finish the handshake in the background; "
                   "`cluster list` shows active once done.", Sty.GRAY)
        elif verb == "accept" and arg:
            cluster.accept(arg)
            _print(f"  Accepted. {arg} activates once both servers confirm (about a minute).", Sty.GRAY)
        elif verb == "remove" and arg:
            _print(f"  {arg}: {cluster.remove(arg)}.", Sty.GRAY)
        elif verb == "info" and arg:
            return cmd_cluster_info(arg)
        elif verb == "groups" and len(words) == 1:
            cluster._find(cluster.load(), arg)
            return _share_groups(arg)
        elif verb == "groups" and len(words) == 3 and words[1] in ("add", "remove"):
            if words[1] == "add":
                _print(f"  {cluster.attach_group(arg, words[2])} is now shared with {arg}.", Sty.GRAY)
            else:
                _print(f"  {cluster.detach_group(arg, words[2])} is no longer shared with {arg}.", Sty.GRAY)
        elif verb == "codes" and words[0] == "create":
            return _codes_create(words[1] if len(words) > 1 else _ask_for("codes"))
        elif verb == "codes" and words[0] == "list":
            return _codes_list(words[1] if len(words) > 1 else None)
        else:
            print(_USAGE, file=sys.stderr)
            return 2
    except (cluster.ClusterError, ContractError, RuntimeError, OSError) as exc:
        _print(f"  {exc}", Sty.WARNING)
        return 1
    return 0


def main(argv) -> int:
    # `cluster <verb> …` from the table; `global cluster …` is the old spelling.
    if argv and argv[0] in ("cluster", "clusters"):
        argv = argv[1:] or ["list"]
    if argv and argv[0] in ("list", "create", "invite", "join", "accept", "remove", "groups", "codes", "info"):
        return cmd_cluster(argv)
    print(_USAGE, file=sys.stderr)
    return 2
