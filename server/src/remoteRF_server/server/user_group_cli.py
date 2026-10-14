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

from __future__ import annotations
from typing import Any, Dict, List, Optional
import csv
import json
import os
import re
from datetime import datetime
from pathlib import Path

from ..common.utils.panel import print_table
from .global_onboarding import invite, lan_endpoint
from .user_group_handler import user_group_handler


def _print_device_choices() -> None:
    """The ids a whitelist can name, so nobody has to guess."""
    from . import device_manager

    devices = device_manager.get_all_devices_str()
    if not devices:
        print("No devices are configured yet (devices.yml).")
        return
    print("Devices on this server:")
    for gid in sorted(devices):
        print(f"  {gid:>4}  {devices[gid]}")


def _invites(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add the pasteable `invite` form to code rows (bare for LAN-only groups)."""
    lan_only = {
        int(g["group_id"]): bool(g.get("lan_only"))
        for g in user_group_handler.get_all_user_groups(include_users=False) or []
    }
    for row in rows:
        code = str(row.get("code_name", ""))
        # A federation-bound code is redeemed through its signed invitation,
        # never typed as a Global invite.
        federated = row.get("federation_contract_id") is not None
        row["invite"] = code if federated else invite(
            code, lan_only=lan_only.get(int(row.get("group_id", -1)), False)
        )
    return rows


def _fmt_duration(seconds: int) -> str:
    seconds = int(seconds)
    if seconds <= 0:
        return "never expires"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"

from .user_group_handler import user_group_handler

CANCEL = {"c", "e", "exit", "q", "quit"}


def _clusters_here() -> List[str]:
    """Clusters this lab is in; `global` is anyone on RemoteRF Global."""
    from .federation import cluster

    return sorted(cluster.load())


def _names(raw: str) -> List[str]:
    return [] if raw.lower() == "none" else [p for p in re.split(r"[\s,]+", raw) if p]

def make_user_group_local(session) -> None:
    def _prompt_str(msg: str) -> Optional[str]:
        s = (session.prompt(msg) or "").strip()
        if s.lower() in CANCEL:
            return None
        return s

    def _prompt_yes_no(msg: str, default_no: bool = True) -> bool:
        s = (session.prompt(msg) or "").strip().lower()
        if not s:
            return not default_no
        return s in {"y", "yes"}

    def _prompt_int(msg: str, *, default: Optional[int] = None, min_v: Optional[int] = 0) -> Optional[int]:
        while True:
            s = (session.prompt(msg) or "").strip()
            if s.lower() in CANCEL:
                return None
            if not s:
                if default is None:
                    print("Please enter a value (or 'c' to cancel).")
                    continue
                val = default
            else:
                try:
                    val = int(s)
                except ValueError:
                    print("Please enter an integer (or 'c' to cancel).")
                    continue

            if min_v is not None and val < min_v:
                print(f"Value must be >= {min_v}.")
                continue
            return val

    def _prompt_int_list(msg: str) -> Optional[List[int]]:
        while True:
            s = (session.prompt(msg) or "").strip()
            if s.lower() in CANCEL:
                return None

            if not s or s.lower() in {"all", "*"}:
                print("List the device ids this group may use, e.g. '0,1,2'.")
                continue

            # Allow both commas and whitespace
            parts = [p for p in s.replace(",", " ").split() if p]
            try:
                vals = [int(p) for p in parts]
            except ValueError:
                print("Invalid list. Use e.g. '0,1,2' or '0 1 2'.")
                continue

            if any(v < 0 for v in vals):
                print("Device IDs must be >= 0.")
                continue

            # Dedup while preserving order
            seen = set()
            out = []
            for v in vals:
                if v not in seen:
                    seen.add(v)
                    out.append(v)

            return out

    # ---- Group name ----
    group_name = _prompt_str("Enter group name (c to cancel): ")
    if not group_name:
        return

    if not _prompt_yes_no(f"Confirm group name '{group_name}'? (y/n): ", default_no=True):
        return

    # ---- Parameters ----
    _print_device_choices()
    devices_whitelist = _prompt_int_list("Devices whitelist (e.g. 0,1,2) (c to cancel): ")
    if devices_whitelist is None:
        return

    max_reservation_time_sec = _prompt_int("Max reservation time (sec) [1800] (c to cancel): ", default=1800, min_v=1)
    if max_reservation_time_sec is None:
        return

    max_reservations = _prompt_int("Max concurrent reservations [3] (c to cancel): ", default=3, min_v=1)
    if max_reservations is None:
        return

    lifetime_sec = _prompt_int("Group lifetime (sec) [0=forever] (c to cancel): ", default=0, min_v=0)
    if lifetime_sec is None:
        return

    horizon_days = _prompt_int("Max days ahead a reservation may start [7] (0=no limit) (c to cancel): ", default=7, min_v=0)
    if horizon_days is None:
        return

    # Off the LAN means through the Global relay: codes for a LAN-only group
    # cannot be redeemed there and its members cannot log in there.
    lan_only = not _prompt_yes_no("Reachable from outside your network (via Global)? (Y/n): ", default_no=False)

    public = not lan_only and _prompt_yes_no("Public: open to anyone on RemoteRF Global? (y/N): ", default_no=True)
    if public:
        public = _prompt_yes_no("Are you sure? Anyone with a RemoteRF Global account, and the users of every deployment in the "
                                "public cluster, can then see and reserve this group's devices. (Y/n): ", default_no=False)
    partners = [name for name in _clusters_here() if name != "global"] if not lan_only else []
    if partners:
        raw = _prompt_str(f"Also share with partner clusters ({', '.join(partners)}; comma-separated, "
                          "Enter for none, c to cancel): ")
        if raw is None:
            return
        partners = _names(raw or "none")

    # ---- Final confirmation ----
    wl_str = ",".join(map(str, devices_whitelist))
    print("\nAbout to create user group with:")
    print(f"  group_name               : {group_name}")
    print(f"  devices_whitelist        : {wl_str}")
    print(f"  max_reservation_time_sec : {max_reservation_time_sec}")
    print(f"  max_reservations         : {max_reservations}")
    print(f"  lifetime_sec             : {lifetime_sec}")
    print(f"  max_days_ahead           : {horizon_days or 'no limit'}")
    print(f"  lan_only                 : {'yes' if lan_only else 'no'}")
    print(f"  public                   : {'yes' if public else 'no'}")
    if partners:
        print(f"  partner clusters         : {', '.join(partners)}")

    if not _prompt_yes_no("Proceed? (y/n): ", default_no=True):
        return

    # ---- Create ----
    group_id = user_group_handler.create_user_group(
        group_name=group_name,
        devices_whitelist=devices_whitelist,
        max_reservation_time_sec=max_reservation_time_sec,
        max_reservations=max_reservations,
        lifetime_sec=lifetime_sec,
        lan_only=lan_only,
        max_horizon_sec=horizon_days * 86400,
    )

    if group_id is not None:
        print(f"User group created with group_id={group_id}.")
        from .federation import cluster
        for name in (["global"] if public else []) + partners:
            try:
                cluster.attach_group(name, str(group_id))
                print(f"Shared with {name}; `groups share {group_name} {name} off` takes it back.")
            except (cluster.ClusterError, RuntimeError, OSError) as exc:
                print(f"Not shared with {name} ({exc}); `groups share {group_name} {name} on` once this deployment is in it.")
    else:
        print("Failed to create user group.")

def remove_user_group_local(session) -> None:

    def _prompt_int(msg: str) -> Optional[int]:
        while True:
            s = (session.prompt(msg) or "").strip()
            if s.lower() in CANCEL:
                return None
            try:
                v = int(s)
            except ValueError:
                print("Please enter an integer group ID (or 'c' to cancel).")
                continue
            if v < 0:
                print("Group ID must be >= 0.")
                continue
            return v

    def _prompt_yes_no(msg: str) -> bool:
        s = (session.prompt(msg) or "").strip().lower()
        return s in {"y", "yes"}

    group_id = _prompt_int("Enter group ID to delete (c to cancel): ")
    if group_id is None:
        return

    if not _prompt_yes_no(f"Confirm delete group_id={group_id}? (y/n): "):
        return

    ok = user_group_handler.delete_user_group(group_id=group_id)

    if ok:
        print(f"Deleted user group {group_id}.")
    else:
        print(f"Failed to delete user group {group_id}.")

def list_user_groups_local(session) -> None:

    def _prompt_yes_no(msg: str, default_no: bool = True) -> bool:
        s = (session.prompt(msg) or "").strip().lower()
        if not s:
            return not default_no
        return s in {"y", "yes"}

    # include_users = _prompt_yes_no("Include users in output? (y/n) [n]: ", default_no=True)
    include_users = False

    groups: List[Dict[str, Any]] = user_group_handler.get_all_user_groups(include_users=include_users) or []
    from .federation import cluster

    for group in groups:
        group["devices_whitelist"] = group.get("devices_whitelist") or "all"
        group["shared_with"] = ", ".join(cluster.shared_with(group["group_id"])) or "-"
    columns = [
        "group_id", "group_name", "devices_whitelist", "max_reservation_time_sec",
        "max_reservations", "lifetime_sec", "max_horizon_sec", "lan_only", "shared_with", "created_at",
    ] + (["users"] if include_users else [])
    print_table("User groups", groups, columns, empty="No user groups found.")

def edit_user_group_local(session) -> None:

    def _prompt_raw(msg: str) -> Optional[str]:
        s = (session.prompt(msg) or "").strip()
        if s.lower() in CANCEL:
            return None
        return s

    def _prompt_int_optional(msg: str, *, min_v: Optional[int] = 0) -> Optional[Optional[int]]:
        s = _prompt_raw(msg)
        if s is None:
            return None  # cancelled
        if s == "":
            return ""  # sentinel for unchanged
        try:
            v = int(s)
        except ValueError:
            print("Please enter an integer, or press Enter to keep unchanged, or 'c' to cancel.")
            return _prompt_int_optional(msg, min_v=min_v)
        if min_v is not None and v < min_v:
            print(f"Value must be >= {min_v}.")
            return _prompt_int_optional(msg, min_v=min_v)
        return v

    def _prompt_devices_optional(msg: str) -> Optional[object]:
        s = _prompt_raw(msg)
        if s is None:
            return None  # cancelled
        if s == "":
            return ""    # unchanged
        if s.lower() in {"all", "*"}:
            print("List the device ids this group may use, e.g. '0,1,2'.")
            return _prompt_devices_optional(msg)
        parts = [p for p in s.replace(",", " ").split() if p]
        try:
            vals = [int(p) for p in parts]
        except ValueError:
            print("Invalid list. Use e.g. '0,1,2' or '0 1 2'.")
            return _prompt_devices_optional(msg)
        if any(v < 0 for v in vals):
            print("Device IDs must be >= 0.")
            return _prompt_devices_optional(msg)
        # dedup preserve order
        seen = set()
        out: List[int] = []
        for v in vals:
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    def _prompt_yes_no(msg: str) -> bool:
        s = (session.prompt(msg) or "").strip().lower()
        return s in {"y", "yes"}

    # ---- Required: group_id ----
    gid_raw = _prompt_raw("Enter group ID to edit (c to cancel): ")
    if gid_raw is None:
        return
    try:
        group_id = int(gid_raw)
    except ValueError:
        print("Group ID must be an integer.")
        return
    if group_id < 0:
        print("Group ID must be >= 0.")
        return

    # ---- Optional fields ----
    group_name = _prompt_raw("New group name (Enter to keep unchanged, c to cancel): ")
    if group_name is None:
        return
    if group_name == "":
        group_name = None

    _print_device_choices()
    devices_whitelist = _prompt_devices_optional(
        "New devices whitelist (e.g. 0,1,2 | Enter unchanged, c cancel): "
    )
    if devices_whitelist is None:
        return
    if devices_whitelist == "":
        devices_whitelist = None  # unchanged

    max_res_time = _prompt_int_optional("New max reservation time sec (Enter unchanged, c cancel): ", min_v=1)
    if max_res_time is None:
        return
    if max_res_time == "":
        max_res_time = None

    max_reservations = _prompt_int_optional("New max reservations (Enter unchanged, c cancel): ", min_v=1)
    if max_reservations is None:
        return
    if max_reservations == "":
        max_reservations = None

    lifetime_sec = _prompt_int_optional("New lifetime sec (0=forever) (Enter unchanged, c cancel): ", min_v=0)
    if lifetime_sec is None:
        return
    if lifetime_sec == "":
        lifetime_sec = None

    horizon_days = _prompt_int_optional("New max days ahead a reservation may start (0=no limit) (Enter unchanged, c cancel): ", min_v=0)
    if horizon_days is None:
        return
    if horizon_days == "":
        horizon_days = None

    lan_only_raw = _prompt_raw("LAN only? (y/n | Enter unchanged, c cancel): ")
    if lan_only_raw is None:
        return
    lan_only = None if lan_only_raw == "" else lan_only_raw.lower() in {"y", "yes"}

    from .federation import cluster

    share = None  # unchanged
    here = _clusters_here()
    if here:
        print(f"Shared with now: {', '.join(cluster.shared_with(group_id)) or 'nothing'} "
              f"(clusters: {', '.join(here)}; global = anyone on RemoteRF Global)")
        share_raw = _prompt_raw("Share with (comma-separated | none | Enter unchanged, c cancel): ")
        if share_raw is None:
            return
        share = _names(share_raw) if share_raw else None

    # Ensure at least one change
    if (
        group_name is None
        and devices_whitelist is None
        and max_res_time is None
        and max_reservations is None
        and lifetime_sec is None
        and horizon_days is None
        and lan_only is None
        and share is None
    ):
        print("No changes specified. Nothing to do.")
        return

    # ---- Summary + confirm ----
    def _fmt_devices(v: Optional[List[int]]) -> str:
        if v is None:
            return "(unchanged)"
        return ",".join(map(str, v)) or "all"

    print("\nAbout to edit user group:")
    print(f"  group_id                : {group_id}")
    print(f"  group_name              : {group_name if group_name is not None else '(unchanged)'}")
    print(f"  devices_whitelist       : {_fmt_devices(devices_whitelist)}")
    print(f"  max_reservation_time_sec: {max_res_time if max_res_time is not None else '(unchanged)'}")
    print(f"  max_reservations        : {max_reservations if max_reservations is not None else '(unchanged)'}")
    print(f"  lifetime_sec            : {lifetime_sec if lifetime_sec is not None else '(unchanged)'}")
    print(f"  max_days_ahead          : {(horizon_days or 'no limit') if horizon_days is not None else '(unchanged)'}")
    print(f"  lan_only                : {('yes' if lan_only else 'no') if lan_only is not None else '(unchanged)'}")
    print(f"  shared_with             : {(', '.join(share) or 'nothing') if share is not None else '(unchanged)'}")

    if not _prompt_yes_no("Proceed? (y/n): "):
        return

    if share is not None:
        try:
            added, removed = cluster.share_group(str(group_id), share)
            print(f"Sharing: +{', '.join(added) or 'none'}  -{', '.join(removed) or 'none'}")
        except cluster.ClusterError as exc:
            print(f"Sharing unchanged: {exc}")
            return
    if not any(v is not None for v in (group_name, devices_whitelist, max_res_time, max_reservations,
                                         lifetime_sec, horizon_days, lan_only)):
        return

    ok = user_group_handler.edit_user_group(
        group_id=group_id,
        group_name=group_name,
        devices_whitelist=devices_whitelist,  # type: ignore[arg-type]
        max_reservation_time_sec=max_res_time,  # type: ignore[arg-type]
        max_reservations=max_reservations,      # type: ignore[arg-type]
        lifetime_sec=lifetime_sec,              # type: ignore[arg-type]
        lan_only=lan_only,
        max_horizon_sec=None if horizon_days is None else horizon_days * 86400,
    )

    if ok:
        print("User group updated.")
    else:
        print("Failed to update user group.")

def make_enrollment_codes_local(session) -> None:

    def _prompt_raw(msg: str) -> Optional[str]:
        s = (session.prompt(msg) or "").strip()
        if s.lower() in CANCEL:
            return None
        return s

    def _prompt_yes_no(msg: str, default_no: bool = True) -> bool:
        s = (session.prompt(msg) or "").strip().lower()
        if not s:
            return not default_no
        return s in {"y", "yes"}

    def _prompt_int(msg: str, *, default: Optional[int] = None, min_v: Optional[int] = 0) -> Optional[int]:
        while True:
            s = _prompt_raw(msg)
            if s is None:
                return None
            if s == "":
                if default is None:
                    print("Please enter a value (or 'c' to cancel).")
                    continue
                v = default
            else:
                try:
                    v = int(s)
                except ValueError:
                    print("Please enter an integer (or 'c' to cancel).")
                    continue
            if min_v is not None and v < min_v:
                print(f"Value must be >= {min_v}.")
                continue
            return v

    # A cluster code enrols the user at every lab in a partner cluster; `global` needs none.
    partners = [name for name in _clusters_here() if name != "global"]
    if partners and _prompt_yes_no(f"For a partner cluster instead of a group ({', '.join(partners)})? "
                                   "Users join every deployment in it. (y/N): ", default_no=True):
        name = partners[0] if len(partners) == 1 else _prompt_raw(f"Which cluster? [{partners[0]}] (c to cancel): ")
        if name is None:
            return
        from .federation import cluster
        from .federation.cli import _codes_create

        try:
            _codes_create(name or partners[0])
        except cluster.ClusterError as exc:
            print(exc)
        return

    count = _prompt_int("How many enrollment codes? (c to cancel): ", min_v=1)
    if count is None:
        return

    groups = {int(g["group_id"]): g for g in user_group_handler.get_all_user_groups(include_users=False) or []}
    group_id = -1  # account only: no local devices; a public cluster admits the account on its own
    if not groups:
        print("No user groups yet: skipping (codes create accounts only).")
    elif _prompt_yes_no("Attach a user group? (Y/n): ", default_no=False):
        print("Your groups:")
        for gid, g in sorted(groups.items()):
            print(f"  {gid:>3}  {g['group_name']}" + ("  (LAN only)" if g.get("lan_only") else ""))
        while True:
            group_id = _prompt_int("Group ID to attach codes to? (c to cancel): ", min_v=0)
            if group_id is None:
                return
            if group_id in groups:
                break
            print(f"No group with id {group_id}; pick one from the list.")
    else:
        print("Account only: the account joins no group and sees no local devices; a public cluster admits it on its own.")

    char_count = _prompt_int("Characters per code name? [10] (c to cancel): ", default=10, min_v=4)
    if char_count is None:
        return

    try:
        code_names: List[str] = user_group_handler.generate_random_enrollment_code_names(
            count=count,
            char_count=char_count,
        ) or []
    except Exception as e:
        print(f"Failed to generate code names: {e}")
        return

    if not code_names:
        print("No codes generated.")
        return

    print("\nGenerated code names:")
    for i, name in enumerate(code_names, 1):
        print(f"  {i:>2}) {name}")

    if not _prompt_yes_no("\nUse these codes? (y/n): ", default_no=True):
        return

    uses = _prompt_int("Uses per code? [1] (c to cancel): ", default=1, min_v=1)
    if uses is None:
        return

    duration_sec = _prompt_int(
        "Duration in seconds? [3600] (0=never expires) (c to cancel): ",
        default=3600,
        min_v=0,
    )
    if duration_sec is None:
        return

    print("\nAbout to create enrollment codes with:")
    print(f"  group_id     : {group_id if group_id >= 0 else 'none (account only)'}")
    print(f"  count        : {len(code_names)}")
    print(f"  uses         : {uses}")
    print(f"  duration_sec : {duration_sec}")
    
    if not _prompt_yes_no("Proceed? (y/n): ", default_no=True):
        return

    result = user_group_handler.create_enrollment_codes(
        code_names=code_names,
        group_id=group_id,
        uses=uses,
        duration_sec=duration_sec,
    )
    created = [r for r in user_group_handler.get_all_enrollment_codes() or [] if r.get("code_name") in code_names]
    if not created:
        print(f"\nNo codes were created{f': {result}' if result else ''}.")
        return
    print(f"\n{result}")
    rows = _invites(created)
    if rows and rows[0]["invite"] == rows[0]["code_name"]:
        print(f"Hand these out as is; users connect first with: remoterf -c -a {lan_endpoint() or '<lan address>'}")
    else:
        print("Hand these out as is; users enter one at: remoterf --register")
    print_table("Enrollment codes", rows, ["invite"])

def remove_enrollment_code_local(session) -> None:

    def _prompt(msg: str):
        s = (session.prompt(msg) or "").strip()
        return None if s.lower() in CANCEL else s

    def _yes(msg: str) -> bool:
        return (session.prompt(msg) or "").strip().lower() in {"y", "yes"}

    mode = _prompt("Delete by (n)ame or (g)roup_id? [n] (c to cancel): ")
    if mode is None:
        return
    mode = (mode or "n").lower()

    if mode.startswith("n"):
        code_name = _prompt("Enter code or invite (c to cancel): ")
        if code_name:
            code_name = code_name.rpartition("/")[2].strip()  # invite -> bare code
        if not code_name:
            return
        if not _yes(f"Delete enrollment code '{code_name}'? (y/n): "):
            return
        ok = user_group_handler.delete_enrollment_code_name(code_name=code_name)
        print("Deleted." if ok else "Not found / failed.")
        return

    if mode.startswith("g"):
        gid_s = _prompt("Enter group_id to delete ALL codes for that group (c to cancel): ")
        if not gid_s:
            return
        try:
            group_id = int(gid_s)
        except ValueError:
            print("group_id must be an integer.")
            return
        if group_id < 0:
            print("group_id must be >= 0.")
            return
        if not _yes(f"Delete ALL enrollment codes for group_id={group_id}? (y/n): "):
            return
        ok = user_group_handler.delete_enrollment_code_id(group_id=group_id)
        print("Deleted." if ok else "None deleted / failed.")
        return

    print("Unknown option. Use 'n' or 'g'.")

def list_enrollment_codes_local(session) -> None:
    """Codes with the same group and parameters share one block, so 200 codes
    for one class are a header and a few lines of invites, not 200 records."""
    import textwrap

    from ..common.utils.panel import content_width, print_panel
    from .federation import cluster

    rows = _invites(user_group_handler.get_all_enrollment_codes() or [])
    if not rows:
        print_table("Enrollment codes", [], [], empty="No enrollment codes found.")
        return
    groups = {
        int(g["group_id"]): g
        for g in user_group_handler.get_all_user_groups(include_users=False) or []
    }
    buckets: Dict[tuple, List[Dict[str, Any]]] = {}
    for row in rows:
        key = (
            int(row.get("group_id", -1)),
            int(row.get("uses", 0)),
            int(row.get("duration_sec", 0)),
            row.get("federation_contract_id"),
            row.get("federation_contract_version"),
            row.get("allowed_issuer_deployment_id"),
            row.get("cluster_name"),
        )
        buckets.setdefault(key, []).append(row)

    width = content_width()
    lines: List[str] = []
    for (gid, uses, duration, contract, version, issuer, cluster_name), items in sorted(
        buckets.items(), key=lambda kv: (kv[0][0], kv[0][3] or "", -kv[0][1], kv[0][2])
    ):
        group = groups.get(gid, {})
        head = " · ".join([
            f"cluster {cluster_name}" if cluster_name else "account only" if gid < 0
            else f"group {gid} {group.get('group_name', '?')}".rstrip(),
            f"{_plural(uses, 'use')} left",
            _fmt_duration(duration),
            _plural(len(items), "code"),
        ] + (["LAN only"] if group.get("lan_only") else []))
        if contract:
            head += f" · federated: contract {contract} v{version}, issuer {cluster.peer_name(issuer)}"
        if lines:
            lines.append("")
        lines += textwrap.wrap(head, width=width) or [head]
        lines += [
            "  " + line
            for line in textwrap.wrap(
                "  ".join(item["invite"] for item in items),
                width=width - 2,
                break_long_words=False,
                break_on_hyphens=False,
            )
        ]
    print(flush=True)
    print_panel("Enrollment codes", lines, literal=True, max_width=None)
    print(flush=True)

def _resolve_download_dir() -> Path:
    """
    Best-effort Downloads folder resolution:
      1) XDG_DOWNLOAD_DIR env (if set)
      2) ~/.config/user-dirs.dirs XDG_DOWNLOAD_DIR (Linux desktops)
      3) ~/Downloads
      4) fallback: cwd
    """
    # 1) Env override (rare, but cheap to support)
    xdg_env = os.getenv("XDG_DOWNLOAD_DIR")
    if xdg_env:
        p = Path(os.path.expandvars(xdg_env)).expanduser()
        return p

    # 2) user-dirs.dirs (common on Linux w/ xdg-user-dirs)
    try:
        user_dirs = Path.home() / ".config" / "user-dirs.dirs"
        if user_dirs.exists():
            txt = user_dirs.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r'^XDG_DOWNLOAD_DIR\s*=\s*"(.*)"\s*$', txt, flags=re.MULTILINE)
            if m:
                raw = m.group(1)
                raw = raw.replace("$HOME", str(Path.home()))
                p = Path(os.path.expandvars(raw)).expanduser()
                return p
    except Exception:
        pass

    # 3) Default
    p = Path.home() / "Downloads"
    return p


def _coerce_csv_cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list, tuple)):
        # stable, readable cell content
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    return str(v)


def _write_csv(
    rows: List[Dict[str, Any]],
    out_path: Path,
    *,
    preferred_columns: Optional[List[str]] = None,
) -> None:
    if not rows:
        raise ValueError("No rows to write.")

    preferred_columns = preferred_columns or []

    present = set().union(*(r.keys() for r in rows))
    columns = [c for c in preferred_columns if c in present]
    columns += [c for c in sorted(present) if c not in columns]

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({c: _coerce_csv_cell(r.get(c)) for c in columns})


def export_user_groups_csv_local() -> Optional[Path]:
    # include_users=True so CSV truly contains "everything"
    groups: List[Dict[str, Any]] = user_group_handler.get_all_user_groups(include_users=True) or []
    if not groups:
        print("No user groups found.")
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = _resolve_download_dir()
    out_path = out_dir / f"remoterf_user_groups_{ts}.csv"

    preferred = [
        "group_id", "id",
        "group_name", "name",
        "devices_whitelist",
        "max_reservation_time_sec",
        "max_reservations",
        "lifetime_sec",
        "max_horizon_sec",
        "created_at",
        "users",
    ]

    try:
        _write_csv(groups, out_path, preferred_columns=preferred)
        print(f"Exported user groups CSV -> {out_path}")
        return out_path
    except Exception as e:
        print(f"Failed to export user groups CSV: {e}")
        return None


def export_enrollment_codes_csv_local() -> Optional[Path]:
    rows: List[Dict[str, Any]] = _invites(user_group_handler.get_all_enrollment_codes() or [])
    if not rows:
        print("No enrollment codes found.")
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = _resolve_download_dir()
    out_path = out_dir / f"remoterf_enrollment_codes_{ts}.csv"

    preferred = [
        "code_name",
        "group_id",
        "uses",
        "uses_left",
        "remaining_uses",
        "duration_sec",
        "expires_at",
        "created_at",
    ]

    try:
        _write_csv(rows, out_path, preferred_columns=preferred)
        print(f"Exported enrollment codes CSV -> {out_path}")
        return out_path
    except Exception as e:
        print(f"Failed to export enrollment codes CSV: {e}")
        return None
