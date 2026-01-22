from __future__ import annotations
from typing import Any, Dict, List, Optional

from .user_group_handler import user_group_handler

CANCEL = {"c", "e", "exit", "q", "quit"}

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
                return []

            # Allow both commas and whitespace
            parts = [p for p in s.replace(",", " ").split() if p]
            try:
                vals = [int(p) for p in parts]
            except ValueError:
                print("Invalid list. Use e.g. '0,1,2' or '0 1 2' or 'all'.")
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
    devices_whitelist = _prompt_int_list("Devices whitelist (e.g. 0,1,2 | 'all' for no whitelist) (c to cancel): ")
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

    # ---- Final confirmation ----
    wl_str = "ALL" if len(devices_whitelist) == 0 else ",".join(map(str, devices_whitelist))
    print("\nAbout to create user group with:")
    print(f"  group_name               : {group_name}")
    print(f"  devices_whitelist        : {wl_str}")
    print(f"  max_reservation_time_sec : {max_reservation_time_sec}")
    print(f"  max_reservations         : {max_reservations}")
    print(f"  lifetime_sec             : {lifetime_sec}")

    if not _prompt_yes_no("Proceed? (y/n): ", default_no=True):
        return

    # ---- Create ----
    ok = user_group_handler.create_user_group(
        group_name=group_name,
        devices_whitelist=devices_whitelist,
        max_reservation_time_sec=max_reservation_time_sec,
        max_reservations=max_reservations,
        lifetime_sec=lifetime_sec,
    )

    if ok:
        print("User group created.")
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

    include_users = _prompt_yes_no("Include users in output? (y/n) [n]: ", default_no=True)

    groups: List[Dict[str, Any]] = user_group_handler.get_all_user_groups(include_users=include_users) or []

    if not groups:
        print("No user groups found.")
        return

    # Print a compact table-like view.
    def _fmt(v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, (list, tuple)):
            return ",".join(str(x) for x in v)
        if isinstance(v, dict):
            return str(v)
        return str(v)

    # Prefer common keys if present
    preferred = [
        "group_id",
        "id",
        "group_name",
        "name",
        "devices_whitelist",
        "max_reservation_time_sec",
        "max_reservations",
        "lifetime_sec",
        "created_at",
        "users",
    ]

    # Choose columns: preferred keys that exist in at least one record, then any remaining keys.
    present = set().union(*(g.keys() for g in groups))
    columns = [k for k in preferred if k in present]
    columns += [k for k in sorted(present) if k not in columns]

    # If not including users, drop users column if present to keep output clean.
    if not include_users and "users" in columns:
        columns.remove("users")

    # Compute widths (cap long values)
    def _cap(s: str, n: int = 48) -> str:
        return s if len(s) <= n else s[: n - 3] + "..."

    widths = {c: len(c) for c in columns}
    rows: List[List[str]] = []
    for g in groups:
        row = []
        for c in columns:
            val = _fmt(g.get(c, ""))
            val = _cap(val)
            widths[c] = max(widths[c], len(val))
            row.append(val)
        rows.append(row)

    # Header
    header = "  ".join(c.ljust(widths[c]) for c in columns)
    sep = "  ".join("-" * widths[c] for c in columns)
    print(header)
    print(sep)

    # Rows
    for row in rows:
        print("  ".join(row[i].ljust(widths[columns[i]]) for i in range(len(columns))))

    # If include_users, print expanded user lists (if present) for readability
    if include_users:
        # Find a reasonable key name for users if exists
        user_key = "users" if any("users" in g for g in groups) else None
        if user_key:
            print("\nUsers per group:")
            for g in groups:
                gid = g.get("group_id", g.get("id", "?"))
                name = g.get("group_name", g.get("name", ""))
                users = g.get(user_key, [])
                if not users:
                    continue
                print(f"  {gid} {name}:")
                if isinstance(users, list):
                    for u in users:
                        print(f"    - {u}")
                else:
                    print(f"    - {users}")

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
            return []
        parts = [p for p in s.replace(",", " ").split() if p]
        try:
            vals = [int(p) for p in parts]
        except ValueError:
            print("Invalid list. Use e.g. '0,1,2' or '0 1 2' or 'all'.")
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

    devices_whitelist = _prompt_devices_optional(
        "New devices whitelist (e.g. 0,1,2 | 'all' => [] | Enter unchanged, c cancel): "
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

    # Ensure at least one change
    if (
        group_name is None
        and devices_whitelist is None
        and max_res_time is None
        and max_reservations is None
        and lifetime_sec is None
    ):
        print("No changes specified. Nothing to do.")
        return

    # ---- Summary + confirm ----
    def _fmt_devices(v: Optional[List[int]]) -> str:
        if v is None:
            return "(unchanged)"
        return "ALL([])" if len(v) == 0 else ",".join(map(str, v))

    print("\nAbout to edit user group:")
    print(f"  group_id                : {group_id}")
    print(f"  group_name              : {group_name if group_name is not None else '(unchanged)'}")
    print(f"  devices_whitelist       : {_fmt_devices(devices_whitelist)}")
    print(f"  max_reservation_time_sec: {max_res_time if max_res_time is not None else '(unchanged)'}")
    print(f"  max_reservations        : {max_reservations if max_reservations is not None else '(unchanged)'}")
    print(f"  lifetime_sec            : {lifetime_sec if lifetime_sec is not None else '(unchanged)'}")

    if not _prompt_yes_no("Proceed? (y/n): "):
        return

    ok = user_group_handler.edit_user_group(
        group_id=group_id,
        group_name=group_name,
        devices_whitelist=devices_whitelist,  # type: ignore[arg-type]
        max_reservation_time_sec=max_res_time,  # type: ignore[arg-type]
        max_reservations=max_reservations,      # type: ignore[arg-type]
        lifetime_sec=lifetime_sec,              # type: ignore[arg-type]
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

    count = _prompt_int("How many enrollment codes? (c to cancel): ", min_v=1)
    if count is None:
        return

    group_id = _prompt_int("Group ID to attach codes to? (c to cancel): ", min_v=0)
    if group_id is None:
        return

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
    print(f"  group_id     : {group_id}")
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
    print("\nCreated enrollment codes:")
    print(result)

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
        code_name = _prompt("Enter code_name (c to cancel): ")
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
    rows: List[Dict[str, Any]] = user_group_handler.get_all_enrollment_codes() or []

    if not rows:
        print("No enrollment codes found.")
        return

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
    present = set().union(*(r.keys() for r in rows))
    cols = [c for c in preferred if c in present] + [c for c in sorted(present) if c not in preferred]

    def _fmt(v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, (list, tuple)):
            return ",".join(str(x) for x in v)
        return str(v)

    def _cap(s: str, n: int = 48) -> str:
        return s if len(s) <= n else s[: n - 3] + "..."

    # Compute widths
    widths = {c: len(c) for c in cols}
    table: List[List[str]] = []
    for r in rows:
        row = []
        for c in cols:
            cell = _cap(_fmt(r.get(c, "")))
            widths[c] = max(widths[c], len(cell))
            row.append(cell)
        table.append(row)

    # Print
    header = "  ".join(c.ljust(widths[c]) for c in cols)
    sep = "  ".join("-" * widths[c] for c in cols)
    print(header)
    print(sep)
    for row in table:
        print("  ".join(row[i].ljust(widths[cols[i]]) for i in range(len(cols))))