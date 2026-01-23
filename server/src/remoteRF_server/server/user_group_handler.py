import sqlite3
from datetime import datetime
import time
import sys
import json
import threading
from pathlib import Path
from functools import wraps
from typing import Optional, Tuple, List

from ..common.utils import *

class UserGroupHandler:
    '''
    Handles user groups and enrollment codes.
        create_user_group -> bool
        delete_user_group -> bool
        edit_user_group -> bool
        get_all_user_groups -> list[dict]
        create_enrollment_code -> str
        create_enrollment_codes -> str
        generate_random_enrollment_code_names -> list[str]
        delete_enrollment_code (by code_name) -> bool
        delete_enrollment_code (by group_id) -> bool
        get_all_enrollment_codes -> list[dict]
        enroll_user_with_code -> bool
        get_users_devices -> list[int]
        get_users_max_reservation_time -> tuple[bool, int]
        get_users_max_reservations -> tuple[bool, int]
    '''
    
    def __init__(self):
        self.filepath = Path(__file__).resolve().parent.parent/'db'/'usergroups.db'
        self.db = sqlite3.connect(self.filepath)
        self.cursor = self.db.cursor()
        
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS UserGroups (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT NOT NULL UNIQUE,
            devices_whitelist TEXT NOT NULL DEFAULT '[]',  -- JSON array, e.g. "[0,1,2]"
            max_reservation_time_sec INTEGER NOT NULL,
            max_reservations INTEGER NOT NULL,
            lifetime_sec INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        ''')
        
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS UsersLookup (
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, group_id)
        );
        ''')
        
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS EnrollmentCodes (
            code_id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_name TEXT NOT NULL UNIQUE,
            group_id INTEGER NOT NULL,
            uses INTEGER NOT NULL,
            duration_sec INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        ''')
        
        self.cursor.close()
        self.db.commit()
        self.db.close()
        self.lock = threading.Lock()

    @db_connection
    def create_user_group(
        self,
        *,
        group_name: str,
        devices_whitelist: list[int],
        max_reservation_time_sec: int,
        max_reservations: int,
        lifetime_sec: int,
    ) -> bool:
        try:
            if not isinstance(group_name, str) or not group_name.strip():
                return False

            if devices_whitelist is None:
                devices_whitelist = []
            if not isinstance(devices_whitelist, (list, tuple)):
                return False

            try:
                devices_whitelist = sorted({int(d) for d in devices_whitelist})
            except Exception:
                return False

            try:
                max_reservation_time_sec = int(max_reservation_time_sec)
                max_reservations = int(max_reservations)
                lifetime_sec = int(lifetime_sec)
            except Exception:
                return False

            if max_reservation_time_sec <= 0:
                return False
            if max_reservations < 0:
                return False
            if lifetime_sec < 0:
                return False

            devices_json = json.dumps(devices_whitelist)

            # ---- insert ----
            self.cursor.execute(
                """
                INSERT INTO UserGroups
                (group_name, devices_whitelist, max_reservation_time_sec, max_reservations, lifetime_sec, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    group_name.strip(),
                    devices_json,
                    max_reservation_time_sec,
                    max_reservations,
                    lifetime_sec,
                    datetime.now(),
                ),
            )
            return True

        except Exception:
            return False

    @db_connection
    def get_groups_user_in(self, *, uid: int) -> list[str]:
        try:
            uid = int(uid)
            if uid < 0:
                return []

            # 1) Fetch group_ids the user is in
            self.cursor.execute(
                "SELECT group_id FROM UsersLookup WHERE user_id = ?",
                (uid,),
            )
            gid_rows = self.cursor.fetchall() or []
            group_ids = []
            for r in gid_rows:
                if not r or r[0] is None:
                    continue
                try:
                    gid = int(r[0])
                except Exception:
                    continue
                if gid > 0:
                    group_ids.append(gid)

            if not group_ids:
                return []

            # de-dupe, stable order
            seen_gid = set()
            group_ids_unique = []
            for gid in group_ids:
                if gid in seen_gid:
                    continue
                seen_gid.add(gid)
                group_ids_unique.append(gid)

            # 2) Fetch group names from UserGroups using those ids
            placeholders = ",".join(["?"] * len(group_ids_unique))
            self.cursor.execute(
                f"""
                SELECT group_name
                FROM UserGroups
                WHERE group_id IN ({placeholders})
                ORDER BY group_name ASC
                """,
                tuple(group_ids_unique),
            )
            rows = self.cursor.fetchall() or []

            # de-dupe defensively, preserve order
            out: list[str] = []
            seen_name: set[str] = set()
            for r in rows:
                if not r or r[0] is None:
                    continue
                name = str(r[0]).strip()
                if not name or name in seen_name:
                    continue
                seen_name.add(name)
                out.append(name)

            return out
        except Exception:
            return []



    @db_connection
    def delete_user_group(
        self, 
        *, 
        group_id: int
    ) -> bool:
        try:
            try:
                group_id = int(group_id)
            except Exception:
                return False
            if group_id <= 0:
                return False

            self.cursor.execute("SELECT 1 FROM UserGroups WHERE group_id = ? LIMIT 1", (group_id,))
            if self.cursor.fetchone() is None:
                return False

            # cleanup
            self.cursor.execute("DELETE FROM EnrollmentCodes WHERE group_id = ?", (group_id,))
            self.cursor.execute("DELETE FROM UsersLookup WHERE group_id = ?", (group_id,))
            self.cursor.execute("DELETE FROM UserGroups WHERE group_id = ?", (group_id,))

            return True
        except Exception:
            return False

    @db_connection
    def edit_user_group(
        self,
        *,
        group_id: int,
        group_name: str = None,
        devices_whitelist: list[int] = None,
        max_reservation_time_sec: int = None,
        max_reservations: int = None,
        lifetime_sec: int = None
    ) -> bool:
        try:
            try:
                group_id = int(group_id)
            except Exception:
                return False
            if group_id <= 0:
                return False

            self.cursor.execute("SELECT 1 FROM UserGroups WHERE group_id = ? LIMIT 1", (group_id,))
            if self.cursor.fetchone() is None:
                return False

            # dynamic update
            sets = []
            params = []

            if group_name is not None:
                group_name = str(group_name).strip()
                if group_name == "":
                    return False
                sets.append("group_name = ?")
                params.append(group_name)

            if devices_whitelist is not None:
                try:
                    wl = [int(x) for x in list(devices_whitelist)]
                except Exception:
                    return False
                wl = sorted(set(wl))
                sets.append("devices_whitelist = ?")
                params.append(json.dumps(wl))

            if max_reservation_time_sec is not None:
                try:
                    v = int(max_reservation_time_sec)
                except Exception:
                    return False
                if v <= 0:
                    return False
                sets.append("max_reservation_time_sec = ?")
                params.append(v)

            if max_reservations is not None:
                try:
                    v = int(max_reservations)
                except Exception:
                    return False
                if v <= 0:
                    return False
                sets.append("max_reservations = ?")
                params.append(v)

            if lifetime_sec is not None:
                try:
                    v = int(lifetime_sec)
                except Exception:
                    return False
                if v <= 0:
                    return False
                sets.append("lifetime_sec = ?")
                params.append(v)

            if not sets:
                return False

            params.append(group_id)
            sql = f"UPDATE UserGroups SET {', '.join(sets)} WHERE group_id = ?"
            self.cursor.execute(sql, tuple(params))
            return True
        except Exception:
            return False

    @db_connection
    def get_all_user_groups(self, include_users: bool) -> list[dict]:
        try:
            include_users = bool(include_users)

            self.cursor.execute("""
                SELECT
                    group_id,
                    group_name,
                    devices_whitelist,
                    max_reservation_time_sec,
                    max_reservations,
                    lifetime_sec,
                    created_at
                FROM UserGroups
                ORDER BY group_id ASC
            """)
            rows = self.cursor.fetchall() or []

            groups: list[dict] = []
            gid_to_users: dict[int, list[int]] = {}

            if include_users:
                self.cursor.execute("""
                    SELECT user_id, group_id
                    FROM UsersLookup
                """)
                urows = self.cursor.fetchall() or []
                for user_id, group_id in urows:
                    try:
                        gid = int(group_id)
                        uid = int(user_id)
                    except Exception:
                        continue
                    gid_to_users.setdefault(gid, []).append(uid)

                # sort
                for gid in gid_to_users:
                    gid_to_users[gid] = sorted(set(gid_to_users[gid]))

            for r in rows:
                try:
                    gid = int(r[0])
                    name = str(r[1])
                    wl_raw = r[2] if r[2] is not None else "[]"
                    try:
                        wl = json.loads(wl_raw) if isinstance(wl_raw, str) else wl_raw
                        wl = [int(x) for x in (wl or [])]
                        wl = sorted(set(wl))
                    except Exception:
                        wl = []
                    max_t = int(r[3])
                    max_r = int(r[4])
                    life = int(r[5])
                    created_at = r[6]
                except Exception:
                    continue

                entry = {
                    "group_id": gid,
                    "group_name": name,
                    "devices_whitelist": wl,
                    "max_reservation_time_sec": max_t,
                    "max_reservations": max_r,
                    "lifetime_sec": life,
                    "created_at": str(created_at) if created_at is not None else None,
                }
                if include_users:
                    entry["users"] = gid_to_users.get(gid, [])
                groups.append(entry)

            return groups
        except Exception:
            return []

    @db_connection
    def create_enrollment_code(self, *, code_name: str, group_id: int, uses: int, duration_sec: int) -> str:
        try:
            code_name = str(code_name).strip()
            group_id = int(group_id)
            uses = int(uses)
            duration_sec = int(duration_sec)

            if not code_name or uses <= 0 or duration_sec < 0 or group_id < 0:
                return ""

            self.cursor.execute("SELECT 1 FROM UserGroups WHERE group_id = ? LIMIT 1", (group_id,))
            if self.cursor.fetchone() is None:
                return ""

            self.cursor.execute(
                """
                INSERT INTO EnrollmentCodes (code_name, group_id, uses, duration_sec)
                VALUES (?, ?, ?, ?)
                """,
                (code_name, group_id, uses, duration_sec),
            )
            return code_name
        except Exception:
            return ""
        
    @db_connection
    def create_enrollment_codes(
        self, 
        *, 
        code_names: list[str], 
        group_id: int, 
        uses: int, 
        duration_sec: int
    ) -> str:
        try:
            # Basic sanitize / type normalization
            if not isinstance(code_names, list) or len(code_names) == 0:
                return ""

            group_id = int(group_id)
            uses = int(uses)
            duration_sec = int(duration_sec)

            if group_id < 0 or uses <= 0 or duration_sec < 0:
                return ""

            # Ensure group exists
            self.cursor.execute("SELECT 1 FROM UserGroups WHERE group_id = ? LIMIT 1", (group_id,))
            if self.cursor.fetchone() is None:
                return ""

            # Clean + de-dupe (preserve order)
            cleaned: list[str] = []
            seen: set[str] = set()
            for c in code_names:
                if not isinstance(c, str):
                    continue
                c = c.strip()
                if not c:
                    continue
                if c in seen:
                    continue
                seen.add(c)
                cleaned.append(c)

            if not cleaned:
                return ""

            # Insert many, silently skip conflicts/invalid rows
            created = 0
            for code in cleaned:
                try:
                    self.cursor.execute(
                        """
                        INSERT OR IGNORE INTO EnrollmentCodes (code_name, group_id, uses, duration_sec)
                        VALUES (?, ?, ?, ?)
                        """,
                        (code, group_id, uses, duration_sec),
                    )
                    # sqlite3 rowcount is 1 if inserted, 0 if ignored
                    if getattr(self.cursor, "rowcount", 0) == 1:
                        created += 1
                except Exception:
                    continue

            return f"Created {created}/{len(cleaned)} enrollment codes."
        except Exception:
            return ""

    @db_connection
    def generate_random_enrollment_code_names(
        self, *, count: int, char_count: int
    ) -> list[str]:
        try:
            count = int(count)
            char_count = int(char_count)

            if count <= 0 or char_count <= 0:
                return []

            import secrets
            import string

            alphabet = string.ascii_uppercase + string.digits

            # Pull existing codes once so we can reroll locally without hammering the DB.
            try:
                self.cursor.execute("SELECT code_name FROM EnrollmentCodes")
                existing_rows = self.cursor.fetchall() or []
                existing: set[str] = {
                    str(r[0]).strip() for r in existing_rows if r and r[0] is not None and str(r[0]).strip()
                }
            except Exception:
                existing = set()

            created: list[str] = []
            used: set[str] = set(existing)  # prevents collisions with DB + within this batch

            max_attempts = max(1000, count * 200)
            attempts = 0

            while len(created) < count and attempts < max_attempts:
                attempts += 1
                code = "".join(secrets.choice(alphabet) for _ in range(char_count))
                if code in used:
                    continue
                used.add(code)
                created.append(code)

            return created
        except Exception:
            return []
    
    @db_connection
    def delete_enrollment_code_name(self, *, code_name: str) -> bool:
        try:
            if not isinstance(code_name, str):
                return False

            code_name = code_name.strip()
            if not code_name:
                return False

            self.cursor.execute(
                "SELECT 1 FROM EnrollmentCodes WHERE code_name = ? LIMIT 1",
                (code_name,),
            )
            if self.cursor.fetchone() is None:
                return False

            self.cursor.execute(
                "DELETE FROM EnrollmentCodes WHERE code_name = ?",
                (code_name,),
            )
            return self.cursor.rowcount > 0
        except Exception:
            return False

    @db_connection
    def delete_enrollment_code_id(self, *, group_id: int) -> bool:
        try:
            group_id = int(group_id)
            if group_id < 0:
                return False

            self.cursor.execute(
                "DELETE FROM EnrollmentCodes WHERE group_id = ?",
                (group_id,),
            )
            return self.cursor.rowcount > 0
        except Exception:
            return False
    
    @db_connection
    def get_all_enrollment_codes(self) -> list[dict]:
        try:
            self.cursor.execute(
                "SELECT code_id, code_name, group_id, uses, duration_sec FROM EnrollmentCodes"
            )
            rows = self.cursor.fetchall() or []

            out: list[dict] = []
            for r in rows:
                try:
                    out.append(
                        {
                            "code_id": int(r[0]),
                            "code_name": str(r[1]),
                            "group_id": int(r[2]),
                            "uses": int(r[3]),
                            "duration_sec": int(r[4]),
                        }
                    )
                except Exception:
                    continue

            return out
        except Exception:
            return []
        
    @db_connection
    def validate_enrollment_code(self, *, code_name: str) -> bool:
        # Check if enrollment code exists and has remaining uses
        try:
            if not isinstance(code_name, str):
                return False
            code_name = code_name.strip()
            if not code_name:
                return False

            self.cursor.execute(
                "SELECT uses FROM EnrollmentCodes WHERE code_name = ? LIMIT 1",
                (code_name,),
            )
            row = self.cursor.fetchone()
            if row is None:
                return False

            try:
                uses_left = int(row[0])
            except Exception:
                return False

            return uses_left > 0
        except Exception:
            return False
    
    @db_connection
    def enroll_user_with_code(self, *, uid: int, code_name: str) -> bool:
        # Add into users table, and decrement uses in enrollment codes table
        try:
            uid = int(uid)
            code_name = str(code_name).strip()
            if uid < 0 or not code_name:
                return False

            # look up code + ensure it exists and has remaining uses
            self.cursor.execute(
                "SELECT group_id, uses FROM EnrollmentCodes WHERE code_name = ? LIMIT 1",
                (code_name,),
            )
            row = self.cursor.fetchone()
            if row is None:
                return False

            group_id = int(row[0])
            uses_left = int(row[1])
            if group_id < 0 or uses_left <= 0:
                return False

            # ensure group exists
            self.cursor.execute("SELECT 1 FROM UserGroups WHERE group_id = ? LIMIT 1", (group_id,))
            if self.cursor.fetchone() is None:
                return False

            # insert enrollment
            self.cursor.execute(
                "SELECT 1 FROM UsersLookup WHERE user_id = ? AND group_id = ? LIMIT 1",
                (uid, group_id),
            )
            if self.cursor.fetchone() is None:
                self.cursor.execute(
                    "INSERT INTO UsersLookup (user_id, group_id) VALUES (?, ?)",
                    (uid, group_id),
                )

            # decrement uses (guard again in SQL)
            self.cursor.execute(
                "UPDATE EnrollmentCodes SET uses = uses - 1 WHERE code_name = ? AND uses > 0",
                (code_name,),
            )
            if self.cursor.rowcount <= 0:
                return False

            # delete code if exhausted
            self.cursor.execute(
                "DELETE FROM EnrollmentCodes WHERE code_name = ? AND uses <= 0",
                (code_name,),
            )

            return True
        except Exception:
            return False

    @db_connection
    def get_users_devices(self, *, uid: int) -> list[int]:
        # union of all devices whitelists from all groups the user is in
        try:
            uid = int(uid)
            if uid < 0:
                return []

            # get all group_ids the user is enrolled in
            self.cursor.execute(
                "SELECT group_id FROM UsersLookup WHERE user_id = ?",
                (uid,),
            )
            group_rows = self.cursor.fetchall()
            if not group_rows:
                return []

            group_ids = [int(r[0]) for r in group_rows if r and r[0] is not None]
            if not group_ids:
                return []

            # fetch whitelists for those groups
            placeholders = ",".join(["?"] * len(group_ids))
            self.cursor.execute(
                f"SELECT devices_whitelist FROM UserGroups WHERE group_id IN ({placeholders})",
                tuple(group_ids),
            )
            rows = self.cursor.fetchall()
            if not rows:
                return []

            out_set: set[int] = set()
            for (wl_str,) in rows:
                if wl_str is None:
                    continue
                try:
                    parsed = json.loads(wl_str) if isinstance(wl_str, str) else []
                    if isinstance(parsed, list):
                        for x in parsed:
                            try:
                                out_set.add(int(x))
                            except Exception:
                                pass
                except Exception:
                    try:
                        parts = [p.strip() for p in str(wl_str).split(",")]
                        for p in parts:
                            if p != "":
                                out_set.add(int(p))
                    except Exception:
                        pass

            return sorted(out_set)
        except Exception:
            return []

    
    @db_connection
    def get_users_max_reservation_time(self, *, uid: int, device_id: int) -> tuple[bool, int]:
        # if the same device shows up in multiple groups, return the highest max_reservation_time_sec
        try:
            import json

            uid = int(uid)
            device_id = int(device_id)
            if uid < 0 or device_id < 0:
                return (False, 0)

            # find all groups the user is in
            self.cursor.execute("SELECT group_id FROM UsersLookup WHERE user_id = ?", (uid,))
            group_rows = self.cursor.fetchall()
            if not group_rows:
                return (False, 0)

            group_ids = [int(r[0]) for r in group_rows if r and r[0] is not None]
            if not group_ids:
                return (False, 0)

            placeholders = ",".join(["?"] * len(group_ids))
            self.cursor.execute(
                f"SELECT devices_whitelist, max_reservation_time_sec FROM UserGroups WHERE group_id IN ({placeholders})",
                tuple(group_ids),
            )
            rows = self.cursor.fetchall()
            if not rows:
                return (False, 0)

            allowed = False
            best = 0

            for wl_str, max_time in rows:
                # parse whitelist (JSON array preferred, tolerate fallback)
                whitelist: list[int] = []
                if wl_str is not None:
                    try:
                        parsed = json.loads(wl_str) if isinstance(wl_str, str) else []
                        if isinstance(parsed, list):
                            whitelist = [int(x) for x in parsed if str(x).strip() != ""]
                    except Exception:
                        try:
                            whitelist = [int(p.strip()) for p in str(wl_str).split(",") if p.strip() != ""]
                        except Exception:
                            whitelist = []

                if device_id in whitelist:
                    allowed = True
                    try:
                        t = int(max_time)
                    except Exception:
                        t = 0
                    if t > best:
                        best = t

            return (allowed, best if allowed else 0)
        except Exception:
            return (False, 0)

    @db_connection
    def get_users_max_reservations(self, *, uid: int, device_id: int) -> tuple[bool, int]:
        # if the same device shows up in multiple groups, return the highest max_reservations
        try:
            import json

            uid = int(uid)
            device_id = int(device_id)
            if uid < 0 or device_id < 0:
                return (False, 0)

            # find all groups the user is in
            self.cursor.execute("SELECT group_id FROM UsersLookup WHERE user_id = ?", (uid,))
            group_rows = self.cursor.fetchall()
            if not group_rows:
                return (False, 0)

            group_ids = [int(r[0]) for r in group_rows if r and r[0] is not None]
            if not group_ids:
                return (False, 0)

            placeholders = ",".join(["?"] * len(group_ids))
            self.cursor.execute(
                f"SELECT devices_whitelist, max_reservations FROM UserGroups WHERE group_id IN ({placeholders})",
                tuple(group_ids),
            )
            rows = self.cursor.fetchall()
            if not rows:
                return (False, 0)

            allowed = False
            best = 0

            for wl_str, max_res in rows:
                # parse whitelist (JSON array preferred, tolerate fallback)
                whitelist: list[int] = []
                if wl_str is not None:
                    try:
                        parsed = json.loads(wl_str) if isinstance(wl_str, str) else []
                        if isinstance(parsed, list):
                            whitelist = [int(x) for x in parsed if str(x).strip() != ""]
                    except Exception:
                        try:
                            whitelist = [int(p.strip()) for p in str(wl_str).split(",") if p.strip() != ""]
                        except Exception:
                            whitelist = []

                if device_id in whitelist:
                    allowed = True
                    try:
                        n = int(max_res)
                    except Exception:
                        n = 0
                    if n > best:
                        best = n

            return (allowed, best if allowed else 0)
        except Exception:
            return (False, 0)
        
    def _parse_whitelist(self, wl_str) -> set[int]:
        try:
            if wl_str is None:
                return set()
            if isinstance(wl_str, str):
                parsed = json.loads(wl_str)
                if isinstance(parsed, list):
                    return {int(x) for x in parsed}
            return set()
        except Exception:
            # tolerate old formats like "1,2,3"
            try:
                return {int(p.strip()) for p in str(wl_str).split(",") if p.strip() != ""}
            except Exception:
                return set()

    @db_connection
    def get_user_group_reservation_quota_rows(
        self,
        *,
        uid: int,
        reserved_device_ids: list[int],
    ) -> list[list[int]]:
        """
        Returns rows: [group_id, used_reservations_in_group, max_reservations_in_group]
        for every group the user is in.
        """
        try:
            uid = int(uid)
            if uid < 0:
                return []

            # sanitize reserved_device_ids
            try:
                rdevs = [int(d) for d in (reserved_device_ids or [])]
            except Exception:
                rdevs = []

            # groups for user
            self.cursor.execute("SELECT group_id FROM UsersLookup WHERE user_id = ?", (uid,))
            group_rows = self.cursor.fetchall() or []
            group_ids = [int(r[0]) for r in group_rows if r and r[0] is not None]
            if not group_ids:
                return []

            placeholders = ",".join(["?"] * len(group_ids))
            self.cursor.execute(
                f"""
                SELECT group_id, devices_whitelist, max_reservations
                FROM UserGroups
                WHERE group_id IN ({placeholders})
                """,
                tuple(group_ids),
            )
            rows = self.cursor.fetchall() or []

            out: list[list[int]] = []
            for gid, wl_str, max_res in rows:
                try:
                    gid = int(gid)
                    max_res = int(max_res)
                except Exception:
                    continue

                wl = self._parse_whitelist(wl_str)
                used = 0
                for d in rdevs:
                    if d in wl:
                        used += 1

                out.append([gid, used, max_res])

            # stable order
            out.sort(key=lambda x: x[0])
            return out
        except Exception:
            return []

    @db_connection
    def get_group_quota_for_device(
        self,
        *,
        uid: int,
        device_id: int,
        reserved_device_ids: list[int],
    ) -> tuple[bool, int, int, int]:
        try:
            uid = int(uid)
            device_id = int(device_id)
            if uid < 0 or device_id < 0:
                return (False, 0, 0, -1)

            try:
                rdevs = [int(d) for d in (reserved_device_ids or [])]
            except Exception:
                rdevs = []

            self.cursor.execute("SELECT group_id FROM UsersLookup WHERE user_id = ?", (uid,))
            group_rows = self.cursor.fetchall() or []
            group_ids = [int(r[0]) for r in group_rows if r and r[0] is not None]
            if not group_ids:
                return (False, 0, 0, -1)

            placeholders = ",".join(["?"] * len(group_ids))
            self.cursor.execute(
                f"""
                SELECT group_id, devices_whitelist, max_reservations
                FROM UserGroups
                WHERE group_id IN ({placeholders})
                """,
                tuple(group_ids),
            )
            rows = self.cursor.fetchall() or []
            if not rows:
                return (False, 0, 0, -1)

            candidates = []
            for gid, wl_str, max_res in rows:
                try:
                    gid = int(gid)
                    max_res = int(max_res)
                except Exception:
                    continue

                wl = self._parse_whitelist(wl_str)
                if device_id not in wl:
                    continue

                used = 0
                for d in rdevs:
                    if d in wl:
                        used += 1

                remaining = max_res - used  # can be <= 0 (meaning full/exceeded)

                # Sort key: prefer more remaining, then higher max, then fewer used, then lower gid
                candidates.append((remaining, max_res, -used, -gid, used, gid))

            if not candidates:
                return (False, 0, 0, -1)

            candidates.sort(reverse=True)
            _remaining, max_res, _neg_used, _neg_gid, used, gid = candidates[0]
            return (True, used, max_res, gid)

        except Exception:
            return (False, 0, 0, -1)
        
    @db_connection
    def check_expiration_and_cleanup(self) -> dict:
        def _parse_dt(v):
            if v is None:
                return None
            if isinstance(v, datetime):
                return v
            s = str(v).strip()
            if not s:
                return None
            try:
                return datetime.fromisoformat(s)
            except Exception:
                pass
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
                try:
                    return datetime.strptime(s, fmt)
                except Exception:
                    continue
            return None

        try:
            now = datetime.now()
            
            print("Flushing User Groups")

            expired_group_ids: list[int] = []
            expired_code_names: list[str] = []

            # ---- find expired groups ----
            self.cursor.execute("""
                SELECT group_id, lifetime_sec, created_at
                FROM UserGroups
                WHERE lifetime_sec > 0
            """)
            for group_id, lifetime_sec, created_at in (self.cursor.fetchall() or []):
                try:
                    gid = int(group_id)
                    life = int(lifetime_sec)
                except Exception:
                    continue
                if gid <= 0 or life <= 0:
                    continue

                dt = _parse_dt(created_at)
                if dt is None:
                    continue

                if (now - dt).total_seconds() >= life:
                    expired_group_ids.append(gid)

            # ---- find expired codes ----
            self.cursor.execute("""
                SELECT code_name, duration_sec, created_at
                FROM EnrollmentCodes
                WHERE duration_sec > 0
            """)
            for code_name, duration_sec, created_at in (self.cursor.fetchall() or []):
                code = str(code_name).strip() if code_name is not None else ""
                try:
                    dur = int(duration_sec)
                except Exception:
                    continue
                if not code or dur <= 0:
                    continue

                dt = _parse_dt(created_at)
                if dt is None:
                    continue

                if (now - dt).total_seconds() >= dur:
                    expired_code_names.append(code)

            # De-dupe
            expired_group_ids = sorted(set(expired_group_ids))
            expired_code_names = sorted(set(expired_code_names))

            codes_deleted = 0
            groups_deleted = 0

            # ---- delete expired codes by name ----
            for code in expired_code_names:
                try:
                    # reuse your existing deletion logic, but inline is cheaper
                    self.cursor.execute("DELETE FROM EnrollmentCodes WHERE code_name = ?", (code,))
                    if self.cursor.rowcount > 0:
                        codes_deleted += 1
                except Exception:
                    continue

            # ---- delete expired groups using your existing logic (cleanup cascade) ----
            for gid in expired_group_ids:
                try:
                    # Call the existing method; it will be serialized anyway, but avoid re-entering wrapper.
                    # So do the same SQL your delete_user_group() does:
                    self.cursor.execute("DELETE FROM EnrollmentCodes WHERE group_id = ?", (gid,))
                    self.cursor.execute("DELETE FROM UsersLookup WHERE group_id = ?", (gid,))
                    self.cursor.execute("DELETE FROM UserGroups WHERE group_id = ?", (gid,))
                    if self.cursor.rowcount > 0:
                        groups_deleted += 1
                except Exception:
                    continue

            return {
                "expired_groups_deleted": groups_deleted,
                "expired_codes_deleted": codes_deleted,
                "expired_group_ids": expired_group_ids,
                "expired_code_names": expired_code_names,
            }

        except Exception:
            return {
                "expired_groups_deleted": 0,
                "expired_codes_deleted": 0,
                "expired_group_ids": [],
                "expired_code_names": [],
            }

user_group_handler = UserGroupHandler()

def start_usergroup_cleanup_loop(
    *,
    interval_sec: int,
) -> Tuple[threading.Event, threading.Thread]:
    interval_sec = int(interval_sec)
    if interval_sec <= 0:
        interval_sec = 60

    stop_event = threading.Event()

    def _worker():
        while not stop_event.is_set():
            try:
                user_group_handler.check_expiration_and_cleanup()
            except Exception:
                # optional: log/printf traceback here if you want
                pass

            # interruptible sleep (wakes immediately when stop_event.set() is called)
            stop_event.wait(interval_sec)

    t = threading.Thread(target=_worker, name="usergroup_cleanup_loop", daemon=True)
    t.start()
    return stop_event, t

