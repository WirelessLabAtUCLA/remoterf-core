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

"""Remote admin: pinned lab admins reach a restricted `serverrf` shell over
SSH carried inside the lab's gRPC port (docs/remote-admin-design.md).

This module is the lab's side of it at rest: the admin host key, the pins in
remote_admin.db (its own file, so no purge half-removes it), one-time codes,
the append-only audit log, the policy, and the `admins …` console commands.
`remote_admin_ssh` serves the tunnel; `remoteRF_server.remote_admin_shell` is
the shell an admin lands in.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path

DB_NAME = "remote_admin.db"
PAIR_TTL = 24 * 3600
DEVICE_CODE_TTL = 600
CODE_ATTEMPTS = 5
MIN_PASSWORD = 12
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_FP_PREFIX = 12  # base64 characters of the host key fingerprint a pairing code carries

SCHEMA = """
CREATE TABLE IF NOT EXISTS remote_admins (
    admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT 'lab',
    acc_id INTEGER UNIQUE,
    username TEXT NOT NULL,
    subject_id TEXT,
    email_snapshot TEXT,
    pass_salt TEXT,
    pass_hash TEXT,
    read_only INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    disabled_at INTEGER
);
CREATE TABLE IF NOT EXISTS remote_admin_devices (
    device_id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL,
    pubkey TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    label TEXT,
    approved_via TEXT NOT NULL,
    approved_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS remote_admin_codes (
    code_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    device_fp TEXT,
    session_id TEXT,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used_at INTEGER
);
CREATE TABLE IF NOT EXISTS remote_admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    admin TEXT,
    device_fp TEXT,
    route TEXT,
    session_id TEXT,
    event TEXT NOT NULL,
    argv_json TEXT,
    rc INTEGER
);
CREATE TRIGGER IF NOT EXISTS remote_admin_audit_no_update BEFORE UPDATE ON remote_admin_audit
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS remote_admin_audit_no_delete BEFORE DELETE ON remote_admin_audit
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TABLE IF NOT EXISTS remote_admin_policy (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

POLICY_DEFAULTS = {"relay": "on", "new_device": "email"}


# -----------------------------
# Files
# -----------------------------

def _db_dir() -> Path:
    from ..common.utils.db_location import get_db_dir

    return get_db_dir()


def db_path() -> Path:
    return _db_dir() / DB_NAME


def home_dir() -> Path:
    from .global_onboarding import cfg_dir

    return cfg_dir() / "remote_admin"


def host_key_path() -> Path:
    return home_dir() / "host_ed25519"


def backups_dir() -> Path:
    return home_dir() / "backups"


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def host_key(*, create: bool = False):
    """The lab's dedicated admin host key (paramiko), or None before the first pin."""
    import paramiko

    path = host_key_path()
    if not path.exists():
        if not create:
            return None
        _write_new_host_key(path)
    return paramiko.Ed25519Key(filename=str(path))


def _write_new_host_key(path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    tmp = path.with_suffix(".new")
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    os.replace(tmp, path)


def public_line(key) -> str:
    return f"{key.get_name()} {key.get_base64()}"


# -----------------------------
# Accounts (read straight from the lab's databases)
# -----------------------------

def _account(*, acc_id: int | None = None, username: str | None = None):
    path = _db_dir() / "reservations.db"
    if not path.exists():
        return None
    with closing(sqlite3.connect(path, timeout=10.0)) as conn:
        conn.row_factory = sqlite3.Row
        if acc_id is not None:
            row = conn.execute("SELECT acc_id, username, email, auth_type FROM Accounts WHERE acc_id=?", (acc_id,)).fetchone()
        else:
            row = conn.execute("SELECT acc_id, username, email, auth_type FROM Accounts WHERE username=?", (username,)).fetchone()
        if row is None:
            return None
        try:
            bound = conn.execute("SELECT 1 FROM FederatedAccountBindings WHERE local_account_id=?",
                                 (row["acc_id"],)).fetchone() is not None
        except sqlite3.OperationalError:
            bound = False
        return {**dict(row), "federated": bound or row["auth_type"] != "local_password" or row["username"].startswith("fed-")}


def _is_admin(username: str) -> bool:
    path = _db_dir() / "perms.db"
    if not path.exists():
        return False
    with closing(sqlite3.connect(path, timeout=10.0)) as conn:
        try:
            return conn.execute("SELECT 1 FROM Admins WHERE Username=?", (username,)).fetchone() is not None
        except sqlite3.OperationalError:
            return False


def _link_subject(acc_id: int, username: str) -> str | None:
    """The Global subject of a linked account here (its device codes go to that address)."""
    path = _db_dir() / "usergroups.db"
    if not path.exists():
        return None
    with closing(sqlite3.connect(path, timeout=10.0)) as conn:
        try:
            row = conn.execute("SELECT subject_id FROM GlobalAccountLinks WHERE local_account_id=? AND username=?",
                               (acc_id, username)).fetchone()
        except sqlite3.OperationalError:
            return None
    return row[0] if row else None


# -----------------------------
# Pins
# -----------------------------

def login_name(pin) -> str:
    return f"{pin['username']}@global" if pin["kind"] == "global" else pin["username"]


def _split_login(login: str) -> tuple[str, str]:
    name, at, where = login.strip().rpartition("@")
    if at and where.lower() == "global":
        return "global", name
    return "lab", login.strip()


def find_pin(conn, login: str, *, active: bool = True):
    kind, name = _split_login(login)
    sql = "SELECT * FROM remote_admins WHERE kind=? AND username=?"
    if active:
        sql += " AND disabled_at IS NULL"
    return conn.execute(sql + " ORDER BY admin_id DESC LIMIT 1", (kind, name)).fetchone()


def pin_by_id(conn, admin_id: int):
    return conn.execute("SELECT * FROM remote_admins WHERE admin_id=?", (int(admin_id),)).fetchone()


def pin_problem(pin) -> str | None:
    """Why this pin may not log in right now, or None. Checked at every login and
    while a session runs: a deleted, renamed or demoted account ends remote admin."""
    if pin is None:
        return "not pinned"
    if pin["disabled_at"] is not None:
        return "pin disabled"
    if pin["kind"] == "global":
        return None
    account = _account(acc_id=pin["acc_id"])
    if account is None or account["username"] != pin["username"]:
        return "account gone"
    if account["federated"]:
        return "not a lab account"
    if not _is_admin(pin["username"]):
        return "no longer an Admin"
    return None


def any_active_pin() -> bool:
    if not db_path().exists():
        return False
    with closing(connect()) as conn:
        return conn.execute("SELECT 1 FROM remote_admins WHERE disabled_at IS NULL LIMIT 1").fetchone() is not None


def set_password(conn, admin_id: int, password: str) -> None:
    from ..common.utils.api_token import hash_password

    salt, hashed = hash_password(password)
    conn.execute("UPDATE remote_admins SET pass_salt=?, pass_hash=? WHERE admin_id=?", (salt, hashed, int(admin_id)))


_DUMMY = None


def check_password(pin, password: str) -> bool:
    """Against the remote-admin verifier only, never the account's. A pin with no
    password (not paired yet) or no pin costs the same time and fails."""
    from ..common.utils.api_token import hash_password, verify_password

    global _DUMMY
    if pin is None or not pin["pass_hash"]:
        _DUMMY = _DUMMY or hash_password(secrets.token_hex(8))
        verify_password(_DUMMY[0], _DUMMY[1], password)
        return False
    return verify_password(pin["pass_salt"], pin["pass_hash"], password)[0]


def disable_pin(conn, admin_id: int, *, now: int | None = None) -> None:
    now = int(now or time.time())
    conn.execute("UPDATE remote_admins SET disabled_at=? WHERE admin_id=? AND disabled_at IS NULL", (now, int(admin_id)))
    conn.execute("UPDATE remote_admin_devices SET revoked_at=? WHERE admin_id=? AND revoked_at IS NULL", (now, int(admin_id)))
    conn.execute("UPDATE remote_admin_codes SET used_at=? WHERE admin_id=? AND used_at IS NULL", (now, int(admin_id)))


# -----------------------------
# Devices
# -----------------------------

def device_for(conn, admin_id: int, pubkey: str):
    return conn.execute("SELECT * FROM remote_admin_devices WHERE admin_id=? AND pubkey=? AND revoked_at IS NULL",
                        (int(admin_id), pubkey)).fetchone()


def approve_device(conn, admin_id: int, pubkey: str, fingerprint: str, label: str, via: str) -> None:
    now = int(time.time())
    conn.execute(
        "INSERT INTO remote_admin_devices(admin_id,pubkey,fingerprint,label,approved_via,approved_at,last_used_at) "
        "VALUES (?,?,?,?,?,?,?) ON CONFLICT(pubkey) DO UPDATE SET admin_id=excluded.admin_id, label=excluded.label, "
        "approved_via=excluded.approved_via, approved_at=excluded.approved_at, last_used_at=excluded.last_used_at, "
        "revoked_at=NULL",
        (int(admin_id), pubkey, fingerprint, label, via, now, now))


def revoke_devices(conn, admin_id: int, fp: str) -> int:
    """`all`, or one device by its fingerprint (any unique prefix, with or without SHA256:)."""
    now = int(time.time())
    if fp == "all":
        return conn.execute("UPDATE remote_admin_devices SET revoked_at=? WHERE admin_id=? AND revoked_at IS NULL",
                            (now, int(admin_id))).rowcount
    fp = fp if fp.startswith("SHA256:") else "SHA256:" + fp
    rows = conn.execute("SELECT device_id FROM remote_admin_devices WHERE admin_id=? AND revoked_at IS NULL "
                        "AND fingerprint LIKE ? ESCAPE '\\'",
                        (int(admin_id), fp.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")).fetchall()
    if len(rows) != 1:
        return -len(rows)  # 0: none; negative: ambiguous
    conn.execute("UPDATE remote_admin_devices SET revoked_at=? WHERE device_id=?", (now, rows[0][0]))
    return 1


# -----------------------------
# Codes
# -----------------------------

def _normalize(code: str) -> str:
    return code.split(".", 1)[0].upper().replace("-", "").replace(" ", "")


def _code_hash(code: str) -> str:
    return hashlib.sha256(("remoterf-admin-code:" + _normalize(code)).encode()).hexdigest()


def issue_code(conn, admin_id: int, purpose: str, *, length: int, ttl: int, device_fp=None, session_id=None) -> str:
    """A fresh one-time code; any older unused one of the same purpose dies with it."""
    now = int(time.time())
    conn.execute("UPDATE remote_admin_codes SET used_at=? WHERE admin_id=? AND purpose=? AND used_at IS NULL",
                 (now, int(admin_id), purpose))
    code = "".join(secrets.choice(_B32) for _ in range(length))
    conn.execute("INSERT INTO remote_admin_codes(code_hash,admin_id,purpose,device_fp,session_id,expires_at) "
                 "VALUES (?,?,?,?,?,?)", (_code_hash(code), int(admin_id), purpose, device_fp, session_id, now + ttl))
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4)) if purpose == "pair" else code


def redeem_code(conn, admin_id: int, purpose: str, typed: str, *, device_fp=None, session_id=None) -> bool:
    """One use, CODE_ATTEMPTS tries, unexpired; a device code only for the device
    and SSH session it was sent for."""
    now = int(time.time())
    sql = ("SELECT code_hash FROM remote_admin_codes WHERE admin_id=? AND purpose=? AND used_at IS NULL "
           "AND expires_at>? AND attempts<?")
    params = [int(admin_id), purpose, now, CODE_ATTEMPTS]
    if purpose == "device":
        sql += " AND device_fp=? AND session_id=?"
        params += [device_fp, session_id]
    hashes = [row[0] for row in conn.execute(sql, params)]
    if not hashes:
        return False
    wanted = _code_hash(typed or "")
    if wanted in hashes:
        conn.execute("UPDATE remote_admin_codes SET used_at=? WHERE code_hash=?", (now, wanted))
        return True
    conn.executemany("UPDATE remote_admin_codes SET attempts=attempts+1 WHERE code_hash=?", [(h,) for h in hashes])
    return False


def email_device_code(pin, code: str, fp: str, label: str, route: str) -> str | None:
    """Have Global email a new-device code to this pin's Global address. The
    masked address, or None when the pin has no email path (console codes only)."""
    return None


# -----------------------------
# Audit, policy
# -----------------------------

def audit(event: str, *, admin=None, device_fp=None, route=None, session_id=None, detail=None, rc=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute(
            "INSERT INTO remote_admin_audit(ts,admin,device_fp,route,session_id,event,argv_json,rc) VALUES (?,?,?,?,?,?,?,?)",
            (int(time.time()), admin, device_fp, route, session_id, event,
             None if detail is None else json.dumps(detail), rc))
        if own:
            conn.commit()
    finally:
        if own:
            conn.close()


def policy(conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        return {**POLICY_DEFAULTS, **{k: v for k, v in conn.execute("SELECT key, value FROM remote_admin_policy")}}
    finally:
        if own:
            conn.close()


# -----------------------------
# Console commands: `admins …` (never remote; see remote_admin_shell)
# -----------------------------

def _lab_locator() -> str:
    from . import global_onboarding as g

    if g.participating() and g.state() == "active" and g.lab_slug():
        return g.lab_slug()
    return g.lan_endpoint() or "<lab address>"


def _print_pair(conn, pin) -> None:
    key = host_key(create=True)
    code = issue_code(conn, pin["admin_id"], "pair", length=16, ttl=PAIR_TTL)
    prefix = key.fingerprint.split(":", 1)[1][:_FP_PREFIX]
    print("Pairing code (24 h, one use; it also vouches for this lab's host key):")
    print(f"  remoterf --remote-admin pair {login_name(pin)}@{_lab_locator()} {code}.{prefix}")
    print(f"Host key {key.fingerprint}")


def _usage(text: str) -> int:
    print(f"Usage: {text}", file=sys.stderr)
    return 2


def _pin_or_complain(conn, login: str):
    pin = find_pin(conn, login)
    if pin is None:
        print(f"{login} is not a remote admin here. `admins list` shows who is.", file=sys.stderr)
    return pin


def cmd_admins_list(argv) -> int:
    from ..common.utils.panel import print_table

    with closing(connect()) as conn:
        rows = []
        for pin in conn.execute("SELECT * FROM remote_admins WHERE disabled_at IS NULL ORDER BY admin_id"):
            devices = conn.execute("SELECT COUNT(*), MAX(last_used_at) FROM remote_admin_devices "
                                   "WHERE admin_id=? AND revoked_at IS NULL", (pin["admin_id"],)).fetchone()
            problem = pin_problem(pin)
            rows.append({"admin": login_name(pin), "access": "read-only" if pin["read_only"] else "full",
                         "devices": devices[0], "last_used": _when(devices[1]),
                         "state": problem or ("active" if pin["pass_hash"] else "not paired yet")})
    print_table("Remote admins", rows, ["admin", "access", "devices", "last_used", "state"],
                empty="No remote admins. Pin one: admins add <username> [--read-only]")
    return 0


def _when(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""


def cmd_admins_add(argv) -> int:
    read_only = "--read-only" in argv
    names = [a for a in argv if not a.startswith("-")]
    if len(names) != 1:
        return _usage("admins add <username> [--read-only]   (a Global-only account: <name>@global)")
    login = names[0]
    kind, name = _split_login(login)
    with closing(connect()) as conn:
        if find_pin(conn, login) is not None:
            print(f"{login} is already a remote admin. A new device or a forgotten password: admins code {login}",
                  file=sys.stderr)
            return 1
        if kind == "global":
            pin_row = _add_global_pin(conn, name, read_only)
            if pin_row is None:
                return 1
        else:
            account = _account(username=name)
            if account is None:
                print(f"No account {name} here.", file=sys.stderr)
                return 1
            if account["federated"]:
                print(f"{name} is a visitor from another deployment; only this lab's own accounts can be remote admins.",
                      file=sys.stderr)
                return 1
            if not _is_admin(name):
                print(f"{name} is not an Admin. Make them one first (users manage); pinning never grants the role.",
                      file=sys.stderr)
                return 1
            conn.execute("DELETE FROM remote_admins WHERE acc_id=? AND disabled_at IS NOT NULL", (account["acc_id"],))
            cur = conn.execute(
                "INSERT INTO remote_admins(kind,acc_id,username,subject_id,email_snapshot,read_only,created_at) "
                "VALUES ('lab',?,?,?,?,?,?)",
                (account["acc_id"], name, _link_subject(account["acc_id"], name), account["email"], int(read_only),
                 int(time.time())))
            pin_row = pin_by_id(conn, cur.lastrowid)
        audit("pin_added", admin=login, detail={"read_only": read_only}, conn=conn)
        print(f"Pinned {login} as a {'read-only ' if read_only else ''}remote admin.")
        _print_pair(conn, pin_row)
        conn.commit()
    return 0


def _add_global_pin(conn, name: str, read_only: bool):
    print("Global-only accounts can be pinned once this lab runs the Global part of remote admin.", file=sys.stderr)
    return None


def cmd_admins_code(argv) -> int:
    if len(argv) != 1:
        return _usage("admins code <username>")
    with closing(connect()) as conn:
        pin = _pin_or_complain(conn, argv[0])
        if pin is None:
            return 1
        print(f"For a new device of {argv[0]}, or to set a new remote-admin password:")
        _print_pair(conn, pin)
        audit("code_issued", admin=argv[0], conn=conn)
        conn.commit()
    return 0


def cmd_admins_remove(argv) -> int:
    if len(argv) != 1:
        return _usage("admins remove <username>")
    with closing(connect()) as conn:
        pin = _pin_or_complain(conn, argv[0])
        if pin is None:
            return 1
        disable_pin(conn, pin["admin_id"])
        audit("pin_removed", admin=argv[0], conn=conn)
        conn.commit()
    print(f"{argv[0]} is no longer a remote admin; any session they have open ends within seconds.")
    return 0


def cmd_admins_devices(argv) -> int:
    from ..common.utils.panel import print_table

    with closing(connect()) as conn:
        pins = [find_pin(conn, argv[0])] if argv else list(conn.execute(
            "SELECT * FROM remote_admins WHERE disabled_at IS NULL ORDER BY admin_id"))
        if argv and pins[0] is None:
            return 1 if _pin_or_complain(conn, argv[0]) is None else 0
        rows = [{"admin": login_name(pin), "device": d["fingerprint"], "label": d["label"] or "",
                 "approved": f"{_when(d['approved_at'])} ({d['approved_via']})", "last_used": _when(d["last_used_at"])}
                for pin in pins
                for d in conn.execute("SELECT * FROM remote_admin_devices WHERE admin_id=? AND revoked_at IS NULL",
                                      (pin["admin_id"],))]
    print_table("Remote-admin devices", rows, ["admin", "device", "label", "approved", "last_used"], empty="No devices.")
    return 0


def cmd_admins_revoke(argv) -> int:
    if len(argv) != 2:
        return _usage("admins revoke <username> <fingerprint|all>")
    with closing(connect()) as conn:
        pin = _pin_or_complain(conn, argv[0])
        if pin is None:
            return 1
        n = revoke_devices(conn, pin["admin_id"], argv[1])
        if n == 0:
            print("No such device. `admins devices` lists them.", file=sys.stderr)
            return 1
        if n < 0:
            print("That fingerprint matches more than one device; give more of it.", file=sys.stderr)
            return 1
        audit("device_revoked", admin=argv[0], detail={"device": argv[1], "by": "console"}, conn=conn)
        conn.commit()
    print(f"Revoked {n} device(s) of {argv[0]}; their sessions end within seconds.")
    return 0


def cmd_admins_log(argv) -> int:
    from ..common.utils.panel import print_table

    try:
        n = max(1, min(1000, int(argv[0]))) if argv else 30
    except ValueError:
        return _usage("admins log [N]")
    with closing(connect()) as conn:
        rows = list(conn.execute("SELECT * FROM remote_admin_audit ORDER BY id DESC LIMIT ?", (n,)))
    print_table("Remote-admin audit", [
        {"when": time.strftime("%m-%d %H:%M:%S", time.localtime(r["ts"])), "admin": r["admin"] or "",
         "route": r["route"] or "", "event": r["event"], "detail": _detail(r["argv_json"]),
         "rc": "" if r["rc"] is None else r["rc"]} for r in reversed(rows)],
        ["when", "admin", "route", "event", "detail", "rc"], empty="Nothing yet.")
    return 0


def _detail(raw) -> str:
    if not raw:
        return ""
    value = json.loads(raw)
    if isinstance(value, dict) and "argv" in value:
        return " ".join(value["argv"])
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def cmd_admins_hostkey(argv) -> int:
    if argv and argv != ["rotate"]:
        return _usage("admins hostkey [rotate]")
    if argv:
        if not _confirm("Every remote admin will have to trust the new key (a fresh code, or "
                        "`remoterf --remote-admin trust`). Type 'rotate' to confirm: ", "rotate"):
            return 1
        path = host_key_path()
        if path.exists():
            path.unlink()
        key = host_key(create=True)
        audit("hostkey_rotated", detail={"fingerprint": key.fingerprint})
        print(f"New host key {key.fingerprint}")
        return 0
    key = host_key()
    print(f"Host key {key.fingerprint}" if key else "No host key yet; the first `admins add` makes one.")
    return 0


def _confirm(prompt: str, word: str) -> bool:
    try:
        return input(prompt).strip().lower() == word
    except (EOFError, KeyboardInterrupt):
        return False


def cmd_admins_policy(argv) -> int:
    usage = "admins policy [relay on|off] [new-device email|console]"
    allowed = {"relay": {"on", "off"}, "new-device": {"email", "console"}}
    if len(argv) % 2:
        return _usage(usage)
    changes = dict(zip(argv[::2], argv[1::2]))
    if any(k not in allowed or v not in allowed[k] for k, v in changes.items()):
        return _usage(usage)
    with closing(connect()) as conn:
        for key, value in changes.items():
            conn.execute("INSERT OR REPLACE INTO remote_admin_policy VALUES (?,?)", (key.replace("-", "_"), value))
        if changes:
            audit("policy", detail=changes, conn=conn)
        conn.commit()
        current = policy(conn)
    print(f"relay       {current['relay']}   (off: LAN and VPN only)")
    print(f"new-device  {current['new_device']}   (console: only `admins code` approves a new device)")
    return 0


def cmd_admins_kick(argv) -> int:
    from . import remote_admin_ssh

    n = remote_admin_ssh.kick(argv[0] if argv else None)
    print(f"Ended {n} remote-admin session(s).")
    return 0
