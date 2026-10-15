"""Global accounts with a login at this lab (Server 1.5+).

Joining a lab by code from RemoteRF Global makes an ordinary local account
here -- same username and email as the Global account, its password a
verifier of a lab-bound secret the lab never sees the password behind
(core lan.py) -- and links it to the Global subject. That one account is the
user here on every path: logins over the LAN, and Global's signed requests
(devices, reservations, permissions), so nothing ever needs reconciling.
The link lives in usergroups.db beside FederatedPrincipals, where the
federation handlers resolve who a grant is for.
"""

from __future__ import annotations

import sqlite3
from uuid import NAMESPACE_URL, uuid5

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS GlobalAccountLinks ("
    "local_account_id INTEGER PRIMARY KEY, issuer_deployment_id TEXT NOT NULL, "
    "subject_id TEXT NOT NULL, created_at INTEGER NOT NULL, "
    "UNIQUE (issuer_deployment_id, subject_id))"
)


def principal_id(subject: str) -> str:
    """The id receipts and audits name a linked account by (a UUID, like a proxy's)."""
    return str(uuid5(NAMESPACE_URL, f"remoterf-link:{subject}"))


def global_home_id() -> str | None:
    """The RemoteRF Global home this lab holds a standing contract with."""
    from . import global_home

    return (global_home.load().get("identity") or {}).get("deployment_id")


def account_for(conn: sqlite3.Connection, issuer: str, subject: str) -> int | None:
    """The linked account for this grant's (iss, sub), on the caller's usergroups connection."""
    try:
        row = conn.execute(
            "SELECT local_account_id FROM GlobalAccountLinks WHERE issuer_deployment_id=? AND subject_id=?",
            (issuer, subject),
        ).fetchone()
    except sqlite3.OperationalError:
        return None  # never linked anyone: no table
    return int(row[0]) if row else None


def _usergroups() -> sqlite3.Connection:
    from ..user_group_handler import user_group_handler

    return sqlite3.connect(user_group_handler.filepath, timeout=10.0)


def is_linked(local_account_id: int) -> bool:
    with _usergroups() as conn:
        try:
            return conn.execute("SELECT 1 FROM GlobalAccountLinks WHERE local_account_id=?",
                                (int(local_account_id),)).fetchone() is not None
        except sqlite3.OperationalError:
            return False


def lookup(issuer: str, subject: str) -> int | None:
    with _usergroups() as conn:
        return account_for(conn, issuer, subject)


def link(local_account_id: int, issuer: str, subject: str, now: int) -> None:
    with _usergroups() as conn:
        conn.execute(SCHEMA)
        conn.execute("INSERT OR REPLACE INTO GlobalAccountLinks VALUES (?,?,?,?)",
                     (int(local_account_id), issuer, subject, int(now)))
