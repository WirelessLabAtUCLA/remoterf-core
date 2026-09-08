"""Offline, evidence-bound Global-v1 owner-state disposal tooling.

This module never guesses ownership from names, suffixes, groups, or dates.
Preflight derives candidates only from exact GlobalPrincipalMappings row IDs,
records every relevant source-file digest, and leaves every deletion unchecked
for human review.  Apply requires a fully reviewed manifest and creates a
private restore archive before touching any row.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import time
from pathlib import Path

from remoterf_federation_core import canonical_json, canonical_uuid, strict_json

from .migrations import (
    check_gate_c_ready,
    initialize_native_subjects,
    migrate_gate_c,
)

FORMAT = "remoterf-global-v1-disposal-v1"
SOURCE_NAMES = ("reservations.db", "usergroups.db", "perms.db", "global.db")
PROTECTED_SOURCE_NAMES = ("reservations.db", "usergroups.db", "perms.db")
GLOBAL_TABLES = {
    "GlobalPrincipalMappings",
    "GlobalAssertionJTIs",
    "GlobalLocalSessions",
    "GlobalCatalogState",
}


class DisposalError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def _source_record(path: Path) -> dict:
    if not path.exists():
        return {"present": False}
    with sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True) as conn:
        tables = sorted(_tables(conn))
    return {
        "present": True,
        "sha256": _sha256(path),
        "size": path.stat().st_size,
        "tables": tables,
    }


def build_preflight(db_dir: str | Path) -> dict:
    root = Path(db_dir).resolve()
    sources = {name: _source_record(root / name) for name in SOURCE_NAMES}
    blockers: list[str] = []
    for name in SOURCE_NAMES:
        for suffix in ("-wal", "-journal"):
            sidecar = root / (name + suffix)
            if sidecar.exists() and sidecar.stat().st_size:
                blockers.append(
                    f"{sidecar.name} is present; quiesce/checkpoint writers first"
                )
    candidates = {
        "accounts": [],
        "reservations": [],
        "memberships": [],
        "roles": [],
    }
    for name in PROTECTED_SOURCE_NAMES:
        if not (root / name).exists():
            blockers.append(f"{name} is missing")
    reservations_path = root / "reservations.db"
    global_path = root / "global.db"
    mappings: list[tuple] = []

    if global_path.exists():
        with sqlite3.connect(f"file:{global_path}?mode=ro", uri=True) as conn:
            tables = _tables(conn)
            missing = sorted(GLOBAL_TABLES - tables)
            unexpected = sorted(tables - GLOBAL_TABLES)
            if missing:
                blockers.append("global.db missing expected tables: " + ", ".join(missing))
            if unexpected:
                blockers.append("global.db has unexpected tables: " + ", ".join(unexpected))
            if "GlobalPrincipalMappings" in tables:
                mappings = conn.execute(
                    "SELECT id, issuer, global_subject, local_account_id, status "
                    "FROM GlobalPrincipalMappings ORDER BY id"
                ).fetchall()

    accounts_by_id: dict[int, tuple] = {}
    if reservations_path.exists():
        with sqlite3.connect(f"file:{reservations_path}?mode=ro", uri=True) as conn:
            tables = _tables(conn)
            if "Accounts" not in tables:
                blockers.append("reservations.db has no Accounts table")
            else:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(Accounts)")}
                auth_expr = "auth_type" if "auth_type" in columns else "'local_password'"
                for row in conn.execute(
                    f"SELECT acc_id, username, email, {auth_expr} FROM Accounts ORDER BY acc_id"
                ):
                    accounts_by_id[int(row[0])] = row
                if "auth_type" in columns:
                    unknown = conn.execute(
                        "SELECT acc_id, auth_type FROM Accounts "
                        "WHERE auth_type NOT IN ('local_password','remoterf_global') "
                        "OR auth_type IS NULL ORDER BY acc_id"
                    ).fetchall()
                    for account_id, auth_type in unknown:
                        blockers.append(
                            f"account {int(account_id)} has unknown auth_type {auth_type!r}"
                        )

    mapping_by_account: dict[int, list[tuple]] = {}
    for mapping in mappings:
        mapping_by_account.setdefault(int(mapping[3]), []).append(mapping)
    for account_id, rows in sorted(mapping_by_account.items()):
        if len(rows) != 1:
            blockers.append(f"account {account_id} has {len(rows)} legacy mappings")
            continue
        mapping = rows[0]
        account = accounts_by_id.get(account_id)
        if account is None:
            blockers.append(f"mapping {int(mapping[0])} references missing account {account_id}")
            continue
        if account[3] != "remoterf_global":
            blockers.append(
                f"mapping {int(mapping[0])} references protected/non-v1 account "
                f"{account_id} with auth_type {account[3]!r}"
            )
            continue
        candidates["accounts"].append(
            {
                "mapping_id": int(mapping[0]),
                "acc_id": account_id,
                "username": str(account[1]),
                "email": str(account[2]),
                "auth_type": str(account[3]),
                "delete": False,
            }
        )

    for account_id, account in sorted(accounts_by_id.items()):
        if account[3] == "remoterf_global" and account_id not in mapping_by_account:
            blockers.append(f"legacy account {account_id} has no exact principal mapping")

    approved_ids = {row["acc_id"] for row in candidates["accounts"]}
    usernames = {row["acc_id"]: row["username"] for row in candidates["accounts"]}
    if approved_ids and reservations_path.exists():
        with sqlite3.connect(f"file:{reservations_path}?mode=ro", uri=True) as conn:
            if "Reservations" in _tables(conn):
                for account_id, name in sorted(usernames.items()):
                    rows = conn.execute(
                        "SELECT res_id, username, device_id, start_time, end_time "
                        "FROM Reservations WHERE username = ? ORDER BY res_id",
                        (name,),
                    ).fetchall()
                    candidates["reservations"].extend(
                        {
                            "res_id": int(row[0]),
                            "acc_id": account_id,
                            "username": str(row[1]),
                            "device_id": int(row[2]),
                            "start_time": str(row[3]),
                            "end_time": str(row[4]),
                            "delete": False,
                        }
                        for row in rows
                    )

    usergroups_path = root / "usergroups.db"
    if approved_ids and usergroups_path.exists():
        with sqlite3.connect(f"file:{usergroups_path}?mode=ro", uri=True) as conn:
            if "UsersLookup" in _tables(conn):
                for account_id in sorted(approved_ids):
                    for user_id, group_id in conn.execute(
                        "SELECT user_id, group_id FROM UsersLookup "
                        "WHERE user_id = ? ORDER BY group_id",
                        (account_id,),
                    ):
                        candidates["memberships"].append(
                            {
                                "user_id": int(user_id),
                                "group_id": int(group_id),
                                "delete": False,
                            }
                        )

    perms_path = root / "perms.db"
    if approved_ids and perms_path.exists():
        with sqlite3.connect(f"file:{perms_path}?mode=ro", uri=True) as conn:
            tables = _tables(conn)
            for table, id_column in (
                ("Users", "UserID"),
                ("PowerUsers", "UserID"),
                ("Admins", "AdminID"),
            ):
                if table not in tables:
                    continue
                for account_id, name in sorted(usernames.items()):
                    for row_id, username in conn.execute(
                        f"SELECT {id_column}, Username FROM {table} WHERE Username = ?",
                        (name,),
                    ):
                        candidates["roles"].append(
                            {
                                "table": table,
                                "id_column": id_column,
                                "row_id": int(row_id),
                                "acc_id": account_id,
                                "username": str(username),
                                "delete": False,
                            }
                        )

    global_counts = {}
    if global_path.exists():
        with sqlite3.connect(f"file:{global_path}?mode=ro", uri=True) as conn:
            for table in sorted(_tables(conn)):
                quoted = table.replace('"', '""')
                global_counts[table] = int(
                    conn.execute(f'SELECT COUNT(*) FROM "{quoted}"').fetchone()[0]
                )

    return {
        "format": FORMAT,
        "created_at": int(time.time()),
        "db_dir": str(root),
        "reviewed": False,
        "sources": sources,
        "global_table_counts": global_counts,
        "blockers": blockers,
        "candidates": candidates,
    }


def write_preflight(db_dir: str | Path, manifest_path: str | Path) -> dict:
    manifest = build_preflight(db_dir)
    destination = Path(manifest_path)
    if destination.exists():
        raise DisposalError("refusing to overwrite an existing manifest")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    os.chmod(destination, 0o600)
    return manifest


def _load_manifest(path: str | Path) -> dict:
    raw = Path(path).read_bytes()
    if len(raw) > 1024 * 1024:
        raise DisposalError("manifest exceeds size limit")
    value = strict_json(raw)
    if type(value) is not dict or value.get("format") != FORMAT:
        raise DisposalError("unsupported disposal manifest")
    return value


def _verify_sources(manifest: dict, root: Path) -> None:
    if Path(manifest.get("db_dir", "")).resolve() != root.resolve():
        raise DisposalError("manifest DB directory does not match")
    for name in SOURCE_NAMES:
        expected = manifest["sources"][name]
        path = root / name
        if bool(expected.get("present")) != path.exists():
            raise DisposalError(f"source presence changed: {name}")
        if path.exists() and (
            expected.get("sha256") != _sha256(path)
            or int(expected.get("size", -1)) != path.stat().st_size
        ):
            raise DisposalError(f"source changed after review: {name}")


def _require_review(manifest: dict) -> None:
    if manifest.get("reviewed") is not True:
        raise DisposalError("manifest has not been marked reviewed")
    if manifest.get("blockers"):
        raise DisposalError("manifest contains unresolved blockers")
    candidates = manifest.get("candidates")
    if type(candidates) is not dict or set(candidates) != {
        "accounts",
        "reservations",
        "memberships",
        "roles",
    }:
        raise DisposalError("manifest candidate categories are invalid")
    for category, rows in candidates.items():
        if type(rows) is not list or any(row.get("delete") is not True for row in rows):
            raise DisposalError(f"all {category} candidates require explicit delete=true")


def _verify_exact_candidates(manifest: dict, root: Path) -> None:
    fresh = build_preflight(root)
    if fresh["blockers"]:
        raise DisposalError("source preflight now contains blockers")

    def reviewed_shape(candidates):
        return {
            category: [dict(row, delete=False) for row in rows]
            for category, rows in candidates.items()
        }

    if reviewed_shape(manifest["candidates"]) != fresh["candidates"]:
        raise DisposalError("reviewed candidate rows do not match exact source evidence")


def apply_disposal(
    manifest_path: str | Path,
    *,
    archive_dir: str | Path,
    deployment_id: str,
) -> dict:
    manifest = _load_manifest(manifest_path)
    _require_review(manifest)
    deployment_id = canonical_uuid(deployment_id)
    root = Path(manifest["db_dir"]).resolve()
    _verify_sources(manifest, root)
    _verify_exact_candidates(manifest, root)

    archive = Path(archive_dir).resolve()
    archive.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in SOURCE_NAMES:
        source = root / name
        if source.exists():
            target = archive / name
            shutil.copy2(source, target)
            if _sha256(target) != manifest["sources"][name]["sha256"]:
                raise DisposalError(f"archive verification failed: {name}")
            os.chmod(target, 0o600)
    manifest_copy = archive / "reviewed-disposal-manifest.json"
    shutil.copy2(manifest_path, manifest_copy)
    os.chmod(manifest_copy, 0o600)

    candidates = manifest["candidates"]
    with sqlite3.connect(root / "usergroups.db") as conn:
        conn.execute("BEGIN IMMEDIATE")
        for row in candidates["memberships"]:
            cur = conn.execute(
                "DELETE FROM UsersLookup WHERE user_id = ? AND group_id = ?",
                (row["user_id"], row["group_id"]),
            )
            if cur.rowcount != 1:
                raise DisposalError("reviewed membership row no longer matches")
    with sqlite3.connect(root / "perms.db") as conn:
        conn.execute("BEGIN IMMEDIATE")
        for row in candidates["roles"]:
            table, id_column = row["table"], row["id_column"]
            if (table, id_column) not in {
                ("Users", "UserID"),
                ("PowerUsers", "UserID"),
                ("Admins", "AdminID"),
            }:
                raise DisposalError("invalid reviewed role target")
            cur = conn.execute(
                f"DELETE FROM {table} WHERE {id_column} = ? AND Username = ?",
                (row["row_id"], row["username"]),
            )
            if cur.rowcount != 1:
                raise DisposalError("reviewed role row no longer matches")
    with sqlite3.connect(root / "reservations.db") as conn:
        conn.execute("BEGIN IMMEDIATE")
        for row in candidates["reservations"]:
            cur = conn.execute(
                "DELETE FROM Reservations WHERE res_id = ? AND username = ?",
                (row["res_id"], row["username"]),
            )
            if cur.rowcount != 1:
                raise DisposalError("reviewed reservation row no longer matches")
        for row in candidates["accounts"]:
            cur = conn.execute(
                "DELETE FROM Accounts WHERE acc_id = ? AND username = ? "
                "AND email = ? AND auth_type = 'remoterf_global'",
                (row["acc_id"], row["username"], row["email"]),
            )
            if cur.rowcount != 1:
                raise DisposalError("reviewed account row no longer matches")

    legacy = root / "global.db"
    if legacy.exists():
        legacy.unlink()
    migrate_gate_c(root)
    subjects = initialize_native_subjects(root / "reservations.db", deployment_id)
    check_gate_c_ready(root)
    return {
        "accounts_removed": len(candidates["accounts"]),
        "reservations_removed": len(candidates["reservations"]),
        "memberships_removed": len(candidates["memberships"]),
        "roles_removed": len(candidates["roles"]),
        "native_subjects": len(subjects),
        "archive_dir": str(archive),
    }
