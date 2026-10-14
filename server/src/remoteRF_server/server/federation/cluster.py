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

"""`cluster create|invite|join|accept`: a Gate D contract without the paperwork.

The invite code carries a secret. Each side proves it holds the secret with
an HMAC over its own identity, relayed through Global, and the peer verifies
that tag locally before pinning the key -- so Global (which only stores the
secret's hash) can carry identities but never substitute one. From there the
agent walks the ordinary contract lifecycle (propose, accept, activate) over
the broker's evidence directory. Nothing here bypasses the local trust store
or the contract state machine; it only drives them.

One cluster swaps the code for an open door: `global`, owned by RemoteRF
Global's account home. Every lab on Global walks in on its own, under the
standing contract it already holds with the home (`global_home`), and every
account on a lab that is in can use what the labs share into it -- the groups
each marks public. There is no secret to check, so the labs pin each other's
key on Global's word -- an admin approved each lab by hand, and that approval
is the trust it runs on. What bounds a lab nobody chose is the per-lab cap.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import string
import threading
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4

from remoterf_federation_core import ContractError, FederationError, OwnerSignedFailure, TransportFailure, canonical_json

from .. import global_onboarding as g
from .contracts import ContractStore
from .enrollment import UNENROLL_CODE
from .migrations import migrate_gate_f_usergroups_schema
from .trust import TrustedKeyStore

CAPABILITIES = ["DEVICE_CONTROL", "DEVICE_READ", "DEVICE_RESERVE", "FEDERATED_ENROLL", "PERMISSIONS_READ"]
CONTRACT_DAYS = 365
CODE_PREFIX = "cluster."          # a student code minted here, redeemed here
CLUSTER_CODE = "cluster"          # the `code_name` a cluster enrolment carries to a partner
CODE_DAYS = 7
GLOBAL = "global"                 # the one public cluster, owned by Global's account home
PUBLIC_LAB_CAP = 30               # reservations one lab may hold here at a time, as a public cluster starts out
# ponytail: the broker's roster holds 64 labs, so a cluster does too. A public
# cluster that outgrows it needs a paged roster, or members that contract with
# the owner alone instead of meshing with each other.
MAX_MEMBERS = 64
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_STATE_FILE = "clusters.json"


class ClusterError(RuntimeError):
    pass


# -----------------------------
# Local state
# -----------------------------
# ponytail: a JSON file next to the identity; move into usergroups.db if
# clusters ever outgrow a handful per deployment.

def _state_path() -> Path:
    return g.identity_dir() / _STATE_FILE


def load() -> dict:
    try:
        clusters = json.loads(_state_path().read_text())
    except FileNotFoundError:
        return {}
    for cluster in clusters.values():
        _upgrade(cluster)
    return clusters


def _upgrade(cluster: dict) -> None:
    """First shape held one partner per owner cluster; now it holds a star."""
    if cluster.get("role") != "owner" or "members" in cluster:
        return
    members, invites = {}, {}
    if cluster.get("peer"):
        members[cluster["peer"]] = {
            "display_name": None, "contract_id": cluster.get("contract_id"),
            "state": cluster.get("state"), "published": cluster.get("published", []),
            "joined_at": cluster.get("created_at"),
        }
        if cluster.get("joiner"):
            members[cluster["peer"]]["joiner"] = cluster["joiner"]
    elif cluster.get("joiner"):
        joiner = cluster["joiner"]
        members[joiner["deployment_id"]] = {
            "display_name": None, "contract_id": None, "state": "pending",
            "published": [], "joined_at": cluster.get("created_at"), "joiner": joiner,
        }
    elif cluster.get("secret") and cluster.get("invite_id"):
        invites[cluster["invite_id"]] = {"secret": cluster["secret"], "auto": cluster.get("auto", True),
                                         "created_at": cluster.get("created_at")}
    for key in ("peer", "contract_id", "state", "published", "joiner", "secret", "invite_id", "auto"):
        cluster.pop(key, None)
    cluster["members"], cluster["invites"] = members, invites


def save(clusters: dict) -> None:
    path = _state_path()
    pending = path.with_name(path.name + ".tmp")
    pending.write_text(json.dumps(clusters, indent=2, sort_keys=True) + "\n")
    os.chmod(pending, 0o600)
    pending.replace(path)


def _find(clusters: dict, name: str) -> dict:
    if name not in clusters:
        raise ClusterError(f"no cluster named {name}")
    return clusters[name]


def _parties(cluster: dict) -> list[tuple[str, dict]]:
    """Every lab we hold a contract with in this cluster: (deployment_id, party)."""
    if cluster["role"] == "owner":
        return list(cluster["members"].items())
    return [(cluster["peer"], cluster)] + list(cluster.get("peers", {}).items())


def contract_cluster(contract_id: str) -> tuple[str, dict] | None:
    for name, cluster in load().items():
        if any(party.get("contract_id") == contract_id for _, party in _parties(cluster)):
            return name, cluster
    return None


def peer_name(deployment_id: str) -> str:
    """A partner deployment's name for the console; its id only when nothing here names it."""
    for cluster in load().values():
        for peer, party in _parties(cluster):
            if peer == deployment_id and (party.get("display_name") or party.get("peer_name")):
                return party.get("display_name") or party["peer_name"]
    from . import global_home

    if (global_home.load().get("identity") or {}).get("deployment_id") == deployment_id:
        return global_home.LABEL
    from .peers import PeerStore

    try:
        # Outlives the cluster: a kicked or removed partner is still named here.
        known = PeerStore(_db_path()).get(deployment_id)
    except (sqlite3.Error, OSError, ValueError):
        known = None
    return (known or {}).get("display_name") or deployment_id


# -----------------------------
# Identity and stores
# -----------------------------

def _identity() -> dict:
    """This deployment's public identity, stable across invites so peers can re-pin."""
    from cryptography.hazmat.primitives import serialization

    key, kid, deployment_id = g._signing_material()
    if not deployment_id:
        raise ClusterError("this server is not active on RemoteRF Global")
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    # Advertise the validity window this key is already pinned with locally
    # (a Gate D import may have set one), so peers pin identical material.
    valid_from, valid_until = 0, None
    try:
        row = _trust().get(deployment_id, kid)
        valid_from, valid_until = int(row["valid_from"]), row["valid_until"]
    except (ContractError, OSError):
        pass
    return {
        "deployment_id": deployment_id,
        "kid": kid,
        "public_key_b64": base64.b64encode(raw).decode("ascii"),
        "public_key_sha256": hashlib.sha256(raw).hexdigest(),
        "valid_from": valid_from,
        "valid_until": valid_until,
    }


def _db_path() -> Path:
    from ...common.utils.db_location import get_db_dir

    return get_db_dir() / "usergroups.db"


def _trust() -> TrustedKeyStore:
    return TrustedKeyStore(_db_path())


def _contracts() -> ContractStore:
    key, kid, deployment_id = g._signing_material()
    return ContractStore(_db_path(), local_deployment_id=deployment_id, private_key=key, signing_kid=kid)


def _pin(material: dict, *, source: str) -> None:
    try:
        _trust().import_key(
            material,
            approved_by="cluster",
            approval_source=source,
            confirm_deployment_id=material["deployment_id"],
            confirm_kid=material["kid"],
            confirm_fingerprint=material["public_key_sha256"],
        )
    except ContractError as exc:
        if exc.code != "duplicate_trusted_key":
            raise


def _pin_self() -> dict:
    # The contract store checks both participants' pins, our own included.
    me = _identity()
    _pin(me, source="identity_file")
    return me


def _identity_of(deployment_id: str) -> Optional[dict]:
    """A pinned lab's identity, as it would advertise it."""
    rows = [row for row in _trust().list(deployment_id) if row["state"] == "active"]
    if not rows:
        return None
    row = rows[-1]
    return {key: row[key] for key in ("deployment_id", "kid", "public_key_b64", "public_key_sha256")} | {
        "valid_from": int(row["valid_from"]), "valid_until": row["valid_until"]}


def _usergroups() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), timeout=10.0)
    migrate_gate_f_usergroups_schema(conn)
    return conn


# -----------------------------
# Invite codes
# -----------------------------

def _tag(secret: bytes, invite_id: str, identity: dict) -> str:
    return hmac.new(secret, f"{invite_id}\n".encode() + canonical_json(identity).encode(), "sha256").hexdigest()


def encode_code(invite_id: str, secret: bytes) -> str:
    raw = base64.b32encode(bytes.fromhex(invite_id) + secret).decode("ascii").rstrip("=")
    return "-".join(raw[i:i + 5] for i in range(0, len(raw), 5))


def decode_code(code: str) -> tuple[str, bytes]:
    compact = re.sub(r"[\s-]", "", code or "").upper()
    try:
        raw = base64.b32decode(compact + "=" * (-len(compact) % 8))
    except Exception:  # noqa: BLE001
        raise ClusterError("that is not a cluster invite code") from None
    if len(raw) != 25:
        raise ClusterError("that is not a cluster invite code")
    return raw[:5].hex(), raw[5:]


# -----------------------------
# Commands
# -----------------------------

def create(name: str) -> dict:
    if not _NAME.match(name or ""):
        raise ClusterError("cluster names are short lowercase slugs, e.g. ucla-shared")
    clusters = load()
    if name in clusters:
        raise ClusterError(f"cluster {name} already exists")
    clusters[name] = {"role": "owner", "created_at": int(time.time()), "members": {}, "invites": {}}
    save(clusters)
    return clusters[name]


def invite(name: str, *, auto: bool = True) -> str:
    """One code admits one lab. The code is the approval: whoever redeems it is
    pinned and contracted without a further step here (`auto=False` keeps a
    manual `accept`). Several codes may be open at once."""
    clusters = load()
    cluster = _find(clusters, name)
    if cluster["role"] != "owner":
        raise ClusterError(f"{name} is owned by another deployment; only the owner invites")
    me = _pin_self()
    invite_id, secret = secrets.token_hex(5), secrets.token_bytes(20)
    g.call("POST", "/v2/broker/invites", {
        "protocol_version": "2",
        "invite_id": invite_id,
        "cluster_name": name,
        "secret_sha256": hashlib.sha256(secret).hexdigest(),
        "identity": me,
        "tag": _tag(secret, invite_id, me),
    })
    cluster["invites"][invite_id] = {"secret": secret.hex(), "auto": auto, "created_at": int(time.time())}
    save(clusters)
    return encode_code(invite_id, secret)


def join(code: str) -> str:
    invite_id, secret = decode_code(code)
    me = _pin_self()
    result = g.call("POST", "/v2/broker/invites/join", {
        "protocol_version": "2",
        "invite_id": invite_id,
        "secret_sha256": hashlib.sha256(secret).hexdigest(),
        "identity": me,
        "tag": _tag(secret, invite_id, me),
    })
    view = result["invite"]
    owner = view["owner"]
    if not hmac.compare_digest(owner["tag"], _tag(secret, invite_id, owner["identity"])):
        raise ClusterError("the owner's identity did not match the invite code; not joining")
    _pin(owner["identity"], source="cluster_invite")
    name = view["cluster_name"]
    clusters = load()
    if name in clusters and clusters[name]["role"] == "owner":
        raise ClusterError(f"{name} is your own cluster")
    clusters[name] = {
        "role": "member",
        "state": "joined",
        "peer": owner["identity"]["deployment_id"],
        "peer_name": owner.get("display_name"),
        "invite_id": invite_id,
        "created_at": int(time.time()),
    }
    save(clusters)
    return name


def _propose(cluster: dict, member: dict, peer: str) -> None:
    """Owner: pin the joiner and propose its bilateral contract."""
    joiner = member.pop("joiner")
    _pin(joiner, source="cluster_invite")
    _contract_with(member, joiner)


def _contract_with(party: dict, other: dict) -> None:
    me = _identity()
    a, b = sorted([me, other], key=lambda item: item["deployment_id"])
    now = int(time.time())
    terms = {
        "contract_id": str(uuid4()),
        "version": 1,
        "deployment_a": a["deployment_id"],
        "deployment_b": b["deployment_id"],
        "valid_from": now - 60,
        "valid_until": now + CONTRACT_DAYS * 86400,
        "allowed_capabilities": CAPABILITIES,
        "key_a_kid": a["kid"],
        "key_a_sha256": a["public_key_sha256"],
        "key_b_kid": b["kid"],
        "key_b_sha256": b["public_key_sha256"],
        "supersedes_version": None,
    }
    _contracts().propose(terms, actor_admin_ref="cluster")
    party.update(state="proposed", contract_id=terms["contract_id"])
    _publish(party)


def accept(name: str, peer: str | None = None) -> dict:
    """Owner, manual invites only: approve a join that is waiting."""
    clusters = load()
    cluster = _find(clusters, name)
    pending = {pid: m for pid, m in cluster.get("members", {}).items() if m.get("state") == "pending"}
    if not pending:
        raise ClusterError(f"{name} has no join waiting for approval")
    if peer is None and len(pending) > 1:
        raise ClusterError(f"{name} has several joins waiting; accept one with `cluster accept {name} <deployment>`: "
                           + ", ".join(sorted(m.get("display_name") or pid for pid, m in pending.items())))
    peer = peer or next(iter(pending))
    if peer not in pending:
        try:
            peer = _member({"members": pending}, peer)
        except ClusterError:
            raise ClusterError(f"{peer} is not waiting to join {name}") from None
    _propose(cluster, pending[peer], peer)
    save(clusters)
    return cluster


def _revoke(contract_id: str | None) -> None:
    if not contract_id:
        return
    try:
        _contracts().revoke(contract_id, 1, actor_admin_ref="cluster")
    except ContractError as exc:
        if exc.code not in ("contract_revoked", "contract_terminal", "invalid_transition"):
            raise


def remove(name: str) -> str:
    """Leave (member) or disband (owner): revoke every contract -- a terminal,
    signed event the other side imports on its next sync -- and forget the
    cluster locally."""
    clusters = load()
    cluster = _find(clusters, name)
    if name == GLOBAL:
        # Its contract is the standing one with Global; stop sharing instead.
        raise ClusterError(f"every deployment is in {GLOBAL}; `groups public <group> off` stops sharing a group")
    outcome = "removed"
    for _, party in _parties(cluster):
        _revoke(party.get("contract_id"))
        try:
            _publish(party)
        except g.GlobalError:
            outcome = "removed locally; could not reach Global to tell the other deployment"
    _forget_accounts(name, cluster)
    del clusters[name]
    save(clusters)
    return outcome


# -----------------------------
# Public clusters, and the two things that bound them
# -----------------------------

def _public_note(name: str, state: str, owner: str | None = None) -> None:
    me = _pin_self()
    g.call("POST", "/v2/broker/clusters/roster", {"protocol_version": "2", "public": {
        "cluster_name": name, "owner": owner or me["deployment_id"], "identity": me, "state": state}})


def join_public(pool: dict, party: dict) -> str:
    """Walk into Global's cluster under the standing contract with its home
    (`party`, from `global_home`); the home's key is pinned on Global's word."""
    from . import global_home

    clusters = load()
    if GLOBAL in clusters:
        raise ClusterError(f"{GLOBAL} is already a cluster here")
    owner = pool["owner"]
    peer = owner["identity"]["deployment_id"]
    _pin(owner["identity"], source="cluster_invite")
    _public_note(GLOBAL, "joined", owner=peer)
    clusters[GLOBAL] = {"role": "member", "state": "active", "public": True, "lab_cap": PUBLIC_LAB_CAP,
                        "peer": peer, "peer_name": owner.get("display_name"), "created_at": int(time.time()),
                        "contract_id": party["contract_id"], "published": list(party.get("published", [])),
                        "groups": []}
    state = global_home.load()
    clusters[GLOBAL]["groups"] = state.pop("public_groups", [])
    save(clusters)
    global_home.save(state)
    return GLOBAL


def _member(cluster: dict, lab: str) -> str:
    """A member deployment by display name (what `cluster list` shows), deployment id or id prefix."""
    lab = (lab or "").strip().rstrip("…")
    hits = [peer for peer, member in cluster["members"].items()
            if peer == lab or (len(lab) >= 8 and peer.startswith(lab))
            or (member.get("display_name") or "").lower() == lab.lower()]
    if len(hits) > 1:
        raise ClusterError(f"several deployments are named {lab}; use an id: " + ", ".join(sorted(hits)))
    if not hits:
        raise ClusterError(f"{lab or 'that'} is not a deployment in this cluster; `cluster list` shows them")
    return hits[0]


def kick(name: str, lab: str) -> str:
    """Owner: put one lab out and keep the rest. Its contract is revoked, its
    visitors lose the cluster's groups and the reservations they hold here,
    and the public door stays shut to it -- a fresh invite code is the way
    back in. Returns the lab's name."""
    clusters = load()
    cluster = _find(clusters, name)
    if cluster["role"] != "owner":
        raise ClusterError(f"{name} is owned by another deployment; only the owner puts a deployment out")
    peer = _member(cluster, lab)
    member = cluster["members"].pop(peer)
    _revoke(member.get("contract_id"))
    try:
        _publish(member)
    except g.GlobalError:
        pass  # revoked here regardless; that lab finds out when its next grant is refused
    if peer not in cluster.setdefault("banned", []):
        cluster["banned"].append(peer)
    _forget_lab(name, peer, member.get("contract_id"))
    save(clusters)
    return member.get("display_name") or peer


def _forget_lab(name: str, peer: str, contract_id: str | None) -> None:
    """Take one lab's visitors out of the cluster and cancel what they hold
    here under its contract."""
    with _usergroups() as conn:
        accounts = [row[0] for row in conn.execute(
            "SELECT a.local_account_id FROM ClusterAccounts a "
            "JOIN FederatedPrincipals p ON p.local_account_id=a.local_account_id "
            "WHERE a.cluster_name=? AND a.kind='proxy' AND p.issuer_deployment_id=?", (name, peer)).fetchall()]
        for account in accounts:
            _take_back(conn, name, account=account)
            conn.execute("DELETE FROM ClusterAccounts WHERE cluster_name=? AND local_account_id=?", (name, account))
    path = _db_path().with_name("reservations.db")
    if not contract_id or not path.exists():
        return
    with closing(sqlite3.connect(path, timeout=10.0)) as conn, conn:
        try:
            conn.execute("DELETE FROM Reservations WHERE res_id IN "
                         "(SELECT res_id FROM FederatedReservations WHERE contract_id=?)", (contract_id,))
            conn.execute("DELETE FROM FederatedReservations WHERE contract_id=?", (contract_id,))
        except sqlite3.OperationalError:
            pass  # no federated reservations table: nothing was ever reserved from outside


def set_cap(name: str, cap: int) -> None:
    """How many reservations any one other lab in the cluster may hold on this
    server's devices at a time; 0 lifts the cap."""
    clusters = load()
    cluster = _find(clusters, name)
    if cap < 0:
        raise ClusterError("the cap is a number of reservations: 0 (no cap) or more")
    cluster["lab_cap"] = int(cap)
    save(clusters)


def lab_cap(deployment_id: str) -> int | None:
    """Reservations one partner lab may hold here at a time: the most generous
    cap among the clusters shared with it. None when any of those has no cap,
    or the lab is in no cluster (a contract made by hand is not capped)."""
    caps = [cluster.get("lab_cap") or 0 for cluster in load().values()
            if deployment_id in dict(_parties(cluster))]
    return max(caps) if caps and all(caps) else None


def list_clusters() -> list[dict]:
    """Owner rows carry `members` and `open_invites`; member rows carry `peer`."""
    store = None
    out = []
    for name, cluster in sorted(load().items()):
        item = {"name": name, "role": cluster["role"], "created_at": cluster.get("created_at"),
                "public": cluster.get("public"), "lab_cap": cluster.get("lab_cap") or 0,
                "kept_out": len(cluster.get("banned", []))}
        if cluster["role"] == "owner":
            members = []
            for peer, member in sorted(cluster["members"].items()):
                state = member.get("state")
                if member.get("contract_id"):
                    try:
                        store = store or _contracts()
                        state = store.show(member["contract_id"], 1)["state"]
                    except ContractError:
                        pass
                members.append({"deployment_id": peer, "display_name": member.get("display_name"),
                                "state": state, "joined_at": member.get("joined_at"),
                                "sharing": member.get("sharing")})
            item.update(members=members, open_invites=len(cluster["invites"]))
        else:
            state = cluster.get("state")
            if cluster.get("contract_id"):
                try:
                    store = store or _contracts()
                    state = store.show(cluster["contract_id"], 1)["state"]
                except ContractError:
                    pass
            peers = [{"deployment_id": peer, "display_name": party.get("display_name"), "state": party.get("state"),
                      "sharing": party.get("sharing")}
                     for peer, party in sorted(cluster.get("peers", {}).items())]
            item.update(peer=cluster["peer"], peer_name=cluster.get("peer_name"), state=state, peers=peers,
                        peer_sharing=cluster.get("sharing"))
        item.update(groups=groups(name), **_account_counts(name))
        out.append(item)
    return out


# -----------------------------
# Groups and students: what a cluster actually shares
# -----------------------------
# Attaching is local -- a partner never sees group names, only the devices a
# proxy in those groups may use. A student redeems one cluster code at home
# and is enrolled at every lab in the cluster; each lab puts the proxy into
# whatever it has attached.

def _group(conn, ref: str) -> tuple[int, str]:
    row = conn.execute(
        "SELECT group_id,group_name FROM UserGroups WHERE group_name=? OR CAST(group_id AS TEXT)=?",
        (ref, ref),
    ).fetchone()
    if row is None:
        raise ClusterError(f"no user group named {ref}")
    return int(row[0]), row[1]


def groups(name: str) -> list[dict]:
    cluster = _find(load(), name)
    out = []
    with _usergroups() as conn:
        for group_id in cluster.get("groups", []):
            row = conn.execute(
                "SELECT group_name,devices_whitelist,max_reservation_time_sec,max_reservations,lifetime_sec,max_horizon_sec "
                "FROM UserGroups WHERE group_id=?", (group_id,)).fetchone()
            if row is not None:
                try:
                    devices = {int(d) for d in json.loads(row[1] or "[]")}
                except (ValueError, TypeError):
                    devices = set()
                out.append({"group_id": group_id, "group_name": row[0], "devices": sorted(devices),
                            "max_reservation_time_sec": int(row[2]), "max_reservations": int(row[3]),
                            "lifetime_sec": int(row[4]), "max_horizon_sec": int(row[5])})
    return out


def _sharing(name: str, home=None) -> dict:
    """What the other labs in the cluster get told about what we share:
    counts, plus each shared group's limits and devices (`cluster info`).
    Given `home`, each device also carries busy_until / next_start (epoch,
    0 = none), anonymous occupancy for Global's availability listing."""
    from ..device_manager import describe_devices

    shared = groups(name)
    occ = home.occupancy() if home is not None else None

    def devices(ids):
        out = describe_devices(ids)
        if occ is not None:
            for d in out:
                o = occ.get(d["id"], {})
                d["busy_until"] = o.get("until") or 0
                d["next_start"] = o.get("next") or 0
        return out

    detail = [{
        "name": g["group_name"], "max_reservation_time_sec": g["max_reservation_time_sec"],
        "max_reservations": g["max_reservations"], "lifetime_sec": g["lifetime_sec"],
        "max_horizon_sec": g["max_horizon_sec"], "devices": devices(g["devices"]),
    } for g in shared]
    return {"groups": len(shared), "devices": len({d for g in shared for d in g["devices"]}), "detail": detail}


def _account_counts(name: str) -> dict:
    with _usergroups() as conn:
        rows = dict(conn.execute(
            "SELECT kind,COUNT(*) FROM ClusterAccounts WHERE cluster_name=? GROUP BY kind", (name,)).fetchall())
    return {"students": rows.get("local", 0), "visitors": rows.get("proxy", 0)}


def _queueing(clusters: dict, name: str) -> bool:
    """On Global but not yet walked into `global` (that takes an agent tick
    or two after the lab goes active): public groups wait for join_public."""
    return name == GLOBAL and GLOBAL not in clusters and g.participating()


def _queue_public(ref: str, on: bool) -> str:
    from . import global_home

    with _usergroups() as conn:
        group_id, group_name = _group(conn, ref)
    state = global_home.load()
    queued = state.setdefault("public_groups", [])
    if on == (group_id in queued):
        raise ClusterError(f"{group_name} is {'already' if on else 'not'} attached to {GLOBAL}")
    queued.append(group_id) if on else queued.remove(group_id)
    global_home.save(state)
    return group_name


def attach_group(name: str, ref: str) -> str:
    clusters = load()
    if _queueing(clusters, name):
        return _queue_public(ref, True)
    cluster = _find(clusters, name)
    with _usergroups() as conn:
        group_id, group_name = _group(conn, ref)
        if group_id in cluster.get("groups", []):
            raise ClusterError(f"{group_name} is already attached to {name}")
        cluster.setdefault("groups", []).append(group_id)
        for (account,) in conn.execute(
                "SELECT local_account_id FROM ClusterAccounts WHERE cluster_name=?", (name,)).fetchall():
            _grant(conn, name, account, group_id)
    save(clusters)
    return group_name


def _grant(conn, name: str, account: int, group_id: int) -> None:
    """Add a membership on the cluster's behalf -- remembered only if it was
    the cluster, not a group code, that granted it."""
    added = conn.execute("INSERT OR IGNORE INTO UsersLookup(user_id,group_id) VALUES (?,?)",
                         (int(account), int(group_id))).rowcount
    if added:
        conn.execute("INSERT OR IGNORE INTO ClusterMemberships(cluster_name,local_account_id,group_id) "
                     "VALUES (?,?,?)", (name, int(account), int(group_id)))


def _take_back(conn, name: str, group_id: int | None = None, account: int | None = None) -> None:
    """Remove exactly the memberships this cluster granted (one group, one account, or all)."""
    where, args = "cluster_name=?", (name,)
    if group_id is not None:
        where, args = where + " AND group_id=?", args + (int(group_id),)
    if account is not None:
        where, args = where + " AND local_account_id=?", args + (int(account),)
    conn.execute(
        f"DELETE FROM UsersLookup WHERE (user_id,group_id) IN "
        f"(SELECT local_account_id,group_id FROM ClusterMemberships WHERE {where})", args)
    conn.execute(f"DELETE FROM ClusterMemberships WHERE {where}", args)


def detach_group(name: str, ref: str) -> str:
    clusters = load()
    if _queueing(clusters, name):
        return _queue_public(ref, False)
    cluster = _find(clusters, name)
    with _usergroups() as conn:
        group_id, group_name = _group(conn, ref)
        if group_id not in cluster.get("groups", []):
            raise ClusterError(f"{group_name} is not attached to {name}")
        cluster["groups"].remove(group_id)
        _take_back(conn, name, group_id)
    save(clusters)
    return group_name


def shared_with(group_id: int) -> list[str]:
    """The clusters a group is shared into."""
    from . import global_home

    names = {name for name, cluster in load().items() if int(group_id) in cluster.get("groups", [])}
    if int(group_id) in global_home.load().get("public_groups", []):
        names.add(GLOBAL)
    return sorted(names)


def share_group(ref: str, names: list[str]) -> tuple[list[str], list[str]]:
    """Share a group into exactly these clusters; returns (added, removed)."""
    clusters = load()
    for name in names:
        if not _queueing(clusters, name):
            _find(clusters, name)
    with _usergroups() as conn:
        group_id, _ = _group(conn, ref)
    current = set(shared_with(group_id))
    for name in set(names) - current:
        attach_group(name, str(group_id))
    for name in current - set(names):
        detach_group(name, str(group_id))
    return sorted(set(names) - current), sorted(current - set(names))


def _forget_accounts(name: str, cluster: dict) -> None:
    with _usergroups() as conn:
        _take_back(conn, name)
        conn.execute("DELETE FROM ClusterAccounts WHERE cluster_name=?", (name,))


def join_account(conn, name: str, cluster: dict, local_account_id: int, *, kind: str) -> None:
    """Put an account (a local student or a partner's proxy) into the cluster
    and every group attached to it. Runs inside the caller's transaction."""
    conn.execute(
        "INSERT OR IGNORE INTO ClusterAccounts(cluster_name,local_account_id,kind,joined_at) VALUES (?,?,?,?)",
        (name, int(local_account_id), kind, int(time.time())),
    )
    for group_id in cluster.get("groups", []):
        _grant(conn, name, local_account_id, group_id)


def admit_account(home, local_account_id: int) -> None:
    """A new native account walks into every public cluster now and is
    enrolled at the labs sharing devices there, instead of on the next tick."""
    clusters = load()
    with _usergroups() as conn:
        for name, cluster in clusters.items():
            if cluster.get("public"):
                join_account(conn, name, cluster, int(local_account_id), kind="local")
    # Off the registration call: enrolling talks to the other labs.
    threading.Thread(target=enroll_students, args=(home,), kwargs={"only_account": int(local_account_id)},
                     daemon=True, name="remoterf-admit").start()


def forget_account(local_account_id: int | None = None) -> None:
    """A deleted account (native or proxy) leaves every cluster, grants and
    all, so the tick stops trying to enrol a ghost. None: every account (a purge)."""
    where, args = ("local_account_id=?", (int(local_account_id),)) if local_account_id is not None else ("1", ())
    with _usergroups() as conn:
        rows = conn.execute(f"SELECT DISTINCT cluster_name, local_account_id FROM ClusterAccounts WHERE {where}", args).fetchall()
        for name, account in rows:
            _take_back(conn, name, account=int(account))
        conn.execute(f"DELETE FROM ClusterAccounts WHERE {where}", args)


def _admit_everyone(clusters: dict) -> None:
    """A public cluster needs no code: every native account here is in it.
    An account that no longer exists is in none."""
    path = _db_path().with_name("reservations.db")
    if not path.exists():
        return
    with closing(sqlite3.connect(path, timeout=10.0)) as conn:
        try:
            rows = conn.execute("SELECT acc_id, auth_type FROM Accounts").fetchall()
        except sqlite3.OperationalError:
            return  # no accounts table yet
    existing = {int(acc) for acc, _ in rows}
    accounts = [int(acc) for acc, kind in rows if kind == "local_password"]
    with _usergroups() as conn:
        ghosts = [int(row[0]) for row in conn.execute(
            "SELECT DISTINCT local_account_id FROM ClusterAccounts WHERE kind='local'") if int(row[0]) not in existing]
    for ghost in ghosts:
        forget_account(ghost)
    public = [(name, cluster) for name, cluster in clusters.items() if cluster.get("public")]
    if not public:
        return
    with _usergroups() as conn:
        for name, cluster in public:
            have = {row[0] for row in conn.execute(
                "SELECT local_account_id FROM ClusterAccounts WHERE cluster_name=?", (name,)).fetchall()}
            for account in accounts:
                if account not in have:
                    join_account(conn, name, cluster, account, kind="local")


def mint_codes(name: str, *, count: int = 1, uses: int = 1, duration_sec: int = CODE_DAYS * 86400) -> list[str]:
    """Same shape as a group code (uses, duration; 0 = never expires), bound
    to the cluster instead of a group."""
    _find(load(), name)
    if not 1 <= count <= 200 or uses < 1 or duration_sec < 0:
        raise ClusterError("count must be 1-200, uses at least 1, duration 0 or more seconds")
    # Same alphabet as group codes; a bigger batch gets longer codes so the
    # guess space per code stays about the same.
    alphabet = string.ascii_uppercase + string.digits
    length = 10 + max(0, (count - 1).bit_length() - 3)  # 10 chars up to 8 codes, 11 to 16, ...
    codes = set()
    while len(codes) < count:
        codes.add(CODE_PREFIX + "".join(secrets.choice(alphabet) for _ in range(length)))
    codes = sorted(codes)
    with _usergroups() as conn:
        conn.executemany(
            "INSERT INTO EnrollmentCodes(code_name,group_id,uses,duration_sec,created_at,cluster_name) "
            "VALUES (?,-1,?,?,?,?)",
            [(code, uses, duration_sec, datetime.now().isoformat(sep=" "), name) for code in codes],
        )
    return codes


def list_codes(name: str | None = None) -> list[dict]:
    with _usergroups() as conn:
        rows = conn.execute(
            "SELECT code_name,cluster_name,uses,duration_sec FROM EnrollmentCodes WHERE cluster_name IS NOT NULL"
            + (" AND cluster_name=?" if name else "") + " ORDER BY cluster_name,code_id",
            (name,) if name else (),
        ).fetchall()
    return [{"code_name": r[0], "cluster_name": r[1], "uses": int(r[2]), "duration_sec": int(r[3])} for r in rows]


def redeem_code(local_account_id: int, code_name: str) -> Optional[str]:
    """A student types a cluster code at home: returns the cluster joined, or None."""
    if not code_name.startswith(CODE_PREFIX):
        return None
    clusters = load()
    with _usergroups() as conn:
        row = conn.execute(
            "SELECT code_id,cluster_name,uses,duration_sec,created_at FROM EnrollmentCodes "
            "WHERE code_name=? AND cluster_name IS NOT NULL",
            (code_name,),
        ).fetchone()
        if row is None or int(row[2]) <= 0 or row[1] not in clusters:
            return None
        if int(row[3]) > 0:
            try:
                created = datetime.fromisoformat(str(row[4]))
            except ValueError:
                return None
            if (datetime.now() - created).total_seconds() >= int(row[3]):
                return None
        conn.execute("UPDATE EnrollmentCodes SET uses=uses-1 WHERE code_id=?", (row[0],))
        conn.execute("DELETE FROM EnrollmentCodes WHERE code_id=? AND uses<=0", (row[0],))
        join_account(conn, row[1], clusters[row[1]], local_account_id, kind="local")
    return row[1]


_ENROL_RETRY_FIRST, _ENROL_RETRY_CAP = 30.0, 600.0
_unreachable: dict[str, tuple[float, float]] = {}  # peer -> (retry_at, delay), monotonic
_revoke_retry: dict[str, tuple[float, float]] = {}  # same, for unenrols
REVOCATION_TTL = 180 * 86400  # an unenrol for a partner we hold no contract with waits this long


def _back_off(table: dict, peer: str) -> None:
    delay = min(table.get(peer, (0.0, _ENROL_RETRY_FIRST / 2))[1] * 2, _ENROL_RETRY_CAP)
    table[peer] = (time.monotonic() + delay, delay)


def _forget_departed(plane) -> None:
    """Drop enrolment records at partners we no longer hold a live contract
    with: that partner may prune our users as "issuer gone", and on a rejoin
    the next tick enrols everyone again (an existing proxy just stays)."""
    if getattr(plane, "path", None) is None:
        return
    try:
        with _usergroups() as conn:
            live = {deployment for row in conn.execute(
                "SELECT deployment_a, deployment_b FROM FederationContracts "
                "WHERE state='active' AND superseded_by_version IS NULL") for deployment in row}
        with closing(sqlite3.connect(plane.path, timeout=10.0)) as conn, conn:
            peers = [row[0] for row in conn.execute("SELECT DISTINCT destination_deployment_id FROM FederatedEnrollments")]
            for peer in peers:
                if peer not in live:
                    conn.execute("DELETE FROM FederatedEnrollments WHERE destination_deployment_id=?", (peer,))
    except sqlite3.OperationalError:
        pass  # no contracts or HOME device plane here yet


def enroll_students(home, notify=None, *, only_account: int | None = None) -> None:
    """HOME: enrol every local student at every active lab they are not yet
    at. Idempotent; the tick retries whatever failed."""
    notify = notify or (lambda text: None)
    enroller, plane = getattr(home, "federation_enroller", None), getattr(home, "federation_devices", None)
    if enroller is None or plane is None:
        return
    _forget_departed(plane)
    clusters = load()
    with _usergroups() as conn:
        rows = conn.execute(
            "SELECT cluster_name,local_account_id FROM ClusterAccounts WHERE kind='local'"
            + (" AND local_account_id=?" if only_account is not None else ""),
            (only_account,) if only_account is not None else (),
        ).fetchall()
    for name, account in rows:
        cluster = clusters.get(name)
        if cluster is None:
            continue
        enrolled = plane.enrolled(account)
        for peer, party in _parties(cluster):
            if party.get("state") != "active" or not party.get("contract_id") or peer in enrolled:
                continue
            if cluster.get("public") and not (party.get("sharing") or {}).get("devices"):
                continue  # a lab nobody chose gets our accounts only once it shares a device
            if _unreachable.get(peer, (0.0, 0.0))[0] > time.monotonic():
                continue  # unreachable a moment ago: back off rather than redial every tick
            subject = _subject_of(plane, account)
            try:
                enroller.outbound.execute(
                    local_account_id=account, destination_deployment_id=peer,
                    contract_id=party["contract_id"], contract_version=1,
                    action="federated_enroll", code_name=CLUSTER_CODE,
                )
            except (FederationError, OSError) as exc:
                if isinstance(exc, TransportFailure) and exc.code == "route_unavailable":
                    _back_off(_unreachable, peer)
                notify(f"[cluster] {name}: could not enrol account {account} at "
                       f"{party.get('display_name') or peer}: {getattr(exc, 'code', exc)}")
                continue
            _unreachable.pop(peer, None)
            plane.record_enrollment(local_account_id=account, destination_deployment_id=peer)
            if subject and _subject_of(plane, account) is None:
                # Deleted while the enrolment was in flight: its delete queued
                # nothing for this peer, so queue the unenrol here.
                with closing(sqlite3.connect(plane.path, timeout=10.0)) as conn, conn:
                    conn.execute("INSERT OR IGNORE INTO FederatedRevocations VALUES (?,?,?)",
                                 (subject, peer, int(time.time())))
                    conn.execute("DELETE FROM FederatedEnrollments WHERE local_account_id=?", (account,))


def _subject_of(plane, account: int) -> str | None:
    if getattr(plane, "path", None) is None:
        return None
    with closing(sqlite3.connect(plane.path, timeout=10.0)) as conn:
        row = conn.execute("SELECT subject_id FROM LocalAccountSubjects WHERE local_account_id=?",
                           (account,)).fetchone()
    return row[0] if row else None


def deliver_revocations(home, notify=None) -> None:
    """HOME: tell each partner a deleted account was enrolled at to drop its
    proxy. A row stays until the partner answers; an older partner answers
    code_invalid (keeps its orphan). A partner we hold no contract with right
    now (left, kicked, past the candidate cap) keeps its row until it is back
    or REVOCATION_TTL runs out."""
    notify = notify or (lambda text: None)
    enroller, plane = getattr(home, "federation_enroller", None), getattr(home, "federation_devices", None)
    if enroller is None or plane is None:
        return
    path = _db_path().with_name("reservations.db")
    try:
        with closing(sqlite3.connect(path, timeout=10.0)) as conn:
            rows = conn.execute("SELECT subject_id, destination_deployment_id, queued_at FROM FederatedRevocations").fetchall()
    except sqlite3.OperationalError:
        return  # no HOME device plane here yet
    if not rows:
        return
    contracts = {}
    for candidate in plane.permissions._candidates(int(plane.clock()), "FEDERATED_ENROLL")[0]:
        contracts.setdefault(candidate["deployment_id"], candidate)
    now = time.time()
    for subject, peer, queued_at in rows:
        contract = contracts.get(peer)
        if contract is None:
            if int(queued_at) > now - REVOCATION_TTL:
                continue  # no contract right now: wait for one, the TTL lets go of a partner that is gone
        else:
            if _revoke_retry.get(peer, (0.0, 0.0))[0] > time.monotonic():
                continue  # failed a moment ago: skip this peer's rows until the backoff runs out
            try:
                enroller.outbound.execute(
                    local_account_id=None, revoked_subject_id=subject, destination_deployment_id=peer,
                    contract_id=contract["contract_id"], contract_version=contract["contract_version"],
                    action="federated_enroll", code_name=UNENROLL_CODE,
                )
            except (FederationError, OSError) as exc:
                # code_invalid (signed): a partner too old to know the code keeps its orphan.
                if not (isinstance(exc, OwnerSignedFailure) and exc.code == "code_invalid"):
                    _back_off(_revoke_retry, peer)
                    notify(f"[cluster] could not remove a deleted account at {peer_name(peer)}: {getattr(exc, 'code', exc)}")
                    continue
            _revoke_retry.pop(peer, None)
        with closing(sqlite3.connect(path, timeout=10.0)) as conn, conn:
            conn.execute("DELETE FROM FederatedRevocations WHERE subject_id=? AND destination_deployment_id=?",
                         (subject, peer))


# -----------------------------
# Agent: one pass per Global liveness tick
# -----------------------------

def _publish(party: dict) -> None:
    """Send our own signed events for this party's contract to the broker."""
    if not party.get("contract_id"):
        return
    store = _contracts()
    shown = store.show(party["contract_id"], 1, include_signed_events=True)
    done = set(party.setdefault("published", []))
    for event in shown["events"]:
        if event["actor_deployment_id"] != store.local_deployment_id or event["event_id"] in done:
            continue
        g.call("POST", "/v2/broker/contracts/events", {
            "protocol_version": "2", "terms": shown["terms"], "signed_event": event["signed_event"],
        })
        done.add(event["event_id"])
    party["published"] = sorted(done)


def _sync_contract(party: dict, peer: str, directory: list[dict]) -> str:
    """Import the peer's events for this party's contract; return the local state."""
    store = _contracts()
    if not party.get("contract_id"):
        # Member: adopt the owner's proposal that names both of us -- the
        # newest one that is not already revoked (an earlier cluster's may be).
        candidates = []
        for item in directory:
            terms = item.get("terms") or {}
            parties = {terms.get("deployment_a"), terms.get("deployment_b")}
            if parties != {peer, store.local_deployment_id} or item["version"] != 1 or not item.get("events"):
                continue
            if _import(store, terms, item["events"]) != "revoked":
                candidates.append((terms["valid_from"], item["contract_id"]))
        if not candidates:
            return party["state"]
        party["contract_id"] = max(candidates)[1]
    for item in directory:
        if item["contract_id"] == party["contract_id"] and item.get("terms"):
            _import(store, item["terms"], item["events"])
    return store.show(party["contract_id"], 1)["state"]


def _event_order(signed_event: str) -> tuple:
    """(occurred_at, actor, actor_sequence) from the unverified payload -- for
    ordering only; the store verifies every event before it counts."""
    try:
        payload = signed_event.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return (int(claims["occurred_at"]), str(claims["iss"]), int(claims["actor_sequence"]))
    except Exception:  # noqa: BLE001 - malformed: let the store reject it, last
        return (2**62, "", 0)


def _import(store: ContractStore, terms: dict, events: list) -> str:
    """Import a directory entry; a contract already revoked here (an earlier
    cluster between the same labs) is simply reported as such."""
    events = sorted(events, key=_event_order)  # the relay's order is not the actors' order
    try:
        store.import_bundle(canonical_json({"protocol_version": "2", "terms": terms, "events": events}))
    except ContractError as exc:
        if exc.code not in ("contract_revoked", "contract_terminal", "invalid_transition"):
            raise
    return store.show(terms["contract_id"], 1)["state"]


def _advance(party: dict, peer: str, directory: list[dict], *, label: str, notify, is_member: bool) -> None:
    """Move one bilateral contract one step; notify on active / revoked."""
    before = party.get("state")
    if before in ("pending", "revoked"):
        return
    state = _sync_contract(party, peer, directory)
    store = _contracts()
    if state == "proposed" and is_member:
        store.accept(party["contract_id"], 1, actor_admin_ref="cluster")
        state = store.activate(party["contract_id"], 1, actor_admin_ref="cluster")["state"]
    elif state == "accepted":
        mine = {e["actor_deployment_id"] for e in store.show(party["contract_id"], 1)["events"]
                if e["event_type"] == "activate"}
        if store.local_deployment_id not in mine:
            state = store.activate(party["contract_id"], 1, actor_admin_ref="cluster")["state"]
    _publish(party)
    if party.get("contract_id"):
        party["state"] = state
    if state == "active" and before != "active":
        notify(f"[cluster] {label} is active")
    if state == "revoked" and before != "revoked":
        notify(f"[cluster] {label} was ended by the other deployment")


def _publish_roster(name: str, cluster: dict) -> None:
    """Owner: whenever the active member set changes, sign and post it so the
    members can pin each other and mesh."""
    active = sorted(peer for peer, member in cluster["members"].items() if member.get("state") == "active")
    if active == cluster.get("roster"):
        return
    key, _, me = g._signing_material()
    members = []
    for peer in active:
        identity = _identity_of(peer)
        if identity is not None:
            members.append({"identity": identity, "display_name": cluster["members"][peer].get("display_name")})
    roster = {"cluster_name": name, "owner": me, "issued_at": int(time.time()), "members": members}
    signature = base64.b64encode(key.sign(canonical_json(roster).encode())).decode("ascii")
    g.call("POST", "/v2/broker/clusters/roster", {"protocol_version": "2", "roster": roster, "signature": signature})
    cluster["roster"] = active


def _publish_status(name: str, cluster: dict, home=None) -> None:
    """Any lab: post our counts for this cluster, and the route the other
    labs may dial us on directly, when either changes."""
    from .peers import own_route

    note = _sharing(name, home)
    route = own_route()
    if route is not None:
        note["route"] = route
    if note == cluster.get("status"):
        return
    key, _, me = g._signing_material()
    owner = me if cluster["role"] == "owner" else cluster["peer"]
    status = {"cluster_name": name, "owner": owner, "deployment_id": me, "issued_at": int(time.time()), **note}
    signature = base64.b64encode(key.sign(canonical_json(status).encode())).decode("ascii")
    g.call("POST", "/v2/broker/clusters/roster", {"protocol_version": "2", "status": status, "signature": signature})
    cluster["status"] = note


def _take_statuses(name: str, cluster: dict, statuses: list[dict]) -> None:
    """Attach each partner's verified counts to its row."""
    owner = g._signing_material()[2] if cluster["role"] == "owner" else cluster["peer"]
    parties = dict(_parties(cluster))
    for item in statuses:
        status = item.get("status") or {}
        peer = status.get("deployment_id")
        if status.get("owner") != owner or status.get("cluster_name") != name or peer not in parties:
            continue
        if _roster_signed_by(peer, status, item.get("signature", "")):
            parties[peer]["sharing"] = {"groups": status["groups"], "devices": status["devices"],
                                        "detail": status.get("detail", [])}
            if status.get("route"):
                # A member's row for its owner carries the name as peer_name.
                _pin_route(peer, parties[peer].get("display_name") or parties[peer].get("peer_name"), status["route"])


def _pin_route(peer: str, display_name: str | None, route: dict) -> None:
    """A lab's own signed route: from now on the HOME dials it directly.
    A malformed one leaves the broker path in place."""
    from .peers import PeerStore

    try:
        PeerStore(_db_path()).upsert(deployment_id=peer, display_name=display_name or peer, route=route,
                                     source="cluster")
    except (ValueError, sqlite3.Error):
        pass


def _roster_signed_by(owner: str, roster: dict, signature: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    for row in _trust().list(owner):
        if row["state"] != "active":
            continue
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(row["public_key_b64"])).verify(
                base64.b64decode(signature), canonical_json(roster).encode())
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


def _mesh(name: str, cluster: dict, rosters: list[dict], directory: list[dict], notify) -> None:
    """Member: pin the other members the owner vouches for and hold one
    contract with each. The lower deployment id proposes; the other accepts."""
    me = g._signing_material()[2]
    peers = cluster.setdefault("peers", {})
    for item in rosters:
        roster = item.get("roster") or {}
        if roster.get("owner") != cluster["peer"] or roster.get("cluster_name") != name:
            continue
        if not _roster_signed_by(cluster["peer"], roster, item.get("signature", "")):
            notify(f"[cluster] {name}: ignored a member list not signed by the owner")
            continue
        listed = {m["identity"]["deployment_id"]: m for m in roster.get("members", [])
                  if m["identity"]["deployment_id"] != me}
        for peer, member in listed.items():
            if peer in peers:
                continue
            _pin(member["identity"], source="cluster_invite")
            peers[peer] = {"display_name": member.get("display_name"), "contract_id": None,
                           "state": "joined", "published": []}
            if me < peer:
                _contract_with(peers[peer], member["identity"])
        for peer in [p for p in peers if p not in listed]:
            _revoke(peers[peer].get("contract_id"))
            try:
                _publish(peers[peer])
            except g.GlobalError:
                pass
            notify(f"[cluster] {name}: {peers[peer].get('display_name') or peer} left")
            del peers[peer]
        break
    for peer, party in peers.items():
        _advance(party, peer, directory, label=f"{name}: {party.get('display_name') or peer}",
                 notify=notify, is_member=me > peer)


def _collect_joins(name: str, cluster: dict, broker_invites: list[dict], notify) -> None:
    """Owner: turn redeemed invites into members; drop invites Global no longer holds."""
    seen = {item["invite_id"]: item for item in broker_invites}
    for invite_id, invite in list(cluster["invites"].items()):
        item = seen.get(invite_id)
        if item is None:
            del cluster["invites"][invite_id]  # expired or consumed elsewhere
            continue
        if not item.get("joiner"):
            continue
        joiner = item["joiner"]
        secret = bytes.fromhex(invite["secret"])
        if not hmac.compare_digest(joiner["tag"], _tag(secret, invite_id, joiner["identity"])):
            notify(f"[cluster] {name}: a join arrived without the invite secret; ignored")
            del cluster["invites"][invite_id]
            continue
        peer = joiner["identity"]["deployment_id"]
        if peer in cluster.get("banned", []):
            cluster["banned"].remove(peer)  # a code handed to a lab that was kicked is its way back in
        member = cluster["members"].setdefault(peer, {"published": [], "joined_at": int(time.time())})
        member.update(display_name=joiner.get("display_name"), joiner=joiner["identity"], state="pending")
        del cluster["invites"][invite_id]
        if invite.get("auto", True):
            _propose(cluster, member, peer)
        else:
            notify(f"[cluster] {member.get('display_name') or peer} wants to join {name}: run `cluster accept {name}`")


_said: set[str] = set()


def _once(key: str, text: str, notify) -> None:
    """A standing condition is worth one console line, not one per tick."""
    if key not in _said:
        _said.add(key)
        notify(text)


def _walk_in(pools: list[dict], notify) -> None:
    """Join Global's cluster once the standing contract with its home is
    active. Any other open door (an older lab's own) is ignored."""
    from . import global_home

    if GLOBAL in load():
        return
    state = global_home.load()
    home = (state.get("identity") or {}).get("deployment_id")
    party = state.get("party") or {}
    if not home or party.get("state") != "active":
        return
    for pool in pools:
        owner = (pool.get("owner") or {}).get("identity") or {}
        if pool.get("cluster_name") != GLOBAL or owner.get("deployment_id") != home:
            continue
        try:
            join_public(pool, party)
        except (ClusterError, ContractError, g.GlobalError, KeyError, TypeError) as exc:
            _once(f"join:{GLOBAL}", f"[cluster] could not join {GLOBAL}: {getattr(exc, 'code', exc)}", notify)
            return
        notify(f"[cluster] joined {GLOBAL}: every account here can reserve what the deployments on Global share. "
               "`groups public <group> on` shares one of yours.")
        return


def tick(notify=None, home=None) -> None:
    """One agent pass: move every cluster and member one step closer to active,
    then (given the HOME runtime) enrol students wherever they are missing."""
    notify = notify or (lambda text: None)
    if home is not None:
        deliver_revocations(home, notify)
    # Rosters, status notes and the public clusters: one GET for the whole pass.
    board = g.call("GET", "/v2/broker/clusters/roster")
    _walk_in(board.get("pools", []), notify)
    clusters = load()
    if not clusters:
        return
    directory = None
    broker_invites = None
    for name, cluster in clusters.items():
        if cluster["role"] == "owner":
            if cluster["invites"]:
                if broker_invites is None:
                    broker_invites = g.call("GET", "/v2/broker/invites")["invites"]
                _collect_joins(name, cluster, broker_invites, notify)
                save(clusters)
            # An empty cluster has nothing to drive, bar withdrawing a roster
            # that still names a lab that has since been kicked.
            if not cluster["members"] and not cluster.get("roster"):
                continue
            if directory is None:
                directory = g.call("GET", "/v2/broker/contracts")["contracts"]
            for peer, member in cluster["members"].items():
                _advance(member, peer, directory, label=f"{name}: {member.get('display_name') or peer}",
                         notify=notify, is_member=False)
            try:
                _publish_roster(name, cluster)
            except g.GlobalError as exc:
                notify(f"[cluster] {name}: could not publish the member list: {exc}")
        else:
            if directory is None:
                directory = g.call("GET", "/v2/broker/contracts")["contracts"]
            _advance(cluster, cluster["peer"], directory, label=name, notify=notify, is_member=True)
        if cluster["role"] != "owner":
            _mesh(name, cluster, board["rosters"], directory, notify)
        try:
            _publish_status(name, cluster, home)
        except g.GlobalError as exc:
            notify(f"[cluster] {name}: could not publish what we share: {exc}")
        _take_statuses(name, cluster, board.get("statuses", []))
        save(clusters)
    _admit_everyone(clusters)
    if home is not None:
        enroll_students(home, notify)
