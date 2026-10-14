"""A partner lab's proxy follows its account: counted apart, removed when the
HOME deletes the account, and prunable once its home is gone.

One process plays both labs (see test_home_device_plane): HOME's native
`alice` and DEST's proxy for her share reservations.db; grants are real."""

import sqlite3
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from remoterf_federation_core import FederationError

from remoteRF_server.server.federation import cluster, enrollment
from remoteRF_server.server.federation.principals import orphan_proxies, prepare_federated_account

from test_gate_e_federation import CONTRACT, DEST, HOME
from test_gate_h_devices import world  # noqa: F401 - fixture
from test_home_device_plane import NATIVE, home  # noqa: F401 - fixture

OTHER = "33333333-3333-4333-8333-333333333333"


@pytest.fixture
def lab(home, tmp_path):
    root, dest_db = home["root"], home["dest_db"]
    with patch.object(cluster, "_state_path", return_value=tmp_path / "clusters.json"), \
         patch.object(cluster, "_db_path", return_value=dest_db):
        cluster._unreachable.clear()
        cluster._revoke_retry.clear()
        res = root / "reservations.db"
        with sqlite3.connect(res) as conn:
            subject = conn.execute("SELECT subject_id FROM LocalAccountSubjects WHERE local_account_id=?",
                                   (home["account_id"],)).fetchone()[0]
            proxy = conn.execute("SELECT a.username FROM FederatedAccountBindings b JOIN Accounts a "
                                 "ON a.acc_id=b.local_account_id WHERE b.remote_subject_id=?", (subject,)).fetchone()[0]
            start = datetime.now() + timedelta(hours=1)
            conn.execute("INSERT INTO Reservations(username,device_id,start_time,end_time,salt,hash) "
                         "VALUES (?,?,?,?,'s','h')", (proxy, home["allowed"], start, start + timedelta(hours=1)))
        home["plane"].record_enrollment(local_account_id=home["account_id"], destination_deployment_id=DEST)
        runtime = SimpleNamespace(federation_enroller=SimpleNamespace(outbound=home["plane"].outbound),
                                  federation_devices=home["plane"])
        yield {**home, "res": res, "subject": subject, "proxy": proxy, "runtime": runtime}
        cluster._unreachable.clear()
        cluster._revoke_retry.clear()


def _rows(db, sql, *args):
    with sqlite3.connect(db) as conn:
        return conn.execute(sql, args).fetchall()


def _queued(lab):
    return _rows(lab["res"], "SELECT subject_id, destination_deployment_id FROM FederatedRevocations")


def _proxy_gone(lab) -> bool:
    return (not _rows(lab["res"], "SELECT 1 FROM Accounts WHERE username=?", lab["proxy"])
            and not _rows(lab["res"], "SELECT 1 FROM Reservations WHERE username=?", lab["proxy"])
            and not _rows(lab["dest_db"], "SELECT 1 FROM FederatedPrincipals WHERE remote_subject_id=?", lab["subject"]))


def test_users_list_puts_visitors_after_the_labs_own_accounts_with_a_count(lab, capsys):
    tables = []
    with patch("remoteRF_server.common.utils.panel.print_table", lambda *a, **k: tables.append(a[1])):
        lab["reservations"].print_all_accounts()
    assert [row["username"] for row in tables[0]] == [NATIVE, lab["proxy"]]
    assert "1 accounts, 1 visiting from partner labs (federated proxies)" in capsys.readouterr().out


def test_deleting_at_home_removes_the_proxy_at_the_partner_after_an_outage(lab):
    lab["reservations"].remove_user(username=NATIVE)
    assert _queued(lab) == [(lab["subject"], DEST)]

    outbound, sender = lab["plane"].outbound, lab["plane"].outbound.sender

    def offline(body, token, deadline):
        raise ConnectionError("partner offline")

    outbound.sender = offline
    notes = []
    cluster.deliver_revocations(lab["runtime"], notes.append)
    assert _queued(lab) == [(lab["subject"], DEST)] and notes  # kept for the next tick
    assert not _proxy_gone(lab)
    cluster.deliver_revocations(lab["runtime"])  # backing off: not even dialled
    assert lab["calls"] == []

    outbound.sender = sender
    cluster._revoke_retry.clear()
    cluster.deliver_revocations(lab["runtime"])
    assert lab["calls"] == ["federated_enroll"]
    assert _queued(lab) == [] and _proxy_gone(lab)
    assert not _rows(lab["dest_db"], "SELECT 1 FROM ClusterAccounts WHERE kind='proxy'")


def test_a_second_unenrol_is_a_harmless_ok(lab):
    lab["reservations"].remove_user(username=NATIVE)
    cluster.deliver_revocations(lab["runtime"])
    with sqlite3.connect(lab["res"]) as conn:  # say the HOME crashed before dropping the row
        conn.execute("INSERT INTO FederatedRevocations VALUES (?,?,1)", (lab["subject"], DEST))
    cluster.deliver_revocations(lab["runtime"])
    assert lab["calls"] == ["federated_enroll", "federated_enroll"] and _queued(lab) == []


def test_the_issuer_signs_an_unenrol_only_for_a_deleted_queued_subject(lab):
    issuer = lab["plane"].outbound.issuer
    sign = dict(destination_deployment_id=DEST, contract_id=CONTRACT, contract_version=1,
                action="federated_enroll", code_name=enrollment.UNENROLL_CODE)
    with pytest.raises(FederationError, match="native_account_required"):  # a live account
        issuer.issue(local_account_id=None, revoked_subject_id=lab["subject"], **sign)
    with pytest.raises(FederationError, match="native_account_required"):  # nor through the native path
        issuer.issue(local_account_id=lab["account_id"], **sign)
    with sqlite3.connect(lab["res"]) as conn:
        conn.execute("INSERT INTO FederatedRevocations VALUES (?,?,1)", (lab["subject"], DEST))
    with pytest.raises(FederationError, match="native_account_required"):  # queued, but still alive
        issuer.issue(local_account_id=None, revoked_subject_id=lab["subject"], **sign)
    with pytest.raises(FederationError, match="native_account_required"):  # not queued
        issuer.issue(local_account_id=None, revoked_subject_id=str(uuid.uuid4()), **sign)
    with pytest.raises(FederationError, match="native_account_required"):  # only an unenrol
        issuer.issue(local_account_id=None, revoked_subject_id=lab["subject"],
                     **{**sign, "code_name": "cluster"})


def test_a_lab_cannot_unenrol_another_labs_user(lab):
    """The partner acts on the grant's own issuer: HOME naming OTHER's subject
    finds no proxy of its own and leaves OTHER's alone."""
    theirs = str(uuid.uuid4())
    prepared = prepare_federated_account(lab["res"], issuer_deployment_id=OTHER, remote_subject_id=theirs,
                                         perms_path=lab["root"] / "perms.db", now=100)
    with sqlite3.connect(lab["dest_db"]) as conn:
        conn.execute("INSERT INTO FederatedPrincipals(id,issuer_deployment_id,remote_subject_id,local_account_id,"
                     "status,created_at,last_seen_at,display_metadata_json) VALUES (?,?,?,?,'active',100,100,'{}')",
                     (str(uuid.uuid4()), OTHER, theirs, prepared.local_account_id))
    with sqlite3.connect(lab["res"]) as conn:
        conn.execute("INSERT INTO FederatedRevocations VALUES (?,?,1)", (theirs, DEST))
    cluster.deliver_revocations(lab["runtime"])
    assert lab["calls"] == ["federated_enroll"] and _queued(lab) == []
    assert _rows(lab["res"], "SELECT 1 FROM Accounts WHERE username=?", prepared.username)
    assert _rows(lab["dest_db"], "SELECT 1 FROM FederatedPrincipals WHERE issuer_deployment_id=?", OTHER)


def test_an_older_partner_answers_code_invalid_and_keeps_its_orphan(lab):
    lab["reservations"].remove_user(username=NATIVE)
    with patch.object(enrollment, "UNENROLL_CODE", "a-code-this-lab-never-heard-of"):
        cluster.deliver_revocations(lab["runtime"])
    assert lab["calls"] == ["federated_enroll"] and _queued(lab) == []  # let go, not retried forever
    assert _rows(lab["res"], "SELECT 1 FROM Accounts WHERE username=?", lab["proxy"])


def test_a_partner_without_a_contract_keeps_its_row_until_the_ttl(lab):
    import time

    fresh, old = str(uuid.uuid4()), str(uuid.uuid4())
    with sqlite3.connect(lab["res"]) as conn:
        conn.execute("INSERT INTO FederatedRevocations VALUES (?,?,?)", (fresh, OTHER, int(time.time())))
        conn.execute("INSERT INTO FederatedRevocations VALUES (?,?,?)",
                     (old, OTHER, int(time.time()) - cluster.REVOCATION_TTL - 1))
    cluster.deliver_revocations(lab["runtime"])
    assert lab["calls"] == [] and _queued(lab) == [(fresh, OTHER)]  # may be back (a rejoin); not past the TTL


def test_a_refusing_partner_is_backed_off_and_noted_once_per_pass(lab):
    from remoterf_federation_core import OwnerSignedFailure

    second = str(uuid.uuid4())
    lab["reservations"].remove_user(username=NATIVE)
    with sqlite3.connect(lab["res"]) as conn:
        conn.execute("INSERT INTO FederatedRevocations VALUES (?,?,1)", (second, DEST))
    outbound, notes = lab["plane"].outbound, []
    refused = OwnerSignedFailure({"status": "error", "error_code": "principal_disabled"})
    with patch.object(outbound, "execute", side_effect=refused) as execute:
        cluster.deliver_revocations(lab["runtime"], notes.append)
        cluster.deliver_revocations(lab["runtime"], notes.append)
    assert execute.call_count == 1 and len(notes) == 1 and len(_queued(lab)) == 2


def test_an_enrolment_finishing_after_its_account_was_deleted_queues_the_unenrol(lab):
    with sqlite3.connect(lab["res"]) as conn:
        conn.execute("DELETE FROM FederatedEnrollments")
    plane, real = lab["plane"], lab["plane"].outbound.execute
    cluster.save({"lab": {"role": "member", "state": "active", "peer": DEST, "contract_id": CONTRACT,
                          "created_at": 1}})
    with cluster._usergroups() as conn:
        conn.execute("INSERT INTO ClusterAccounts(cluster_name,local_account_id,kind,joined_at) VALUES ('lab',?,'local',1)",
                     (lab["account_id"],))

    def deleted_meanwhile(**kwargs):
        result = real(**kwargs)
        lab["reservations"].remove_user(username=NATIVE)
        return result

    with patch.object(plane.outbound, "execute", deleted_meanwhile):
        cluster.enroll_students(lab["runtime"])
    assert _queued(lab) == [(lab["subject"], DEST)]
    assert not _rows(lab["res"], "SELECT 1 FROM FederatedEnrollments")


def test_a_partner_with_no_live_contract_is_forgotten_so_a_rejoin_enrols_again(lab):
    assert lab["plane"].enrolled(lab["account_id"]) == {DEST}
    cluster._forget_departed(lab["plane"])
    assert lab["plane"].enrolled(lab["account_id"]) == {DEST}  # contract live: kept
    with sqlite3.connect(lab["dest_db"]) as conn:
        conn.execute("UPDATE FederationContracts SET state='revoked'")
    cluster._forget_departed(lab["plane"])
    assert lab["plane"].enrolled(lab["account_id"]) == set()


def test_deleting_a_proxy_by_hand_also_clears_its_principal_and_cluster_rows(lab):
    with sqlite3.connect(lab["dest_db"]) as conn:
        account = conn.execute("SELECT local_account_id FROM FederatedPrincipals WHERE remote_subject_id=?",
                               (lab["subject"],)).fetchone()[0]
        conn.execute("INSERT INTO ClusterAccounts VALUES ('lab',?,'proxy',1)", (account,))
        conn.execute("INSERT INTO ClusterMemberships VALUES ('lab',?,1)", (account,))
    lab["reservations"].remove_user(username=lab["proxy"])
    assert _proxy_gone(lab)
    for table in ("ClusterAccounts", "ClusterMemberships", "UsersLookup"):
        column = "user_id" if table == "UsersLookup" else "local_account_id"
        assert not _rows(lab["dest_db"], f"SELECT 1 FROM {table} WHERE {column}=?", account)
    assert _queued(lab) == []  # a proxy is nobody's HOME account: nothing to tell anyone


def test_prune_lists_orphans_and_removes_them_only_with_yes(lab):
    from remoteRF_server.server import grpc_server, user_group_handler as ugh

    gone = prepare_federated_account(lab["res"], issuer_deployment_id=OTHER, remote_subject_id=str(uuid.uuid4()),
                                     perms_path=lab["root"] / "perms.db", now=100)
    with sqlite3.connect(lab["dest_db"]) as conn:
        for issuer, account in ((OTHER, gone.local_account_id), (HOME, 987654)):
            conn.execute("INSERT INTO FederatedPrincipals(id,issuer_deployment_id,remote_subject_id,local_account_id,"
                         "status,created_at,last_seen_at,display_metadata_json) "
                         "VALUES (?,?,?,?,'active',100,100,'{}')", (str(uuid.uuid4()), issuer, str(uuid.uuid4()), account))
    found = {o["username"]: o["reason"] for o in orphan_proxies(lab["res"], lab["dest_db"])}
    assert found == {gone.username: "issuer gone", None: "dangling"}  # alice's live proxy stays
    # Booked ahead: never stale, however long unseen.
    assert lab["proxy"] not in {o["username"] for o in orphan_proxies(lab["res"], lab["dest_db"], stale_days=0)}
    # Used recently, nothing ahead: active, not stale (the principal's own enrolment time is old).
    with sqlite3.connect(lab["dest_db"]) as conn:
        conn.execute("UPDATE FederatedPrincipals SET last_seen_at=100 WHERE remote_subject_id=?", (lab["subject"],))
    with sqlite3.connect(lab["res"]) as conn:
        end = datetime.now() - timedelta(days=1)
        conn.execute("UPDATE Reservations SET start_time=?, end_time=? WHERE username=?",
                     (end - timedelta(hours=1), end, lab["proxy"]))
    assert lab["proxy"] not in {o["username"] for o in orphan_proxies(lab["res"], lab["dest_db"], stale_days=30)}
    with sqlite3.connect(lab["res"]) as conn:
        conn.execute("DELETE FROM Reservations WHERE username=?", (lab["proxy"],))
    assert {o["username"]: o["reason"] for o in orphan_proxies(lab["res"], lab["dest_db"], stale_days=30)}[
        lab["proxy"]] == "stale"

    with patch.object(grpc_server, "reservation_handler", lab["reservations"]), \
         patch.object(ugh, "user_group_handler", SimpleNamespace(filepath=lab["dest_db"])):
        assert grpc_server.cmd_users_prune_proxies([]) == 0
        assert len(orphan_proxies(lab["res"], lab["dest_db"])) == 2
        assert grpc_server.cmd_users_prune_proxies(["-y"]) == 0
    assert orphan_proxies(lab["res"], lab["dest_db"]) == []
    assert not _rows(lab["res"], "SELECT 1 FROM Accounts WHERE username=?", gone.username)
    assert _rows(lab["res"], "SELECT 1 FROM Accounts WHERE username=?", lab["proxy"])
