"""A RemoteRF Global account's login at a lab it joined by code (Server 1.5):
made only by Global's signed enroll, checked with a lab-bound secret, kept in
step by `lan.update`, gone with its last group; and registration on a joined
lab goes to Global."""

import os
import sqlite3
from types import SimpleNamespace
from unittest import mock
from uuid import uuid4

import pytest
from remoterf_federation_core import LAN_UPDATE_CODE, lan_secret, lan_verifier

GLOBAL = "11111111-1111-4111-8111-111111111111"
PARTNER = "22222222-2222-4222-8222-222222222222"
LAB = "33333333-3333-4333-8333-333333333333"
JANE = str(uuid4())


@pytest.fixture
def lab(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REMOTERF_", "XDG_"))}
    env.update(XDG_CONFIG_HOME=str(tmp_path), XDG_DATA_HOME=str(tmp_path / "data"))
    with mock.patch.dict("os.environ", env, clear=True):
        from remoteRF_server.server import acc_perms, reservation
        from remoteRF_server.server import user_group_handler as ugh
        from remoteRF_server.server.federation import links

        groups, handler = ugh.UserGroupHandler(), reservation.ReservationHandler()
        perms = acc_perms.perms_db() if hasattr(acc_perms, "perms_db") else acc_perms.Perms()
        with mock.patch.object(reservation, "perms", perms), \
             mock.patch.object(reservation, "user_group_handler", groups), \
             mock.patch.object(ugh, "user_group_handler", groups), \
             mock.patch.object(reservation, "reservation_handler", handler), \
             mock.patch.object(links, "global_home_id", return_value=GLOBAL):
            yield SimpleNamespace(groups=groups, h=handler, res_db=reservation.get_db_dir() / "reservations.db",
                                  reservation=reservation)


def _link(lab, subject=JANE, name="jdoe", email="jdoe@example.org", password="correct horse"):
    salt, hashed = lan_verifier(lan_secret(password, LAB, name))
    return lab.h.link_global_account(issuer=GLOBAL, subject=subject, username=name, email=email,
                                      salt=salt, hashed=hashed)


def test_a_joined_lab_sends_registration_to_global_before_reading_anything(lab):
    from remoteRF_server.common.utils import map_arg, unmap_arg
    from remoteRF_server.server import global_onboarding

    with mock.patch("remoteRF_server.server.federation.runtime.federation_enabled", return_value=True), \
         mock.patch.object(global_onboarding, "lab_slug", return_value="ucla"):
        reply = lab.h.create_user(un=map_arg("jdoe"), pw=map_arg(""), em=map_arg(""), ec=map_arg("ANY"))
    assert unmap_arg(reply["GS"]) == "ucla" and "UC" not in reply
    with sqlite3.connect(lab.res_db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM Accounts").fetchone()[0] == 0


def test_a_linked_login_takes_the_lab_bound_secret_and_tells_old_clients_to_upgrade(lab):
    uid, error, proxy = _link(lab)
    assert error is None and proxy is None
    assert "UC" in lab.h.login_user("jdoe", lan_secret("correct horse", LAB, "jdoe"))
    assert "remoterf 2.9" in str(lab.h.login_user("jdoe", "correct horse")["UE"])  # the password itself
    assert "Invalid" in str(lab.h.login_user("jdoe", lan_secret("wrong", LAB, "jdoe"))["UE"])
    assert _link(lab)[0] == uid  # again from Global: the same login
    assert _link(lab, subject=str(uuid4()), email="other@example.org")[1] == "username_taken"
    assert _link(lab, subject=str(uuid4()), name="jdoe2", email="JDoe@example.org")[1] == "email_taken"


def test_lan_update_replaces_the_login_and_ends_remembered_sessions(lab):
    _link(lab)
    token = lab.h.issue_session("jdoe")
    salt, hashed = lan_verifier(lan_secret("new password", LAB, "jdoe"))
    assert lab.h.set_linked_verifier(issuer=GLOBAL, subject=JANE, email="jdoe@example.org",
                                     salt=salt, hashed=hashed) is None
    assert "UC" not in lab.h.login_user("jdoe", token)
    assert "UC" in lab.h.login_user("jdoe", lan_secret("new password", LAB, "jdoe"))
    assert lab.h.set_linked_verifier(issuer=GLOBAL, subject=str(uuid4()), email="x@example.org",
                                     salt=salt, hashed=hashed) == "principal_unknown"


def test_a_linked_login_lives_as_long_as_a_group_it_joined(lab):
    keep = lab.groups.create_user_group(group_name="keep", devices_whitelist=[], max_reservation_time_sec=60,
                                        max_reservations=1, lifetime_sec=0)
    term = lab.groups.create_user_group(group_name="term", devices_whitelist=[], max_reservation_time_sec=60,
                                        max_reservations=1, lifetime_sec=0)
    only, both = _link(lab)[0], _link(lab, subject=str(uuid4()), name="amy", email="amy@example.org")[0]
    with sqlite3.connect(lab.groups.filepath) as conn:
        conn.executemany("INSERT INTO UsersLookup(user_id, group_id) VALUES (?,?)",
                         [(only, term), (both, term), (both, keep)])
    assert lab.groups.delete_user_group(group_id=term)
    with sqlite3.connect(lab.res_db) as conn:
        left = {row[0] for row in conn.execute("SELECT username FROM Accounts")}
    assert left == {"amy"}


def _action(code, *, issuer=GLOBAL, **payload):
    claims = {"iss": issuer, "sub": JANE, "request_id": str(uuid4()), "request_sha256": "a" * 64,
              "contract_id": str(uuid4()), "contract_version": 1}
    salt, hashed = lan_verifier(lan_secret("correct horse", LAB, "jdoe"))
    return SimpleNamespace(claims=claims, state="active", prepared=None, request=SimpleNamespace(value={"payload": {
        "code_name": code, "username": "jdoe", "email": "jdoe@example.org", "lan_salt": salt, "lan_hash": hashed,
        **payload}}))


def _enroll(lab, action):
    from remoteRF_server.server.federation.enrollment import ServerFederatedEnrollHandler

    handler = ServerFederatedEnrollHandler(usergroups_path=lab.groups.filepath, reservations_path=lab.res_db,
                                           local_deployment_id=LAB, display_name="Lab")
    action.prepared = handler.prepare(action)
    with sqlite3.connect(lab.groups.filepath) as tx:
        return handler(tx, action)


def test_globals_enroll_makes_the_login_and_a_partner_lab_cannot(lab):
    from remoteRF_server.server.federation.destination import FederationBusinessError

    gid = lab.groups.create_user_group(group_name="class", devices_whitelist=[], max_reservation_time_sec=60,
                                       max_reservations=1, lifetime_sec=0)
    lab.groups.create_enrollment_codes(code_names=["CLASS1"], group_id=gid, uses=2, duration_sec=0)
    with pytest.raises(FederationBusinessError, match="enrollee_not_allowed"):
        _enroll(lab, _action("CLASS1", issuer=PARTNER))
    result = _enroll(lab, _action("CLASS1"))
    assert result["membership_present"] and result["groups"] == [{"group_id": str(gid), "group_name": "class"}]
    uid = lab.h.get_uid("jdoe")
    with sqlite3.connect(lab.groups.filepath) as conn:
        assert conn.execute("SELECT 1 FROM UsersLookup WHERE user_id=? AND group_id=?", (uid, gid)).fetchone()
        assert conn.execute("SELECT uses FROM EnrollmentCodes WHERE code_name='CLASS1'").fetchone()[0] == 1
    assert "UC" in lab.h.login_user("jdoe", lan_secret("correct horse", LAB, "jdoe"))

    # Global's lab-login update, then its unenrol (the account was deleted there).
    salt, hashed = lan_verifier(lan_secret("reset password", LAB, "jdoe"))
    _enroll(lab, _action(LAN_UPDATE_CODE, lan_salt=salt, lan_hash=hashed))
    assert "UC" in lab.h.login_user("jdoe", lan_secret("reset password", LAB, "jdoe"))
    unenroll = _action("cluster.unenroll")
    for field in ("username", "email", "lan_salt", "lan_hash"):
        unenroll.request.value["payload"].pop(field)
    _enroll(lab, unenroll)
    assert lab.h.get_username_by_acc_id(uid) is None


def test_a_lan_only_group_is_joined_only_on_the_lan(lab):
    gid = lab.groups.create_user_group(group_name="bench", devices_whitelist=[], max_reservation_time_sec=60,
                                       max_reservations=1, lifetime_sec=0)
    lab.groups.create_enrollment_codes(code_names=["BENCH1"], group_id=gid, uses=1, duration_sec=0)
    with sqlite3.connect(lab.groups.filepath) as conn:
        conn.execute("UPDATE UserGroups SET lan_only=1 WHERE group_id=?", (gid,))
    result = _enroll(lab, _action("BENCH1"))
    assert not result["membership_present"]  # the login exists; the code waits for ACC:set_enroll on the LAN
    with sqlite3.connect(lab.groups.filepath) as conn:
        assert conn.execute("SELECT uses FROM EnrollmentCodes WHERE code_name='BENCH1'").fetchone()[0] == 1


def test_globals_requests_for_a_linked_account_act_as_that_account(lab):
    from remoteRF_server.server.federation.devices import _DeviceHandlerBase
    from remoteRF_server.server.federation import links
    from remoteRF_server.server.federation.links import SCHEMA

    uid = _link(lab)[0]
    with sqlite3.connect(lab.groups.filepath) as tx:
        tx.execute(SCHEMA)
        assert _DeviceHandlerBase._principal(tx, {"iss": GLOBAL, "sub": JANE}) == (links.principal_id(JANE), uid)


def test_listings_skip_partners_for_a_while_after_one_slow_pass(lab, monkeypatch):
    reservation = lab.reservation
    monkeypatch.setattr(reservation, "_FANOUT_SLOW", -1.0)
    monkeypatch.setattr(reservation, "_fanout_paused_until", 0.0)
    calls = []
    assert reservation._fanout(lambda: calls.append(1) or {"a": 1}, {}) == {"a": 1}
    assert reservation._fanout(lambda: calls.append(1) or {"a": 1}, {}) == {}  # paused: not even asked
    assert len(calls) == 1
