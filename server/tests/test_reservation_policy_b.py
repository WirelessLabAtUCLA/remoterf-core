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

"""Policy B regression coverage: a registered device may be reserved for a
future interval even while it is currently offline. Live connectivity is
operational state, checked only when a reservation is actually exercised
(device access), never at reservation-creation time.
"""

import sqlite3
import uuid
from datetime import datetime, timedelta

import pytest

from remoteRF_server.common.utils.api_token import generate_token
from remoteRF_server.common.utils.db_location import get_db_dir
from remoteRF_server.common.utils.process_arg import map_arg, unmap_arg
from remoteRF_server.server import device_manager
from remoteRF_server.server.device_manager import (
    _DeviceState,
    acquire_device,
    get_all_devices,
    get_registered_devices,
    set_device,
)
from remoteRF_server.server.reservation import reservation_handler
from remoteRF_server.server.user_group_handler import user_group_handler


def _make_device_state(*, connected: bool, name: str) -> _DeviceState:
    return _DeviceState(
        dev=object() if connected else None,
        origin="local",
        online=connected,
        salt="",
        hsh="",
        name=name,
        ident="",
        dtype="test",
    )


@pytest.fixture
def fake_devices():
    """Inject a connected device, a registered-but-offline device, and leave
    one id deliberately unregistered. Restores the real registry afterward."""
    base = 900_000 + (uuid.uuid4().int % 90_000)
    connected_id, offline_id, missing_id = base, base + 1, base + 2

    with device_manager._state_lock:
        saved = dict(device_manager._devices)
        device_manager._devices[connected_id] = _make_device_state(
            connected=True, name="policyb-connected"
        )
        device_manager._devices[offline_id] = _make_device_state(
            connected=False, name="policyb-offline"
        )
        # missing_id is intentionally never added: it must behave as
        # "does not exist" everywhere.

    try:
        yield {"connected": connected_id, "offline": offline_id, "missing": missing_id}
    finally:
        with device_manager._state_lock:
            device_manager._devices.clear()
            device_manager._devices.update(saved)


def _cleanup_account(*, username: str, group_id):
    db_dir = get_db_dir()
    with sqlite3.connect(db_dir / "reservations.db") as con:
        con.execute("DELETE FROM Reservations WHERE username = ?", (username,))
        con.execute("DELETE FROM Accounts WHERE username = ?", (username,))
        con.commit()
    with sqlite3.connect(db_dir / "perms.db") as con:
        con.execute("DELETE FROM Users WHERE Username = ?", (username,))
        con.commit()
    if group_id is not None:
        with sqlite3.connect(db_dir / "usergroups.db") as con:
            con.execute("DELETE FROM UsersLookup WHERE group_id = ?", (group_id,))
            con.execute("DELETE FROM UserGroups WHERE group_id = ?", (group_id,))
            con.execute("DELETE FROM EnrollmentCodes WHERE group_id = ?", (group_id,))
            con.commit()


@pytest.fixture
def test_user(fake_devices):
    """A real Normal User account (created through the real registration
    flow) permitted only for the 'connected' and 'offline' test devices."""
    suffix = uuid.uuid4().hex[:10]
    username = f"_policyb_{suffix}"
    group_id = user_group_handler.create_user_group(
        group_name=f"_policyb_group_{suffix}",
        devices_whitelist=[fake_devices["connected"], fake_devices["offline"]],
        max_reservation_time_sec=3600,
        max_reservations=5,
        lifetime_sec=0,
    )
    assert group_id is not None

    code_name = f"_policyb_code_{suffix}"
    created = user_group_handler.create_enrollment_codes(
        code_names=[code_name], group_id=group_id, uses=5, duration_sec=3600,
    )
    assert created.startswith("Created 1"), created

    resp = reservation_handler.create_user(
        un=map_arg(username),
        pw=map_arg("testpass123"),
        em=map_arg(f"{username}@example.test"),
        ec=map_arg(code_name),
    )
    assert "UC" in resp, unmap_arg(resp.get("UE", map_arg("<no UE>")))

    try:
        yield {"username": username, "group_id": group_id}
    finally:
        _cleanup_account(username=username, group_id=group_id)


def _slot(hours_from_now: float, minutes: int = 30):
    start = datetime.now() + timedelta(hours=hours_from_now)
    return start, start + timedelta(minutes=minutes)


# ---------------------------------------------------------------------------
# device_manager: registered vs. connected views
# ---------------------------------------------------------------------------

def test_get_registered_devices_includes_offline_but_not_missing(fake_devices):
    registered = get_registered_devices()
    assert fake_devices["connected"] in registered
    assert fake_devices["offline"] in registered
    assert fake_devices["missing"] not in registered


def test_get_all_devices_excludes_offline(fake_devices):
    connected_only = get_all_devices()
    assert fake_devices["connected"] in connected_only
    assert fake_devices["offline"] not in connected_only


# ---------------------------------------------------------------------------
# 1-6: reservation creation semantics
# ---------------------------------------------------------------------------

def test_connected_permitted_device_reservation_succeeds(test_user, fake_devices):
    start, end = _slot(1)
    result = reservation_handler.reserve_device(test_user["username"], fake_devices["connected"], start, end)
    assert "Token" in result, {k: unmap_arg(v) for k, v in result.items()}


def test_offline_but_registered_permitted_device_reservation_succeeds(test_user, fake_devices):
    """Policy B: offline is operational state, not reservation eligibility."""
    start, end = _slot(2)
    result = reservation_handler.reserve_device(test_user["username"], fake_devices["offline"], start, end)
    assert "Token" in result, {k: unmap_arg(v) for k, v in result.items()}


def test_reservation_beyond_the_groups_horizon_is_rejected(test_user, fake_devices):
    """A group's max_horizon_sec (default 7 days) bounds how far ahead a start may be."""
    start, end = _slot(6 * 24)
    result = reservation_handler.reserve_device(test_user["username"], fake_devices["connected"], start, end)
    assert "Token" in result, {k: unmap_arg(v) for k, v in result.items()}
    start, end = _slot(8 * 24)
    result = reservation_handler.reserve_device(test_user["username"], fake_devices["connected"], start, end)
    assert "Token" not in result and "7 days ahead" in str({k: unmap_arg(v) for k, v in result.items()})


def test_nonexistent_device_reservation_rejected(test_user, fake_devices):
    start, end = _slot(3)
    result = reservation_handler.reserve_device(test_user["username"], fake_devices["missing"], start, end)
    assert "ace" in result
    assert "does not exist" in unmap_arg(result["ace"])


def test_registered_but_unauthorized_device_reservation_rejected(test_user, fake_devices):
    other_id = fake_devices["offline"] + 500
    with device_manager._state_lock:
        device_manager._devices[other_id] = _make_device_state(connected=False, name="policyb-unauth")
    try:
        start, end = _slot(4)
        result = reservation_handler.reserve_device(test_user["username"], other_id, start, end)
        assert "ace" in result
    finally:
        with device_manager._state_lock:
            device_manager._devices.pop(other_id, None)


def test_conflicting_reservation_rejected(test_user, fake_devices):
    start, end = _slot(5)
    first = reservation_handler.reserve_device(test_user["username"], fake_devices["connected"], start, end)
    assert "Token" in first

    overlap_start = start + timedelta(minutes=10)
    overlap_end = end + timedelta(minutes=10)
    second = reservation_handler.reserve_device(
        test_user["username"], fake_devices["connected"], overlap_start, overlap_end
    )
    assert "ace" in second
    assert "already reserved" in unmap_arg(second["ace"])


def test_invalid_time_interval_rejected(test_user, fake_devices):
    start, _ = _slot(6)
    end = start - timedelta(minutes=5)  # end before start
    result = reservation_handler.reserve_device(test_user["username"], fake_devices["connected"], start, end)
    assert "ace" in result


# ---------------------------------------------------------------------------
# 7-9: connectivity is enforced at access time, not creation time
# ---------------------------------------------------------------------------

def test_reservation_persists_when_device_disconnects_afterward(test_user, fake_devices):
    start, end = _slot(7)
    result = reservation_handler.reserve_device(test_user["username"], fake_devices["connected"], start, end)
    assert "Token" in result

    # Device goes offline after the reservation was created.
    with device_manager._state_lock:
        device_manager._devices[fake_devices["connected"]].dev = None
        device_manager._devices[fake_devices["connected"]].online = False

    db_dir = get_db_dir()
    with sqlite3.connect(db_dir / "reservations.db") as con:
        row = con.execute(
            "SELECT * FROM Reservations WHERE username = ? AND device_id = ?",
            (test_user["username"], fake_devices["connected"]),
        ).fetchone()
    assert row is not None, "reservation row must remain in the DB after the device goes offline"


def test_access_fails_cleanly_when_device_offline_without_corrupting_reservation(test_user, fake_devices):
    salt, hashed, token = generate_token()
    device_id = fake_devices["offline"]
    set_device(device_id, salt, hashed)
    try:
        with pytest.raises(RuntimeError):
            with acquire_device(token):
                pass  # must never get here: device is offline
    finally:
        set_device(device_id, "", "")

    # The token/salt state on the device row itself must be untouched by the
    # failed access attempt (no corruption of reservation-adjacent state).
    with device_manager._state_lock:
        st = device_manager._devices[device_id]
    assert st.salt == "" and st.hsh == ""


def test_access_succeeds_once_device_reconnects(test_user, fake_devices):
    salt, hashed, token = generate_token()
    device_id = fake_devices["offline"]
    set_device(device_id, salt, hashed)
    try:
        with pytest.raises(RuntimeError):
            with acquire_device(token):
                pass

        # Device reconnects within its reservation window.
        with device_manager._state_lock:
            device_manager._devices[device_id].dev = object()
            device_manager._devices[device_id].online = True

        with acquire_device(token) as (gid, dev):
            assert gid == device_id
            assert dev is not None
    finally:
        set_device(device_id, "", "")


# ---------------------------------------------------------------------------
# Integration regression: the exact RRF2 resdev failure this fix addresses
# ---------------------------------------------------------------------------

def test_offline_device_is_listed_by_get_dev_and_is_now_reservable(test_user, fake_devices):
    """Reproduces the originally-reported RRF2 sequence:
    ACC:get_dev returns the permitted offline device (unchanged, desired
    behavior) and a subsequent ACC:reserve_device for it must now succeed
    instead of returning 'Invalid device ID. Device either does not exist or
    is disconnected.'
    """
    devices = reservation_handler.grab_all_devices(test_user["username"])
    offline_key = str(fake_devices["offline"])
    assert offline_key in devices
    assert "policyb-offline" in unmap_arg(devices[offline_key])

    start, end = _slot(8)
    result = reservation_handler.reserve_device(test_user["username"], fake_devices["offline"], start, end)
    assert "Token" in result, {k: unmap_arg(v) for k, v in result.items()}


def test_reservation_overlapping_a_diagnostic_is_refused(test_user, fake_devices):
    start, end = _slot(9)
    gid = fake_devices["connected"]
    device_manager.diag_hold(gid, start.timestamp() + 60)
    try:
        refused = reservation_handler.reserve_device(test_user["username"], gid, start, end)
    finally:
        device_manager.diag_release(gid)
    assert "under diagnostics" in unmap_arg(refused["ace"])
    assert "Token" in reservation_handler.reserve_device(test_user["username"], gid, start, end)
