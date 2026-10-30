"""ACC:availability: permitted devices with anonymous occupancy, one call per
interval per account; and the busy_until/next_start the status note carries."""

import json
import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from remoteRF_server.common.utils import map_arg, unmap_arg
from remoteRF_server.server import device_manager as dm

from test_device_handles import _Devices, _state

GID, OTHER = 4300, 4301


def _ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


class AvailabilityTests(_Devices):
    def setUp(self):
        super().setUp()
        from remoteRF_server.server import acc_perms, reservation, user_group_handler as ugh

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for target in (reservation, acc_perms, ugh):
            patcher = mock.patch.object(target, "get_db_dir", return_value=Path(tmp.name))
            patcher.start()
            self.addCleanup(patcher.stop)
        groups = ugh.UserGroupHandler()
        self.h = reservation.ReservationHandler()
        for name, value in (("perms", acc_perms.perms_db()), ("user_group_handler", groups)):
            patcher = mock.patch.object(reservation, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.dict(reservation._avail_last, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        group = groups.create_user_group(group_name="g", devices_whitelist=[GID], max_reservation_time_sec=60,
                                         max_reservations=1, lifetime_sec=0)
        groups.create_enrollment_codes(code_names=["C1", "C2"], group_id=group, uses=1, duration_sec=0)
        for user, code in (("jdoe", "C1"), ("asmith", "C2")):
            self.assertIn("UC", self.h.create_user(un=map_arg(user), pw=map_arg("password1"),
                                                   em=map_arg(f"{user}@example.org"), ec=map_arg(code)))
        dm._devices[GID] = _state(name="Pluto A")
        dm._devices[OTHER] = _state(name="Pluto B")
        self.reservation = reservation

    def _book(self, user, start, end, gid=GID):
        now = datetime.now()
        with sqlite3.connect(self.h.filepath) as conn:
            conn.execute("INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) "
                         "VALUES (?, ?, ?, ?, 's', 'h')",
                         (user, gid, _ts(now + timedelta(minutes=start)), _ts(now + timedelta(minutes=end))))

    def _call(self, user="jdoe", pw="password1"):
        result = self.h.handle_call(function_name="availability", args={"un": map_arg(user), "pw": map_arg(pw)})
        return {k: unmap_arg(v) for k, v in result.items()}

    def _devices(self, **kw):
        reply = self._call(**kw)
        self.assertEqual(set(reply), {"UC"}, reply)
        return json.loads(reply["UC"])

    def test_only_permitted_devices_free(self):
        data = self._devices()
        self.assertEqual(data["interval"], 10)
        [d] = data["devices"]
        self.assertEqual((d["local_device_id"], d["handle"], d["state"], d["until"], d["next"]),
                         (str(GID), "Pluto_A", "free", None, None))

    def test_someone_elses_booking_is_busy_and_anonymous(self):
        self._book("asmith", -5, 30)
        reply = self._call()
        self.assertNotIn("asmith", reply["UC"])
        [d] = json.loads(reply["UC"])["devices"]
        self.assertEqual(d["state"], "busy")
        self.assertAlmostEqual(d["until"], (datetime.now() + timedelta(minutes=30)).timestamp(), delta=5)

    def test_own_booking_is_mine_and_next_is_inside_the_window_only(self):
        self._book("jdoe", -5, 30)
        self._book("asmith", 60, 90)
        self._book("asmith", 8 * 60, 9 * 60)
        [d] = self._devices()["devices"]
        self.assertEqual(d["state"], "mine")
        self.assertAlmostEqual(d["next"], (datetime.now() + timedelta(minutes=60)).timestamp(), delta=5)

    def test_rate_limited_per_account_with_retry_after(self):
        self._devices()
        refused = self._call()
        self.assertTrue(1 <= refused["retry_after"] <= 10, refused)
        self.assertIn("try again in", refused["ace"])
        self._devices(user="asmith")  # another account is not throttled
        with mock.patch.object(self.reservation, "_AVAIL_INTERVAL", 0):
            self._devices()

    def test_bad_login(self):
        self.assertEqual(self._call(pw="wrong"), {"ace": "Invalid login credentials."})

    def test_status_note_carries_occupancy_only_with_home(self):
        from remoteRF_server.server.federation import cluster

        self._book("asmith", -5, 30)
        self._book("asmith", 60, 90, gid=OTHER)
        group = {"group_name": "g", "max_reservation_time_sec": 60, "max_reservations": 1,
                 "lifetime_sec": 0, "max_horizon_sec": 0, "devices": [GID, OTHER]}
        with mock.patch.object(cluster, "groups", return_value=[group]):
            plain = cluster._sharing("c")["detail"][0]["devices"]
            noted = cluster._sharing("c", home=self.h)["detail"][0]["devices"]
        self.assertNotIn("busy_until", plain[0])
        self.assertGreater(noted[0]["busy_until"], 0)
        self.assertEqual(noted[0]["next_start"], 0)
        self.assertEqual(noted[1]["busy_until"], 0)
        self.assertGreater(noted[1]["next_start"], 0)
