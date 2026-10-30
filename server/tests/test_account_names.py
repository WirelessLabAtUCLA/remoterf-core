"""An account is `name@lab` on Global: the name is unique here only, so
registering never asks Global, and the new account is reported in full."""

import os
import tempfile
import unittest
from unittest import mock


class AccountNameTests(unittest.TestCase):
    def _register_and_delete(self, *, on_global: bool):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("REMOTERF_", "XDG_"))}
        env.update(XDG_CONFIG_HOME=tmp.name, XDG_DATA_HOME=tmp.name + "/data")
        with mock.patch.dict("os.environ", env, clear=True):
            from remoteRF_server.common.utils import map_arg, unmap_arg
            from remoteRF_server.server import acc_perms, global_onboarding, reservation
            from remoteRF_server.server import user_group_handler as ugh

            groups, h = ugh.UserGroupHandler(), reservation.ReservationHandler()
            perms = acc_perms.perms_db() if hasattr(acc_perms, "perms_db") else acc_perms.Perms()
            kv = {"GLOBAL_NAME": "ucla-req", "GLOBAL_FINAL_NAME": "ucla"}
            with mock.patch.object(reservation, "perms", perms), \
                    mock.patch.object(reservation, "user_group_handler", groups), \
                    mock.patch.object(global_onboarding, "load", return_value=kv), \
                    mock.patch.object(global_onboarding, "state",
                                      return_value="active" if on_global else "left"), \
                    mock.patch.object(global_onboarding, "call") as call:
                gid = groups.create_user_group(group_name="g", devices_whitelist=[], max_reservation_time_sec=60,
                                               max_reservations=1, lifetime_sec=0)
                groups.create_enrollment_codes(code_names=["C1"], group_id=gid, uses=5, duration_sec=0)

                def register(name, email):
                    out = h.create_user(un=map_arg(name), pw=map_arg("password1"), em=map_arg(email),
                                        ec=map_arg("C1"))
                    return {k: unmap_arg(v) for k, v in out.items()}

                refused = register("jdoe@ucla", "i@x.org")
                self.assertEqual(refused, {"UE": "Username cannot contain '@'."})
                self.assertEqual(h.get_uid("jdoe@ucla"), -1)

                created = register("alice", "a@x.org")
                self.assertEqual(created, {"UC": "alice@ucla" if on_global else "alice"})
                self.assertEqual(register("alice", "a2@x.org"),
                                 {"UE": "That username or email is already registered."})
                h.remove_user(username="alice")
                self.assertEqual(h.get_uid("alice"), -1)
            call.assert_not_called()

    def test_on_global_the_account_is_name_at_lab_and_global_is_never_asked(self) -> None:
        self._register_and_delete(on_global=True)

    def test_off_global_the_account_is_the_bare_name(self) -> None:
        self._register_and_delete(on_global=False)


if __name__ == "__main__":
    unittest.main()
