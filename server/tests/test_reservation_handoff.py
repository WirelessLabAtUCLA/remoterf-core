"""What one reservation leaves on a device is not the next holder's.

The device manager notices every change of holder, a reservation ending or a
back-to-back one taking over, and resets the device (buffers, streamers, a
running transmitter) before anyone else drives it.
"""

import threading
import time
import unittest
from unittest.mock import patch

from remoteRF_server.server import device_manager

GID = 4243


def _device(dev, salt="a1", hsh="h1"):
    device_manager._devices[GID] = device_manager._DeviceState(
        dev=dev, origin="local", online=True, salt=salt, hsh=hsh, name="dev", ident="X", dtype="adalm_pluto",
    )


class _Radio:
    def __init__(self):
        self.resets = 0
        self.log = []

    def reset_for_next_holder(self):
        self.resets += 1
        self.log.append("reset")

    def prepare_for_holder(self):
        self.log.append("prepare")


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.radio = _Radio()
        _device(self.radio)
        self.addCleanup(device_manager._devices.pop, GID, None)
        self.ended = []
        patcher = patch.object(device_manager, "_reservation_end_callbacks", [self.ended.append])
        patcher.start()
        self.addCleanup(patcher.stop)

    def _drive(self):
        with device_manager.acquire_device_by_gid(GID) as (_, dev):
            return dev.resets

    def test_a_back_to_back_reservation_is_a_change_of_holder(self):
        device_manager.set_device(GID, "b2", "h2")
        self.assertEqual(self.ended, [GID])
        # The next holder's first call finds the device already reset, once.
        self.assertEqual(self._drive(), 1)
        self.assertEqual(self._drive(), 1)

    def test_the_same_reservation_refreshed_is_not(self):
        device_manager.set_device(GID, "a1", "h1")
        self.assertEqual(self.ended, [])
        self.assertEqual(self._drive(), 0)

    def test_an_ended_reservation_resets_the_device_with_nobody_waiting(self):
        device_manager.set_device(GID, "", "")
        self.assertEqual(self.ended, [GID])
        for _ in range(100):  # nobody acquires the device: the background reset does it
            if self.radio.resets:
                break
            time.sleep(0.01)
        self.assertEqual(self.radio.resets, 1)
        self.assertEqual(self._drive(), 1)

    def _wait_log(self, n):
        for _ in range(100):
            if len(self.radio.log) >= n:
                break
            time.sleep(0.01)
        self._drive()  # any background work still holding io_lock finishes first
        return self.radio.log

    def test_a_new_reservation_prepares_the_device_once_after_the_previous_reset(self):
        device_manager.set_device(GID, "b2", "h2")
        self.assertEqual(self._wait_log(2), ["reset", "prepare"])
        device_manager.set_device(GID, "b2", "h2")  # the next tick: same holder
        self.assertEqual(self._wait_log(3), ["reset", "prepare"])

    def test_a_reservation_starting_on_a_free_device_prepares_it(self):
        device_manager.set_device(GID, "", "")
        self._wait_log(1)
        device_manager.set_device(GID, "b2", "h2")
        self.assertEqual(self._wait_log(2), ["reset", "prepare"])

    def test_an_ended_reservation_is_never_prepared(self):
        device_manager.set_device(GID, "", "")
        self.assertEqual(self._wait_log(2), ["reset"])
        device_manager._prepare_for_holder(GID, ("a1", "h1"))  # a stale pre-warm finds it over
        self.assertEqual(self.radio.log, ["reset"])

    def test_a_first_call_during_the_boot_waits_for_that_boot(self):
        booting, boot_done = threading.Event(), threading.Event()

        def slow_boot():
            booting.set()
            boot_done.wait(5)
            self.radio.log.append("prepare")

        self.radio.prepare_for_holder = slow_boot
        device_manager.set_device(GID, "b2", "h2")
        self.assertTrue(booting.wait(5))
        first_call = threading.Thread(target=lambda: self.radio.log.append(("call", self._drive())))
        first_call.start()
        first_call.join(0.1)
        self.assertTrue(first_call.is_alive())  # held on io_lock, not booting a second time
        boot_done.set()
        first_call.join(5)
        self.assertEqual(self.radio.log, ["reset", "prepare", ("call", 1)])

    def test_host_devices_are_not_prepared(self):
        device_manager._devices[GID].origin = "host"
        with patch.object(device_manager, "_sync_host_devices"):
            device_manager.set_device(GID, "b2", "h2")
            self.assertEqual(self._wait_log(2), ["reset"])


class HostReservationStartTests(unittest.TestCase):
    def test_start_is_sent_once_for_a_new_holder_only(self):
        sent = []

        class Registry:
            def send_control(self, host_id, *, kind, device_id, payload):
                sent.append((host_id, kind, device_id, payload))
                return True

        device_manager._devices[GID] = device_manager._DeviceState(
            dev=device_manager.VirtualDevice(GID, "host-1", "d1"), origin="host", online=True,
            salt="", hsh="", name="dev", ident="X", dtype="adalm_pluto",
        )
        self.addCleanup(device_manager._devices.pop, GID, None)
        with patch.object(device_manager, "_sync_host_devices"), patch.object(
            device_manager, "_reservation_end_callbacks", []
        ), patch.object(device_manager.hts, "get_tunnel_registry", return_value=Registry()):
            device_manager.set_device(GID, "s1", "h1")
            device_manager.set_device(GID, "s1", "h1")
            device_manager.set_device(GID, "", "")

        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][:3], ("host-1", "reservation_start", "d1"))
        self.assertEqual(set(sent[0][3]), {"at"})


if __name__ == "__main__":
    unittest.main()
