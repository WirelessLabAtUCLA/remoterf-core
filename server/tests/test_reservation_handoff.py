"""What one reservation leaves on a device is not the next holder's.

The device manager notices every change of holder, a reservation ending or a
back-to-back one taking over, and resets the device (buffers, streamers, a
running transmitter) before anyone else drives it.
"""

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

    def reset_for_next_holder(self):
        self.resets += 1


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



if __name__ == "__main__":
    unittest.main()
