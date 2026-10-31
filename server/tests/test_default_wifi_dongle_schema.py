# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from __future__ import annotations

import importlib
import unittest

from rssi.scanner import dbm_to_quality_percent, freq_to_channel


class WifiDonglePackagingTests(unittest.TestCase):
    def test_bundled_rssi_package(self):
        self.assertEqual(freq_to_channel(2412), 1)
        self.assertEqual(dbm_to_quality_percent(-75.0), 50)

    def test_schema_module_imports(self):
        importlib.import_module("remoteRF_server.drivers.wifi_dongle.wifi_dongle_schema")


if __name__ == "__main__":
    unittest.main()
