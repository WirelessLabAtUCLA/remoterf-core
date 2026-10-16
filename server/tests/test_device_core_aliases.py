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

import importlib
import unittest

ALIASES = {
    "remoteRF_server.common.grpc.grpc_pb2": "remoterf_device_core.grpc.grpc_pb2",
    "remoteRF_server.common.grpc.grpc_host_pb2": "remoterf_device_core.grpc.grpc_host_pb2",
    "remoteRF_server.common.grpc.v2_codec": "remoterf_device_core.grpc.v2_codec",
    "remoteRF_server.common.idl.schema": "remoterf_device_core.idl.schema",
    "remoteRF_server.common.idl.v2": "remoterf_device_core.idl.v2",
    "remoteRF_server.common.idl.pluto_schema": "remoterf_device_core.drivers.adalm_pluto.pluto_schema",
    "remoteRF_server.common.utils.process_arg": "remoterf_device_core.utils.process_arg",
    "remoteRF_server.server.v2_errors": "remoterf_device_core.v2_errors",
    "remoteRF_server.drivers.adalm_pluto.poe": "remoterf_device_core.drivers.adalm_pluto.poe",
    "remoteRF_server.drivers.hackrf.hackrf_schema": "remoterf_device_core.drivers.hackrf.hackrf_schema",
    "remoteRF_server.drivers.usrp.uhd_manifest": "remoterf_device_core.drivers.usrp.uhd_manifest",
}


class DeviceCoreAliasTests(unittest.TestCase):
    def test_old_import_paths_are_the_device_core_modules(self):
        for old, new in ALIASES.items():
            try:
                module = importlib.import_module(old)
            except (ImportError, AttributeError, OSError) as exc:  # pyadi without libiio
                if "iio" in str(exc) or "adi" in str(exc):
                    continue
                raise
            self.assertIs(module, importlib.import_module(new), old)

    def test_one_driver_registry_and_the_lab_drivers_dir(self):
        from remoteRF_server.common.idl import schema
        from remoteRF_server.common.utils import get_drivers_dir
        from remoterf_device_core.idl import schema as core

        self.assertIs(schema._DRIVER_REGISTRY, core._DRIVER_REGISTRY)
        self.assertEqual(core._drivers_dir(), get_drivers_dir())


if __name__ == "__main__":
    unittest.main()
