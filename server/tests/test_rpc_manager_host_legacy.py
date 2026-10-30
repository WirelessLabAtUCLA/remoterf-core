import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault("adi", types.ModuleType("adi"))

from remoteRF_server.common.utils.process_arg import map_arg, unmap_arg
from remoteRF_server.server import rpc_manager as rpc_module
from remoteRF_server.server.device_manager import VirtualDevice
from remoteRF_server.server.rpc_manager import RpcManager


class HostLegacyTests(unittest.TestCase):
    def test_failure_becomes_client_error_and_uses_25_second_timeout(self):
        calls = []

        def forward(registry, **kwargs):
            calls.append(kwargs)
            return {"Ok": map_arg(False)}

        device = VirtualDevice(gid=5, host_id="host-1", device_id="d1", kind="fake")
        with patch.object(rpc_module.hts, "handle_host_device", forward), patch.object(
            rpc_module.hts, "get_tunnel_registry", return_value=None
        ):
            result = RpcManager()._dispatch_acquired(
                function_name="Fake:gain:SET", args={"gain": map_arg(1)}, gid=5, dev=device
            )

        self.assertEqual(calls[0]["timeout_sec"], 25.0)
        self.assertEqual(
            unmap_arg(result["a"]),
            "The device did not answer in time; it may still be powering on. Try again.",
        )

    def test_host_error_text_becomes_client_error(self):
        device = VirtualDevice(gid=5, host_id="host-1", device_id="d1", kind="fake")
        with patch.object(
            rpc_module.hts, "handle_host_device",
            return_value={"Error": map_arg("host failed")},
        ), patch.object(rpc_module.hts, "get_tunnel_registry", return_value=None):
            result = RpcManager()._dispatch_acquired(
                function_name="Fake:gain:GET", args={}, gid=5, dev=device
            )
        self.assertEqual(unmap_arg(result["a"]), "host failed")


if __name__ == "__main__":
    unittest.main()
