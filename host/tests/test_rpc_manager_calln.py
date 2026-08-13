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

from __future__ import annotations

import unittest
from unittest.mock import patch

from remoteRF_host.common.utils import map_arg, unmap_arg
from remoteRF_host.server.rpc_manager import RpcManager


class FakeSchema:
    device_type = "fake"

    def __init__(self):
        self.calls = []

    def dispatch(self, method_name: str, args: dict):
        self.calls.append((method_name, args))
        if method_name == "call_zero":
            return "zero"
        if method_name == "call_one":
            return {"seen": args}
        if method_name == "call_configure":
            return {"seen": args}
        raise KeyError(method_name)

    def list_exposed(self):
        return {"calls": ["call_zero", "call_one", "call_configure"]}


class RpcManagerCallNTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = RpcManager()
        self.schema = FakeSchema()

    def run_with_schema(self, function_name: str, args: dict):
        with patch("remoteRF_host.server.rpc_manager.get_device", return_value=self.schema):
            return self.manager.run_rpc(function_name=function_name, args=args)

    def test_calln_filters_transport_keys_and_forwards_named_args(self) -> None:
        response = self.run_with_schema(
            "Fake:configure:CALLN",
            {
                "g": map_arg(7),
                "a": map_arg("api-token"),
                "token": map_arg("schema-token"),
                "device_id": map_arg(7),
                "device_name": map_arg("radio"),
                "freq": map_arg(2.4e9),
                "gain": map_arg(10),
                "options": map_arg({"agc": False}),
            },
        )

        self.assertEqual(
            self.schema.calls,
            [
                (
                    "call_configure",
                    {"freq": 2.4e9, "gain": 10, "options": {"agc": False}},
                )
            ],
        )
        self.assertEqual(
            unmap_arg(response["configure"]),
            {"seen": {"freq": 2.4e9, "gain": 10, "options": {"agc": False}}},
        )

    def test_call0_and_call1_are_preserved(self) -> None:
        response = self.run_with_schema("Fake:zero:CALL0", {"g": map_arg(7)})
        self.assertEqual(unmap_arg(response["zero"]), "zero")
        self.assertEqual(self.schema.calls[-1], ("call_zero", {}))

        response = self.run_with_schema(
            "Fake:one:CALL1",
            {"g": map_arg(7), "arg1": map_arg({"hello": "world"})},
        )
        self.assertEqual(self.schema.calls[-1], ("call_one", {"value": {"hello": "world"}}))
        self.assertEqual(unmap_arg(response["one"]), {"seen": {"value": {"hello": "world"}}})


if __name__ == "__main__":
    unittest.main()
