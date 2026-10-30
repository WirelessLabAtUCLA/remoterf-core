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

import unittest
import os
import sys
import types
from unittest.mock import patch

import numpy as np

from remoteRF_server.common.idl.schema import (
    DeviceSchema,
    idl_client,
    idl_client_ctor,
    idl_client_method,
    idl_client_module,
    idl_client_namespace,
    idl_client_payload_class,
    idl_client_proxy_class,
    idl_expose,
    idl_register,
)


class FakeSchema(DeviceSchema):
    device_type = "fake"
    driver_version = "0.0.0"

    @idl_expose(kind="set")
    def set_level(self, value: int):
        self.device["level"] = value

    @idl_expose(kind="call")
    def call_ping(self):
        return "pong"

    @idl_expose(kind="call")
    def call_echo(self, value):
        return value

    @idl_expose(kind="call")
    def call_configure(self, freq: float, gain: int = 0, options: dict = None):
        return {"freq": freq, "gain": gain, "options": options}

    @idl_expose(kind="call")
    def call_keyword(self, first: int = 1, *, required: str):
        return {"first": first, "required": required}


class ClientMetadataSchema(DeviceSchema):
    device_type = "usrp"
    client_class = "MultiUSRP"
    client_objects = {
        "uhd": idl_client_module(
            {
                "types": idl_client_namespace(
                    {
                        "TimeSpec": idl_client_payload_class(
                            "TimeSpec",
                            {"secs": {"default": 0.0}},
                            init="timespec",
                            methods=[idl_client_method("timespec_get_real_secs")],
                        ),
                    }
                ),
                "RXStreamer": idl_client_proxy_class(
                    ["usrp", "handle"],
                    init="streamer_handle",
                    methods=[idl_client_method("rx_streamer_recv")],
                ),
                "usrp": idl_client_namespace({}),
            },
            exports=["types", "RXStreamer"],
            bind_client_class_to="usrp",
        ),
    }
    driver_version = "0.0.0"

    @idl_expose(
        kind="call",
        client_return=idl_client_ctor("uhd.types.TimeSpec", "$result"),
    )
    def call_get_time_now(self):
        return {"secs": 1.0}

    @idl_expose(
        kind="call",
        client_return=idl_client_ctor("uhd.RXStreamer", "$self", "$result"),
    )
    def call_get_rx_stream(self, stream_args):
        return {"handle": "rx:1"}


class DeviceSchemaTests(unittest.TestCase):
    def setUp(self):
        self._missing_module = object()
        self._uhd_module = sys.modules.get("uhd", self._missing_module)
        schema_name = "remoteRF_server.drivers.usrp.usrp_schema"
        self._usrp_schema_module = sys.modules.get(
            schema_name,
            self._missing_module,
        )
        if self._usrp_schema_module is self._missing_module:
            self._usrp_schema_uhd = self._missing_module
        else:
            self._usrp_schema_uhd = getattr(
                self._usrp_schema_module,
                "uhd",
                self._missing_module,
            )

    def tearDown(self):
        if self._uhd_module is self._missing_module:
            sys.modules.pop("uhd", None)
        else:
            sys.modules["uhd"] = self._uhd_module

        schema_name = "remoteRF_server.drivers.usrp.usrp_schema"
        package = sys.modules.get("remoteRF_server.drivers.usrp")
        if self._usrp_schema_module is self._missing_module:
            current = sys.modules.pop(schema_name, None)
            if (
                current is not None
                and package is not None
                and getattr(package, "usrp_schema", None) is current
            ):
                delattr(package, "usrp_schema")
        else:
            sys.modules[schema_name] = self._usrp_schema_module
            if package is not None:
                package.usrp_schema = self._usrp_schema_module
            if self._usrp_schema_uhd is self._missing_module:
                if hasattr(self._usrp_schema_module, "uhd"):
                    delattr(self._usrp_schema_module, "uhd")
            else:
                self._usrp_schema_module.uhd = self._usrp_schema_uhd

    def test_client_helper_namespace_matches_explicit_helpers(self):
        self.assertEqual(
            idl_client.ctor("uhd.types.TimeSpec", "$result"),
            idl_client_ctor("uhd.types.TimeSpec", "$result"),
        )
        self.assertEqual(
            idl_client.method("payload_as_payload"),
            idl_client_method("payload_as_payload"),
        )
        self.assertEqual(
            idl_client.module({"types": idl_client.namespace({})}),
            idl_client_module({"types": idl_client_namespace({})}),
        )

    def test_schema_includes_arg_metadata(self):
        schema = FakeSchema()
        idl = schema.get_idl()

        args = idl["calls"]["call_configure"]["args"]
        self.assertEqual([arg["name"] for arg in args], ["freq", "gain", "options"])
        self.assertEqual([arg["required"] for arg in args], [True, False, False])
        self.assertEqual([arg["type"] for arg in args], ["float", "int", "dict"])
        self.assertEqual(args[1]["default"], 0)
        self.assertIsNone(args[2]["default"])
        self.assertEqual(idl["setters"]["set_level"]["args"][0]["name"], "value")

        keyword_args = idl["calls"]["call_keyword"]["args"]
        self.assertEqual(
            [(arg["name"], arg["kind"], arg["required"]) for arg in keyword_args],
            [
                ("first", "positional_or_keyword", False),
                ("required", "keyword_only", True),
            ],
        )

    def test_dispatch_supports_defaults_dicts_and_legacy_value_alias(self):
        schema = FakeSchema()
        schema.bind({})

        self.assertEqual(schema.dispatch("call_ping", {}), "pong")
        self.assertEqual(schema.dispatch("call_echo", {"value": "hello"}), "hello")
        self.assertEqual(
            schema.dispatch(
                "call_configure",
                {"freq": 2.4e9, "options": {"mode": "fast"}},
            ),
            {"freq": 2.4e9, "gain": 0, "options": {"mode": "fast"}},
        )

        schema.dispatch("set_level", {"value": 7})
        self.assertEqual(schema.device["level"], 7)
        schema.dispatch("set_level", {"level": 8})
        self.assertEqual(schema.device["level"], 8)

    def test_dispatch_missing_required_arg_raises(self):
        schema = FakeSchema()
        schema.bind({})

        with self.assertRaisesRegex(TypeError, "missing required argument 'freq'"):
            schema.dispatch("call_configure", {"gain": 3})

    def test_schema_includes_client_object_metadata(self):
        schema = ClientMetadataSchema()
        idl = schema.get_idl()

        self.assertEqual(idl["client_class"], "MultiUSRP")
        self.assertNotIn("client_modules", idl)
        self.assertEqual(idl["client_objects"]["uhd"]["kind"], "module")
        self.assertIn("types", idl["client_objects"]["uhd"]["members"])
        self.assertEqual(
            idl["client_objects"]["uhd"]["bind_client_class_to"],
            "usrp",
        )
        self.assertEqual(
            idl["calls"]["call_get_time_now"]["client_return"],
            {
                "kind": "constructor",
                "target": "uhd.types.TimeSpec",
                "args": ["$result"],
            },
        )
        self.assertEqual(
            idl["calls"]["call_get_rx_stream"]["client_return"],
            {
                "kind": "constructor",
                "target": "uhd.RXStreamer",
                "args": ["$self", "$result"],
            },
        )

    def test_usrp_schema_declares_uhd_client_wrappers(self):
        sys.modules.setdefault("uhd", types.ModuleType("uhd"))

        from remoteRF_server.drivers.usrp.usrp_schema import UsrpSchema

        idl = UsrpSchema().get_idl()
        uhd_module = idl["client_objects"]["uhd"]
        uhd_members = uhd_module["members"]
        types_members = uhd_members["types"]["members"]
        usrp_members = uhd_members["usrp"]["members"]
        libpyuhd_types = uhd_members["libpyuhd"]["members"]["types"]["members"]

        self.assertEqual(idl["client_class"], "MultiUSRP")
        self.assertNotIn("client_modules", idl)
        self.assertEqual(uhd_module["kind"], "module")
        self.assertEqual(uhd_module["bind_client_class_to"], "usrp")
        self.assertEqual(
            set(uhd_module["exports"]),
            {
                "usrp",
                "types",
                "libpyuhd",
                "payload",
                "get_rx_stream",
                "get_tx_stream",
                "close_all_streams",
                "streamer",
                "RXStreamer",
                "TXStreamer",
            },
        )
        for name in [
            "payload",
            "get_rx_stream",
            "get_tx_stream",
            "close_all_streams",
            "streamer",
            "RXStreamer",
            "TXStreamer",
            "types",
            "usrp",
            "libpyuhd",
        ]:
            self.assertIn(name, uhd_members)
        for name in [
            "TimeSpec",
            "StreamCMD",
            "StreamMode",
            "RXMetadata",
            "TXMetadata",
            "RXMetadataErrorCode",
        ]:
            self.assertIn(name, types_members)
        self.assertIn("StreamArgs", usrp_members)
        self.assertIn("SubdevSpec", usrp_members)
        self.assertIn("tune_request", libpyuhd_types)
        self.assertEqual(
            idl["calls"]["call_get_time_now"]["client_return"]["target"],
            "uhd.types.TimeSpec",
        )
        self.assertEqual(
            idl["calls"]["call_get_rx_stream"]["client_return"],
            {
                "kind": "constructor",
                "target": "uhd.RXStreamer",
                "args": ["$self", "$result"],
            },
        )
        self.assertEqual(
            idl["calls"]["call_get_tx_stream"]["client_return"],
            {
                "kind": "constructor",
                "target": "uhd.TXStreamer",
                "args": ["$self", "$result"],
            },
        )

    def test_usrp_schema_reconstructs_generated_uhd_payloads(self):
        fake_uhd = types.ModuleType("uhd")

        class TimeSpec:
            def __init__(self, secs=0.0):
                self.secs = float(secs)

            def get_real_secs(self):
                return self.secs

        class StreamArgs:
            def __init__(self, cpu_format, otw_format):
                self.cpu_format = cpu_format
                self.otw_format = otw_format
                self.channels = []
                self.args = ""

        class SubdevSpec:
            def __init__(self, spec):
                self.spec = spec

        class DeviceAddr:
            def __init__(self, value=""):
                self.value = value

        class TuneRequestPolicy:
            AUTO = object()
            MANUAL = object()
            NONE = object()

        class TuneRequest:
            # As UHD's tune_request_t(target, lo_off): an offset places the
            # RF LO manually at target + offset.
            def __init__(self, target_freq=0.0, lo_off=None):
                self.target_freq = float(target_freq)
                self.rf_freq = 0.0 if lo_off is None else float(target_freq) + float(lo_off)
                self.dsp_freq = 0.0
                self.rf_freq_policy = TuneRequestPolicy.AUTO if lo_off is None else TuneRequestPolicy.MANUAL
                self.dsp_freq_policy = TuneRequestPolicy.AUTO
                self.args = DeviceAddr()

        class MultiUSRP:
            def __init__(self, args):
                self.args = args

        class TXMetadata:
            def __init__(self):
                self.has_time_spec = False
                self.time_spec = None
                self.end_of_burst = False

        class StreamCMD:
            def __init__(self, mode):
                self.mode = mode
                self.stream_now = True
                self.time_spec = None
                self.num_samps = None

        fake_uhd.types = types.SimpleNamespace(
            TimeSpec=TimeSpec,
            DeviceAddr=DeviceAddr,
            TuneRequest=TuneRequest,
            TuneRequestPolicy=TuneRequestPolicy,
            TXMetadata=TXMetadata,
            StreamCMD=StreamCMD,
            StreamMode=types.SimpleNamespace(
                num_done="num_done",
                num_more="num_more",
                stop_cont="stop_cont",
                start_cont="start_cont",
            ),
        )
        fake_uhd.usrp = types.SimpleNamespace(
            MultiUSRP=MultiUSRP,
            StreamArgs=StreamArgs,
            SubdevSpec=SubdevSpec,
        )
        fake_uhd.libpyuhd = types.SimpleNamespace(
            types=types.SimpleNamespace(
                tune_request=lambda *args, **kwargs: {
                    "args": args,
                    "kwargs": kwargs,
                }
            )
        )
        sys.modules["uhd"] = fake_uhd

        from remoteRF_server.drivers.usrp import usrp_schema

        usrp_schema.uhd = fake_uhd

        device = usrp_schema._connect_usrp(serial="31A2B3C")
        self.assertEqual(
            device.args,
            "type=b200,serial=31A2B3C,num_recv_frames=256",
        )
        device = usrp_schema._connect_usrp(addr="192.168.137.21")
        self.assertEqual(
            device.args,
            "type=usrp2,addr=192.168.137.21,num_recv_frames=256",
        )
        device = usrp_schema._connect_usrp(
            type="usrp2",
            addr="192.168.137.21",
        )
        self.assertEqual(
            device.args,
            "type=usrp2,addr=192.168.137.21,num_recv_frames=256",
        )
        device = usrp_schema._connect_usrp(
            profile="x310",
            addr="192.168.10.2",
        )
        self.assertEqual(
            device.args,
            "type=x300,addr=192.168.10.2,num_recv_frames=256",
        )
        with self.assertRaisesRegex(ValueError, "requires UHD type"):
            usrp_schema._connect_usrp(
                profile="n210",
                type="b200",
                addr="192.168.137.21",
            )
        device = usrp_schema._connect_usrp(
            profile="e320",
            args="addr=192.168.20.2",
        )
        self.assertEqual(
            device.args,
            "type=e3xx,addr=192.168.20.2,num_recv_frames=256",
        )
        device = usrp_schema._connect_usrp(
            args="type=b200,serial=31A2B3C,num_recv_frames=64"
        )
        self.assertEqual(
            device.args,
            "type=b200,serial=31A2B3C,num_recv_frames=64",
        )
        with patch.dict(
            os.environ,
            {"REMOTERF_USRP_NUM_RECV_FRAMES": "128"},
        ):
            device = usrp_schema._connect_usrp(serial="31A2B3C")
        self.assertEqual(
            device.args,
            "type=b200,serial=31A2B3C,num_recv_frames=128",
        )
        with patch.dict(
            os.environ,
            {"REMOTERF_USRP_NUM_RECV_FRAMES": "invalid"},
        ):
            with self.assertRaisesRegex(
                ValueError,
                "REMOTERF_USRP_NUM_RECV_FRAMES",
            ):
                usrp_schema._connect_usrp(serial="31A2B3C")

        time_spec = usrp_schema._construct({"__uhd_type__": "TimeSpec", "secs": 3.25})
        self.assertIsInstance(time_spec, TimeSpec)
        self.assertEqual(time_spec.get_real_secs(), 3.25)

        stream_args = usrp_schema._construct({
            "__uhd_type__": "StreamArgs",
            "cpu_format": "fc32",
            "otw_format": "sc16",
            "args": {"spp": 256},
            "channels": [0, 1],
        })
        self.assertIsInstance(stream_args, StreamArgs)
        self.assertEqual(stream_args.args, "spp=256")
        self.assertEqual(stream_args.channels, [0, 1])

        empty_v2_stream_args = usrp_schema._construct({
            "__uhd_type__": "StreamArgs",
            "cpu_format": "fc32",
            "otw_format": "sc16",
            "args": {
                "__uhd_type__": "DeviceAddr",
                "items": {},
            },
            "channels": [0],
        })
        self.assertIsInstance(empty_v2_stream_args.args, DeviceAddr)
        self.assertEqual(empty_v2_stream_args.args.value, "")

        populated_v2_stream_args = usrp_schema._construct({
            "__uhd_type__": "StreamArgs",
            "cpu_format": "fc32",
            "otw_format": "sc16",
            "args": {
                "__uhd_type__": "DeviceAddr",
                "items": {"spp": "512"},
            },
            "channels": [0, 1],
        })
        self.assertIsInstance(populated_v2_stream_args.args, DeviceAddr)
        self.assertEqual(populated_v2_stream_args.args.value, "spp=512")
        self.assertEqual(populated_v2_stream_args.channels, [0, 1])

        stream_cmd = usrp_schema._construct({
            "__uhd_type__": "StreamCMD",
            "mode": "num_done",
            "stream_now": False,
            "time_spec": {"__uhd_type__": "TimeSpec", "secs": 1.5},
            "num_samps": 64,
        })
        self.assertIsInstance(stream_cmd, StreamCMD)
        self.assertEqual(stream_cmd.mode, "num_done")
        self.assertFalse(stream_cmd.stream_now)
        self.assertIsInstance(stream_cmd.time_spec, TimeSpec)
        self.assertEqual(stream_cmd.num_samps, 64)

        tx_metadata = usrp_schema._construct({
            "__uhd_type__": "TXMetadata",
            "has_time_spec": True,
            "time_spec": {"__uhd_type__": "TimeSpec", "secs": 2.0},
            "end_of_burst": True,
        })
        self.assertIsInstance(tx_metadata, TXMetadata)
        self.assertTrue(tx_metadata.has_time_spec)
        self.assertIsInstance(tx_metadata.time_spec, TimeSpec)
        self.assertTrue(tx_metadata.end_of_burst)

        tune = usrp_schema._construct({
            "__uhd_type__": "TuneRequest",
            "args": [915e6],
            "kwargs": {},
        })
        self.assertIsInstance(tune, TuneRequest)
        self.assertEqual(tune.target_freq, 915e6)

        tune = usrp_schema._construct({
            "__uhd_type__": "TuneRequest",
            "target_freq": 100e6,
            "lo_offset": None,
            "rf_freq": 99e6,
            "dsp_freq": 1e6,
            "rf_freq_policy": "MANUAL",
            "dsp_freq_policy": "AUTO",
            "args": {
                "__uhd_type__": "DeviceAddr",
                "items": {"mode_n": "integer"},
            },
        })
        self.assertIsInstance(tune, TuneRequest)
        self.assertEqual(tune.target_freq, 100e6)
        self.assertEqual(tune.rf_freq, 99e6)
        self.assertEqual(tune.dsp_freq, 1e6)
        self.assertIs(tune.rf_freq_policy, TuneRequestPolicy.MANUAL)
        self.assertIs(tune.dsp_freq_policy, TuneRequestPolicy.AUTO)
        self.assertIsInstance(tune.args, DeviceAddr)
        self.assertEqual(tune.args.value, "mode_n=integer")

        def offset_tune(**rf):
            return usrp_schema._construct({
                "__uhd_type__": "TuneRequest", "target_freq": 915e6, "lo_offset": 5e6,
                "dsp_freq": 0.0, "dsp_freq_policy": "AUTO",
                "args": {"__uhd_type__": "DeviceAddr", "items": {}}, **rf,
            })

        # An older Client's TuneRequest(f, lo) sends AUTO / 0.0 RF defaults
        # next to the offset: the manual f + lo survives them.
        tune = offset_tune(rf_freq=0.0, rf_freq_policy="AUTO")
        self.assertIs(tune.rf_freq_policy, TuneRequestPolicy.MANUAL)
        self.assertEqual(tune.rf_freq, 920e6)
        # A current Client sends UHD's own state; an explicit RF choice wins.
        self.assertEqual(offset_tune(rf_freq=920e6, rf_freq_policy="MANUAL").rf_freq, 920e6)
        self.assertEqual(offset_tune(rf_freq=921e6, rf_freq_policy="MANUAL").rf_freq, 921e6)

        subdev = usrp_schema._construct({"__uhd_type__": "SubdevSpec", "spec": "A:0"})
        self.assertIsInstance(subdev, SubdevSpec)
        self.assertEqual(subdev.spec, "A:0")

        with self.assertRaisesRegex(ValueError, "Unsupported StreamCMD mode"):
            usrp_schema._construct({
                "__uhd_type__": "StreamCMD",
                "mode": "not_a_mode",
            })

    def test_usrp_capabilities_runtime_probe_rx_otw_formats_once(self):
        from remoteRF_server.drivers.usrp import usrp_schema

        class StreamArgs:
            def __init__(self, cpu_format, otw_format):
                self.cpu_format = cpu_format
                self.otw_format = otw_format
                self.channels = []

        class Streamer:
            def __init__(self, max_num_samps):
                self.max_num_samps = max_num_samps

            def get_max_num_samps(self):
                return self.max_num_samps

        class Device:
            def __init__(self):
                self.rx_stream_requests = []

            def get_rx_num_channels(self):
                return 1

            def get_tx_num_channels(self):
                return 1

            def get_usrp_rx_info(self, chan):
                return {
                    "mboard_name": "N210",
                    "mboard_id": "N210r4",
                    "mboard_serial": "30FB628",
                }

            def get_usrp_tx_info(self, chan):
                return self.get_usrp_rx_info(chan)

            def get_rx_stream(self, stream_args):
                request = (
                    stream_args.cpu_format,
                    stream_args.otw_format,
                    tuple(stream_args.channels),
                )
                self.rx_stream_requests.append(request)
                if stream_args.otw_format == "sc12":
                    raise RuntimeError(
                        "USRP RX cannot handle requested wire format: sc12"
                    )
                return Streamer(
                    726 if stream_args.otw_format == "sc8" else 363
                )

        fake_uhd = types.SimpleNamespace(
            usrp=types.SimpleNamespace(StreamArgs=StreamArgs),
            get_version_string=lambda: "4.10.0.0",
            get_abi_string=lambda: "test-abi",
        )
        usrp_schema.uhd = fake_uhd
        device = Device()
        schema = usrp_schema.UsrpSchema()
        schema.bind_inventory({"type": "usrp2", "addr": "192.168.137.21"})
        schema.bind(device)

        capabilities = schema.build_session_metadata_v2()
        self.assertEqual(capabilities["hardware_profile"], "n210")
        self.assertEqual(
            capabilities["device_profile"]["support_level"],
            "qualified_native",
        )
        self.assertEqual(
            capabilities["profile_resolution"]["source"],
            "native_identity",
        )
        probe = capabilities["stream_format_capabilities"]
        self.assertEqual(probe["rx"]["status"], "runtime_probed")
        self.assertTrue(probe["rx"]["default"]["supported"])
        self.assertEqual(probe["rx"]["default"]["max_num_samps"], 363)
        self.assertEqual(
            {
                item["otw_format"]: item["supported"]
                for item in probe["rx"]["formats"]
            },
            {"sc16": True, "sc12": False, "sc8": True},
        )
        self.assertEqual(capabilities["supported_otw_formats"], ["sc16", "sc8"])
        self.assertEqual(probe["tx"]["status"], "not_probed")
        self.assertEqual(
            device.rx_stream_requests,
            [
                ("fc32", "", (0,)),
                ("fc32", "sc16", (0,)),
                ("fc32", "sc12", (0,)),
                ("fc32", "sc8", (0,)),
            ],
        )

        self.assertEqual(schema.build_session_metadata_v2(), capabilities)
        self.assertEqual(len(device.rx_stream_requests), 4)
        self.assertFalse(hasattr(schema, "_usrp_streamers"))

    def test_b205mini_capabilities_use_live_single_channel_identity(self):
        from remoteRF_server.drivers.usrp import usrp_schema

        class Property:
            def __init__(self, value):
                self.value = value

            def get(self):
                return self.value

        class Tree:
            values = {
                "/mboards/0/fw_version": "8.0",
                "/mboards/0/fpga_version": "7.0",
                "/mboards/0/usb_version": "3",
            }

            def access_str(self, path):
                if path not in self.values:
                    raise KeyError(path)
                return Property(self.values[path])

        class Device:
            def get_rx_num_channels(self):
                return 1

            def get_tx_num_channels(self):
                return 1

            def get_usrp_rx_info(self, chan):
                return {
                    "mboard_name": "B205mini",
                    "mboard_id": "B205mini",
                    "mboard_serial": "31E9F48",
                }

            def get_usrp_tx_info(self, chan):
                return self.get_usrp_rx_info(chan)

            def get_tree(self):
                return Tree()

        fake_uhd = types.SimpleNamespace(
            get_version_string=lambda: "4.10.0.0",
            get_abi_string=lambda: "test-abi",
        )
        schema = usrp_schema.UsrpSchema()
        schema.bind_inventory({
            "profile": "b205mini",
            "type": "b200",
            "serial": "31E9F48",
        })
        schema.bind(Device())

        with (
            patch.object(usrp_schema, "uhd", fake_uhd),
            patch.dict(
                os.environ,
                {"REMOTERF_USRP_PROBE_RX_OTW_FORMATS": "0"},
                clear=False,
            ),
        ):
            capabilities = schema.build_session_metadata_v2()

        self.assertEqual(capabilities["hardware_profile"], "b205mini")
        self.assertEqual(capabilities["native_name"], "B205mini")
        self.assertEqual(capabilities["native_product"], "B205mini")
        self.assertEqual(capabilities["native_serial"], "31E9F48")
        self.assertEqual(capabilities["rx_channel_count"], 1)
        self.assertEqual(capabilities["tx_channel_count"], 1)
        self.assertEqual(capabilities["transport_type"], "usb")
        self.assertEqual(capabilities["usb_speed"], "3")
        self.assertEqual(capabilities["firmware_version"], "8.0")
        self.assertEqual(capabilities["fpga_version"], "7.0")
        self.assertEqual(
            capabilities["device_profile"]["support_level"],
            "qualified_native",
        )
        self.assertTrue(
            capabilities["profile_resolution"]["requested_profile_matches"]
        )
        self.assertEqual(
            capabilities["stream_format_capabilities"]["rx"]["status"],
            "disabled",
        )

    def test_usrp_runtime_otw_probe_can_be_disabled(self):
        from remoteRF_server.drivers.usrp import usrp_schema

        class Device:
            def get_rx_num_channels(self):
                return 1

            def get_tx_num_channels(self):
                return 0

            def get_usrp_rx_info(self, chan):
                return {"mboard_name": "test", "mboard_id": "test"}

            def get_rx_stream(self, stream_args):
                raise AssertionError("disabled probe must not create a streamer")

        usrp_schema.uhd = types.SimpleNamespace(
            usrp=types.SimpleNamespace(StreamArgs=object),
            get_version_string=lambda: "4.10.0.0",
            get_abi_string=lambda: "test-abi",
        )
        schema = usrp_schema.UsrpSchema()
        schema.bind(Device())

        with patch.dict(
            os.environ,
            {"REMOTERF_USRP_PROBE_RX_OTW_FORMATS": "0"},
        ):
            capabilities = schema.build_session_metadata_v2()

        probe = capabilities["stream_format_capabilities"]["rx"]
        self.assertEqual(probe["status"], "disabled")
        self.assertEqual(capabilities["supported_otw_formats"], [])

    def test_usrp_streamer_lifecycle_uses_server_handles(self):
        fake_uhd = types.ModuleType("uhd")

        class TimeSpec:
            def __init__(self, secs=0.0):
                self.secs = float(secs)

            def get_real_secs(self):
                return self.secs

        class RXMetadata:
            def __init__(self):
                self.error_code = "none"
                self.time_spec = TimeSpec(0.0)
                self.out_of_sequence = False
                self.fragment_offset = 0
                self.more_fragments = False

        class TXMetadata:
            def __init__(self):
                self.has_time_spec = False
                self.time_spec = None
                self.end_of_burst = False

        class StreamCMD:
            def __init__(self, mode):
                self.mode = mode
                self.stream_now = True
                self.time_spec = None
                self.num_samps = None

        class StreamArgs:
            def __init__(self, cpu_format, otw_format):
                self.cpu_format = cpu_format
                self.otw_format = otw_format
                self.args = ""
                self.channels = []

        class FakeRXStreamer:
            def __init__(self):
                self.commands = []

            def get_max_num_samps(self):
                return 4

            def issue_stream_cmd(self, cmd):
                self.commands.append(cmd)

            def recv(self, recv_buffer, metadata, timeout):
                recv_buffer[...] = np.array([3 + 0j, 4 + 0j], dtype=recv_buffer.dtype)
                metadata.time_spec = TimeSpec(6.5)
                metadata.error_code = "none"
                return len(recv_buffer)

        class FakeTXStreamer:
            def __init__(self):
                self.sent = None

            def send(self, samples, metadata, timeout):
                self.sent = (samples, metadata, timeout)
                return len(samples)

        class FakeDevice:
            def __init__(self):
                self.rx_streamer = FakeRXStreamer()
                self.tx_streamer = FakeTXStreamer()
                self.rx_arg = None
                self.tx_arg = None

            def get_rx_stream(self, stream_args):
                self.rx_arg = stream_args
                return self.rx_streamer

            def get_tx_stream(self, stream_args):
                self.tx_arg = stream_args
                return self.tx_streamer

        fake_uhd.types = types.SimpleNamespace(
            TimeSpec=TimeSpec,
            RXMetadata=RXMetadata,
            TXMetadata=TXMetadata,
            StreamCMD=StreamCMD,
            StreamMode=types.SimpleNamespace(
                num_done="num_done",
                num_more="num_more",
                stop_cont="stop_cont",
                start_cont="start_cont",
            ),
        )
        fake_uhd.usrp = types.SimpleNamespace(StreamArgs=StreamArgs)
        sys.modules["uhd"] = fake_uhd

        from remoteRF_server.drivers.usrp import usrp_schema

        usrp_schema.uhd = fake_uhd
        device = FakeDevice()
        schema = usrp_schema.UsrpSchema()
        schema.bind(device)

        stream_args_payload = {
            "__uhd_type__": "StreamArgs",
            "cpu_format": "fc32",
            "otw_format": "sc16",
            "args": {"spp": 128},
            "channels": [0],
        }
        rx_payload = schema.call_get_rx_stream(stream_args_payload)
        tx_payload = schema.call_get_tx_stream(stream_args_payload)

        self.assertEqual(rx_payload, {"__uhd_type__": "RXStreamer", "handle": "rx:1"})
        self.assertEqual(tx_payload, {"__uhd_type__": "TXStreamer", "handle": "tx:2"})
        self.assertEqual(device.rx_arg.args, "spp=128")
        self.assertEqual(device.rx_arg.channels, [0])
        self.assertEqual(schema.call_stream_get_max_num_samps(rx_payload), 4)

        schema.call_stream_issue_stream_cmd({
            "handle": rx_payload["handle"],
            "stream_cmd": {
                "__uhd_type__": "StreamCMD",
                "mode": "num_done",
                "stream_now": False,
                "time_spec": {"__uhd_type__": "TimeSpec", "secs": 1.25},
                "num_samps": 2,
            },
        })
        command = device.rx_streamer.commands[0]
        self.assertIsInstance(command, StreamCMD)
        self.assertEqual(command.mode, "num_done")
        self.assertFalse(command.stream_now)
        self.assertEqual(command.time_spec.get_real_secs(), 1.25)
        self.assertEqual(command.num_samps, 2)

        recv_buffer = np.zeros(2, dtype=np.complex64)
        count, returned_buffer, metadata = schema.call_stream_recv({
            "handle": rx_payload["handle"],
            "recv_buffer": recv_buffer,
            "timeout": 0.25,
        })
        self.assertEqual(count, 2)
        np.testing.assert_allclose(returned_buffer, np.array([3 + 0j, 4 + 0j]))
        self.assertEqual(metadata["time_spec"], {"__uhd_type__": "TimeSpec", "secs": 6.5})

        samples = np.array([1 + 0j, 2 + 0j, 3 + 0j], dtype=np.complex64)
        sent = schema.call_stream_send({
            "handle": tx_payload["handle"],
            "samples": samples,
            "metadata": {
                "__uhd_type__": "TXMetadata",
                "has_time_spec": True,
                "time_spec": {"__uhd_type__": "TimeSpec", "secs": 2.5},
                "end_of_burst": True,
            },
            "timeout": 0.5,
        })
        self.assertEqual(sent, 3)
        sent_samples, sent_metadata, sent_timeout = device.tx_streamer.sent
        np.testing.assert_allclose(sent_samples, samples)
        self.assertIsInstance(sent_metadata, TXMetadata)
        self.assertTrue(sent_metadata.has_time_spec)
        self.assertEqual(sent_metadata.time_spec.get_real_secs(), 2.5)
        self.assertTrue(sent_metadata.end_of_burst)
        self.assertEqual(sent_timeout, 0.5)

        schema.call_stream_close(rx_payload["handle"])
        with self.assertRaisesRegex(KeyError, "Unknown USRP streamer handle"):
            schema.call_stream_get_max_num_samps(rx_payload["handle"])
        self.assertEqual(schema.call_close_all_streams(), 1)
        self.assertEqual(schema.call_close_all_streams(), 0)

    def test_client_constructor_metadata_rejects_ambiguous_or_unsafe_shapes(self):
        with self.assertRaisesRegex(ValueError, "dotted identifier"):
            idl_client_ctor("uhd.types.Bad-Name", "$result")

        with self.assertRaisesRegex(ValueError, "unsupported sentinel"):
            idl_client_ctor("uhd.types.TimeSpec", "$device")

        with self.assertRaisesRegex(ValueError, "exactly"):
            idl_client_ctor("uhd.types.TimeSpec", {"value": 1})

        with self.assertRaisesRegex(TypeError, "JSON serializable"):
            idl_client_ctor("uhd.types.TimeSpec", {"const": object()})

        with self.assertRaisesRegex(ValueError, r"'\$self'.*'\$result'"):
            idl_client_ctor("uhd.types.TimeSpec", "implicit-constant")

    def test_invalid_client_schema_metadata_fails_before_publishing_idl(self):
        with self.assertRaisesRegex(ValueError, "kind"):
            @idl_expose(kind="wat")
            def invalid_kind(self):
                return None

        with self.assertRaisesRegex(ValueError, "getters and calls"):
            @idl_expose(
                kind="set",
                client_return=idl_client_ctor("uhd.types.TimeSpec", "$result"),
            )
            def invalid_setter_return(self, value):
                return None

        class BadClientClass(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_class = "Bad Class"

        with self.assertRaisesRegex(ValueError, "client_class"):
            BadClientClass().get_idl()

        class BadClientModules(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_modules = {"not-valid": "remoteRF.drivers.support.uhd"}

        with self.assertRaisesRegex(ValueError, "alias"):
            BadClientModules().get_idl()

        class BadClientModulePath(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_modules = {"uhd": "os"}

        with self.assertRaisesRegex(TypeError, "remoteRF.drivers.support"):
            BadClientModulePath().get_idl()

        class DuplicateClientRoots(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_modules = {"uhd": "remoteRF.drivers.support.uhd"}
            client_objects = {
                "uhd": idl_client_module({"types": idl_client_namespace({})})
            }

        with self.assertRaisesRegex(ValueError, "duplicates"):
            DuplicateClientRoots().get_idl()

        class BadClientObjectTemplate(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_objects = {
                "x": {
                    "kind": "module",
                    "members": {
                        "Thing": {
                            "kind": "payload_class",
                            "payload_type": "Thing",
                            "fields": [{"name": "value"}],
                            "init": {"template": "unknown"},
                        },
                    },
                },
            }

        with self.assertRaisesRegex(ValueError, "unknown template"):
            BadClientObjectTemplate().get_idl()

        class BadClientObjectField(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_objects = {
                "x": {
                    "kind": "module",
                    "members": {
                        "Thing": {
                            "kind": "payload_class",
                            "payload_type": "Thing",
                            "fields": [{"name": "bad-name"}],
                        },
                    },
                },
            }

        with self.assertRaisesRegex(ValueError, "invalid name"):
            BadClientObjectField().get_idl()

        class BadClientObjectDefault(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_objects = {
                "x": {
                    "kind": "module",
                    "members": {
                        "Thing": {
                            "kind": "payload_class",
                            "payload_type": "Thing",
                            "fields": [{"name": "value", "default": object()}],
                        },
                    },
                },
            }

        with self.assertRaisesRegex(TypeError, "JSON serializable"):
            BadClientObjectDefault().get_idl()

        class BadClientReturn(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"

            @idl_expose(kind="call", client_return={"kind": "eval", "target": "x", "args": []})
            def call_thing(self):
                return None

        with self.assertRaisesRegex(ValueError, "kind"):
            BadClientReturn().get_idl()

        class MissingClientReturnRoot(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"

            @idl_expose(
                kind="call",
                client_return=idl_client_ctor("uhd.types.TimeSpec", "$result"),
            )
            def call_thing(self):
                return {"secs": 0.0}

        with self.assertRaisesRegex(ValueError, "not declared"):
            MissingClientReturnRoot().get_idl()

        class NestedClientModule(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_objects = {
                "x": idl_client_module({
                    "nested": idl_client_module({}),
                }),
            }

        with self.assertRaisesRegex(ValueError, "nested client module"):
            NestedClientModule().get_idl()

        class DuplicateGeneratedClientName(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_objects = {
                "x": idl_client_module({
                    "first": idl_client_namespace({
                        "Thing": idl_client_payload_class("Thing", ["value"]),
                    }),
                    "second": idl_client_namespace({
                        "Thing": idl_client_proxy_class(["handle"]),
                    }),
                }),
            }

        with self.assertRaisesRegex(ValueError, "duplicates generated"):
            DuplicateGeneratedClientName().get_idl()

        class MissingBindPath(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_objects = {
                "x": idl_client_module({}, bind_client_class_to="missing"),
            }

        with self.assertRaisesRegex(ValueError, "unknown member"):
            MissingBindPath().get_idl()

        class NonNamespaceBindPath(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_objects = {
                "x": idl_client_module(
                    {"Thing": idl_client_payload_class("Thing", ["value"])},
                    bind_client_class_to="Thing",
                ),
            }

        with self.assertRaisesRegex(ValueError, "client namespace"):
            NonNamespaceBindPath().get_idl()


if __name__ == "__main__":
    unittest.main()
