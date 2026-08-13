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

from remoteRF_host.common.idl import (
    DeviceSchema,
    idl_client,
    idl_client_ctor,
    idl_client_enum,
    idl_client_function,
    idl_client_method,
    idl_client_module,
    idl_client_namespace,
    idl_client_payload_class,
    idl_client_proxy_class,
    idl_client_strict_class,
    idl_expose,
    idl_register,
    install_server_import_compat,
)


@idl_register("test_device")
class FakeSchema(DeviceSchema):
    device_type = "test_device"
    driver_version = "1.2.3"

    @idl_expose(kind="get")
    def get_status(self):
        return "ok"

    @idl_expose(kind="set")
    def set_gain(self, gain: int = 0):
        self.gain = gain

    @idl_expose(kind="call")
    def call_ping(self):
        return "pong"

    @idl_expose(kind="call")
    def call_echo(self, payload):
        return payload

    @idl_expose(kind="call")
    def call_configure(self, freq: float, gain: int = 0, options: dict = None):
        return {
            "freq": freq,
            "gain": gain,
            "options": options,
        }

    @idl_expose(kind="call")
    def call_keyword(self, value, *, mode: str = "fast"):
        return f"{value}:{mode}"


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
    def setUp(self) -> None:
        self.schema = FakeSchema()
        self.schema.bind(object())

    def test_schema_includes_arg_metadata(self) -> None:
        idl = self.schema.get_idl()
        args = idl["calls"]["call_configure"]["args"]

        self.assertEqual(
            args,
            [
                {
                    "name": "freq",
                    "required": True,
                    "type": "float",
                    "kind": "positional_or_keyword",
                },
                {
                    "name": "gain",
                    "required": False,
                    "type": "int",
                    "kind": "positional_or_keyword",
                    "default": 0,
                },
                {
                    "name": "options",
                    "required": False,
                    "type": "dict",
                    "kind": "positional_or_keyword",
                    "default": None,
                },
            ],
        )
        self.assertEqual(
            idl["calls"]["call_keyword"]["args"][1],
            {
                "name": "mode",
                "required": False,
                "type": "str",
                "kind": "keyword_only",
                "default": "fast",
            },
        )
        self.assertEqual(idl["setters"]["set_gain"]["args"][0]["name"], "gain")

    def test_legacy_schema_does_not_emit_client_object_metadata(self) -> None:
        idl = self.schema.get_idl()

        self.assertNotIn("client_class", idl)
        self.assertNotIn("client_modules", idl)
        self.assertNotIn("client_objects", idl)
        for section_name in ("getters", "setters", "calls"):
            for entry in idl[section_name].values():
                self.assertNotIn("client_return", entry)

    def test_client_helper_namespace_matches_explicit_helpers(self) -> None:
        self.assertEqual(
            idl_client.ctor("uhd.types.TimeSpec", "$result"),
            idl_client_ctor("uhd.types.TimeSpec", "$result"),
        )
        self.assertEqual(
            idl_client.enum(["start_cont", "stop_cont"]),
            idl_client_enum(["start_cont", "stop_cont"]),
        )
        self.assertEqual(
            idl_client.function("uhd_payload"),
            idl_client_function("uhd_payload"),
        )
        self.assertEqual(
            idl_client.method("payload_as_payload"),
            idl_client_method("payload_as_payload"),
        )
        self.assertEqual(
            idl_client.module({"types": idl_client.namespace({})}),
            idl_client_module({"types": idl_client_namespace({})}),
        )
        self.assertEqual(
            idl_client.strict_class(["value"]),
            idl_client_strict_class(["value"]),
        )

    def test_server_import_compat_exports_client_helpers(self) -> None:
        install_server_import_compat()

        from remoteRF_server.common.idl import (
            DeviceSchema as ServerDeviceSchema,
            idl_client as server_idl_client,
            idl_expose as server_idl_expose,
            idl_register as server_idl_register,
        )

        self.assertIs(ServerDeviceSchema, DeviceSchema)
        self.assertIs(server_idl_client.ctor, idl_client.ctor)

        @server_idl_register("compat_client_objects")
        class CompatClientObjectsSchema(ServerDeviceSchema):
            device_type = "compat_client_objects"
            driver_version = "0.0.0"
            client_class = "MultiUSRP"
            client_objects = {
                "uhd": server_idl_client.module(
                    {
                        "types": server_idl_client.namespace(
                            {
                                "TimeSpec": server_idl_client.payload_class(
                                    "TimeSpec",
                                    {"secs": {"default": 0.0}},
                                    init="timespec",
                                ),
                            }
                        ),
                        "usrp": server_idl_client.namespace({}),
                    },
                    bind_client_class_to="usrp",
                ),
            }

            @server_idl_expose(
                kind="call",
                client_return=server_idl_client.ctor("uhd.types.TimeSpec", "$result"),
            )
            def call_get_time_now(self):
                return {"secs": 1.0}

        idl = CompatClientObjectsSchema().get_idl()
        self.assertEqual(idl["client_class"], "MultiUSRP")
        self.assertIn("uhd", idl["client_objects"])
        self.assertEqual(
            idl["calls"]["call_get_time_now"]["client_return"]["target"],
            "uhd.types.TimeSpec",
        )

    def test_schema_includes_client_object_metadata(self) -> None:
        idl = ClientMetadataSchema().get_idl()

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

    def test_getter_client_return_metadata_is_supported(self) -> None:
        class GetterReturnSchema(DeviceSchema):
            device_type = "getter_return"
            driver_version = "0.0.0"
            client_objects = {
                "uhd": idl_client_module(
                    {
                        "types": idl_client_namespace(
                            {
                                "TimeSpec": idl_client_payload_class(
                                    "TimeSpec",
                                    {"secs": {"default": 0.0}},
                                ),
                            }
                        ),
                    },
                ),
            }

            @idl_expose(
                kind="get",
                client_return=idl_client_ctor("uhd.types.TimeSpec", "$result"),
            )
            def get_time(self):
                return {"secs": 1.0}

        idl = GetterReturnSchema().get_idl()
        self.assertNotIn("args", idl["getters"]["get_time"])
        self.assertEqual(
            idl["getters"]["get_time"]["client_return"],
            {
                "kind": "constructor",
                "target": "uhd.types.TimeSpec",
                "args": ["$result"],
            },
        )

    def test_legacy_client_modules_remain_supported_without_client_objects(self) -> None:
        class LegacyClientModuleSchema(DeviceSchema):
            device_type = "legacy_client_module"
            driver_version = "0.0.0"
            client_modules = {"uhd": "remoteRF.drivers.support.uhd"}

            @idl_expose(
                kind="call",
                client_return=idl_client_ctor("uhd.types.TimeSpec", "$result"),
            )
            def call_get_time_now(self):
                return {"secs": 1.0}

        idl = LegacyClientModuleSchema().get_idl()
        self.assertEqual(
            idl["client_modules"],
            {"uhd": "remoteRF.drivers.support.uhd"},
        )
        self.assertNotIn("client_objects", idl)
        self.assertEqual(
            idl["calls"]["call_get_time_now"]["client_return"]["target"],
            "uhd.types.TimeSpec",
        )

    def test_capability_string_uses_calln_for_named_or_optional_args(self) -> None:
        caps = self.schema.get_capabilities()
        self.assertEqual(caps["ping"], "call0")
        self.assertEqual(caps["echo"], "call1")
        self.assertEqual(caps["configure"], "calln")
        self.assertEqual(caps["keyword"], "calln")

    def test_dispatch_applies_defaults_and_named_args(self) -> None:
        self.assertEqual(self.schema.dispatch("call_ping", {}), "pong")
        self.assertEqual(self.schema.dispatch("call_echo", {"value": {"a": 1}}), {"a": 1})
        self.assertEqual(
            self.schema.dispatch("call_configure", {"freq": 2.4e9}),
            {"freq": 2.4e9, "gain": 0, "options": None},
        )
        self.assertEqual(
            self.schema.dispatch(
                "call_configure",
                {"freq": 2.4e9, "gain": 10, "options": {"agc": False}},
            ),
            {"freq": 2.4e9, "gain": 10, "options": {"agc": False}},
        )
        self.assertEqual(self.schema.dispatch("call_keyword", {"value": 5}), "5:fast")
        self.assertEqual(self.schema.dispatch("call_keyword", {"value": 5, "mode": "slow"}), "5:slow")

    def test_dispatch_reports_missing_required_args(self) -> None:
        with self.assertRaisesRegex(TypeError, "missing required argument 'freq'"):
            self.schema.dispatch("call_configure", {"gain": 1})

    def test_setter_preserves_legacy_first_arg_fallback(self) -> None:
        self.schema.dispatch("set_gain", {"set_gain": 12})
        self.assertEqual(self.schema.gain, 12)

    def test_unsupported_varargs_fail_during_schema_build(self) -> None:
        class BadSchema(DeviceSchema):
            device_type = "bad"
            driver_version = "0"

            @idl_expose(kind="call")
            def call_bad(self, *values):
                return values

        bad = BadSchema()
        with self.assertRaisesRegex(TypeError, "cannot be exposed"):
            bad.get_idl()

    def test_client_constructor_metadata_rejects_ambiguous_or_unsafe_shapes(self) -> None:
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

    def test_invalid_client_schema_metadata_fails_before_publishing_idl(self) -> None:
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

        class BadClientObjectExport(DeviceSchema):
            device_type = "bad"
            driver_version = "0.0.0"
            client_objects = {
                "x": idl_client_module(
                    {"types": idl_client_namespace({})},
                    exports=["missing"],
                )
            }

        with self.assertRaisesRegex(ValueError, "unknown member"):
            BadClientObjectExport().get_idl()

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
