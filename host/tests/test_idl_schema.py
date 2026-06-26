from __future__ import annotations

import unittest

from remoteRF_host.common.idl import DeviceSchema, idl_expose, idl_register


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


if __name__ == "__main__":
    unittest.main()
