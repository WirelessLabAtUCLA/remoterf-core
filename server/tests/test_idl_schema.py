import unittest

from remoteRF_server.common.idl.schema import DeviceSchema, idl_expose


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


class DeviceSchemaTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
