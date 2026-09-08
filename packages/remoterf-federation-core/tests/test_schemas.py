import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from remoterf_federation_core import *


class SchemaTests(unittest.TestCase):
    def test_local_no_identity(self):
        self.assertIsNone(local_capabilities()["deployment_id"])
        self.assertFalse(local_capabilities()["registration_policy"]["email_verification_required"])

    def test_https(self):
        doc = local_capabilities(deployment_id="550e8400-e29b-41d4-a716-446655440000")
        doc.update(account_transport="https-json", account_api_base="/v2/deployment")
        self.assertEqual(validate_capabilities(canonical_json(doc)), doc)

    def test_reject_invalid_capabilities(self):
        mutations = [
            ("protocol_version", 2), ("protocol_version", "3"), ("deployment_id", "email@example.com"),
            ("deployment_id", "550E8400-E29B-41D4-A716-446655440000"),
            ("display_name", "x"*257), ("display_name", "\x1b[2J"),
            ("account_transport", "http"), ("account_api_base", "https://evil.example"),
            ("account_api_base", "/v2/deployment"), ("federation_enabled", 1),
            ("federation_enabled", True), ("federation_protocol_version", "3"),
            ("supported_operations", ["FederationV2.Execute"]), ("supported_operations", ["ACC:login"]*2),
            ("registration_policy", {}), ("unexpected", True),
        ]
        for key,value in mutations:
            with self.subTest(key=key, value=value), self.assertRaises(ValidationError):
                doc=local_capabilities(); doc[key]=value; validate_capabilities(doc)
        for path in ["//evil", "/a/../b", "/a%2fb", "/a?x=1", "/a#x", "/", "https://evil", "/a/", "/a\\b"]:
            with self.subTest(path=path), self.assertRaises(ValidationError):
                doc=local_capabilities(deployment_id="550e8400-e29b-41d4-a716-446655440000")
                doc.update(account_transport="https-json",account_api_base=path)
                validate_capabilities(doc)

    def test_strict_encoding(self):
        for value in ['{"a":1,"a":2}', '{"a":NaN}', '[]'*20000]:
            with self.assertRaises(ValidationError): strict_json(value)
        for value in [1.2,{1:"a"},[float('inf')]]:
            with self.assertRaises(ValidationError): canonical_json(value)
        self.assertEqual(canonical_json({"b":1,"a":2}), '{"a":2,"b":1}')

    def test_import_has_no_runtime_dependencies_or_side_effects(self):
        with tempfile.TemporaryDirectory() as d:
            script = '''
import socket,sqlite3,sys
from pathlib import Path
socket.socket=lambda *a,**k: (_ for _ in ()).throw(AssertionError("network"))
sqlite3.connect=lambda *a,**k: (_ for _ in ()).throw(AssertionError("DB"))
import remoterf_federation_core as c
assert c.__version__ == "0.2.0"
assert not any(n.startswith(("remoteRF_server", "numpy", "adi", "rtlsdr", "sqlalchemy", "httpx")) for n in sys.modules)
assert not list(Path.cwd().iterdir())
'''
            subprocess.run([sys.executable,"-c",script],cwd=d,check=True)
