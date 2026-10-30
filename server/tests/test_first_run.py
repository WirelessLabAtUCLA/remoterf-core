"""First `serverrf --serve`: nothing should fail for want of a question."""

import builtins
import tempfile
import unittest
from unittest import mock

from remoteRF_server import serverrf_cli as cli


class FirstRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.dict(
            "os.environ",
            {
                "REMOTERF_CONFIG_DIR": self.tmp.name + "/config",
                "REMOTERF_CERT_DIR": self.tmp.name + "/config/certs",
                "REMOTERF_FEDERATION_IDENTITY_DIR": self.tmp.name + "/identity",
                "REMOTERF_GLOBAL_ORIGIN": "https://127.0.0.1:9",
            },
        )
        patch.start()
        self.addCleanup(patch.stop)

    def answer(self, *replies):
        return mock.patch.object(builtins, "input", mock.Mock(side_effect=replies))

    def test_ports_and_address_are_asked_for_once(self):
        with mock.patch.object(cli, "_detect_lan_address", return_value="192.168.1.20"):
            with self.answer("", "", ""):
                self.assertTrue(cli._ensure_network_configured())
        env = cli._read_env_kv(cli._server_env_path())
        self.assertEqual(env["STATIC_IP"], "192.168.1.20")
        self.assertEqual(env["GRPC_PORT"], str(cli.DEFAULT_GRPC_PORT))
        self.assertEqual(env["CERT_PORT"], str(cli.DEFAULT_GRPC_PORT + 1))

        # Asked once: a later start must not prompt again.
        with mock.patch.object(builtins, "input", mock.Mock(side_effect=AssertionError)):
            self.assertTrue(cli._ensure_network_configured())

    def test_explicit_answers_are_kept(self):
        with self.answer("10.0.0.5", "61005", "61006"):
            self.assertTrue(cli._ensure_network_configured())
        env = cli._read_env_kv(cli._server_env_path())
        self.assertEqual(
            (env["STATIC_IP"], env["GRPC_PORT"], env["CERT_PORT"]),
            ("10.0.0.5", "61005", "61006"),
        )

    def test_the_certificate_port_defaults_next_to_the_grpc_port(self):
        with self.answer("10.0.0.5", "5000", ""):
            self.assertTrue(cli._ensure_network_configured())
        self.assertEqual(cli._read_env_kv(cli._server_env_path())["CERT_PORT"], "5001")

    def test_nonsense_is_refused_rather_than_written(self):
        for replies in (("10.0.0.5", "abc", ""), ("10.0.0.5", "99999", "99998"),
                        ("10.0.0.5", "5000", "5000")):
            with self.subTest(replies=replies):
                with self.answer(*replies):
                    self.assertFalse(cli._ensure_network_configured())
                self.assertNotIn("GRPC_PORT", cli._read_env_kv(cli._server_env_path()))

    def test_aborting_setup_does_not_start_the_server(self):
        with self.answer(KeyboardInterrupt()):
            self.assertFalse(cli._ensure_network_configured())

    def test_certificates_cover_the_global_name_from_the_first_issue(self):
        """Adding the public name later would reissue the CA and break clients."""
        from remoteRF_server.server import global_onboarding as g

        with self.answer("10.0.0.5", "61005", ""):
            cli._ensure_network_configured()
        g.update(GLOBAL_CONSENT="yes", GLOBAL_NAME="ucla", GLOBAL_STATE="unverified")

        captured = {}

        def fake(**kwargs):
            captured.update(kwargs)
            (cli._certs_dir()).mkdir(parents=True, exist_ok=True)
            (cli._certs_dir() / "server.crt").write_text("x")
            (cli._certs_dir() / "server.key").write_text("x")
            return 0

        with mock.patch.object(cli, "_gen_certs", side_effect=fake):
            self.assertTrue(cli._ensure_certificates())
        self.assertEqual(captured["static_ip"], "10.0.0.5")
        # Not yet approved, but the name is already chosen.
        self.assertEqual(captured["dns"], ["ucla.global.remoterf.net"])
        self.assertFalse(captured["force"])

        # Existing certificates are never silently replaced.
        with mock.patch.object(cli, "_gen_certs", side_effect=AssertionError):
            self.assertTrue(cli._ensure_certificates())

    def test_a_lab_that_declined_global_gets_a_plain_certificate(self):
        from remoteRF_server.server import global_onboarding as g

        with self.answer("10.0.0.5", "61005", ""):
            cli._ensure_network_configured()
        g.update(GLOBAL_CONSENT="no")

        captured = {}

        def fake(**kwargs):
            captured.update(kwargs)
            (cli._certs_dir()).mkdir(parents=True, exist_ok=True)
            (cli._certs_dir() / "server.crt").write_text("x")
            (cli._certs_dir() / "server.key").write_text("x")
            return 0

        with mock.patch.object(cli, "_gen_certs", side_effect=fake):
            self.assertTrue(cli._ensure_certificates())
        self.assertEqual(captured["dns"], [])


if __name__ == "__main__":
    unittest.main()
