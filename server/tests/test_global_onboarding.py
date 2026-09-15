"""Phase 0-3 RemoteRF Global participation: consent, request, relay, report."""

import builtins
import unittest
from unittest import mock

from remoteRF_server.server import global_onboarding as g


class ConsentTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.dict(
            "os.environ",
            {
                "REMOTERF_CONFIG_DIR": self.tmp.name + "/config",
                "REMOTERF_FEDERATION_IDENTITY_DIR": self.tmp.name + "/identity",
                "REMOTERF_GLOBAL_DOMAIN": "global.remoterf.net",
                # Never the real broker: an unmocked call must fail fast here
                # rather than submit a deployment request to production.
                "REMOTERF_GLOBAL_ORIGIN": "https://127.0.0.1:9",
                # Hermetic: no LAN-address probe, and the loopback forward
                # the tunnel tests expect.
                "REMOTERF_BIND_HOST": "0.0.0.0",
            },
        )
        patch.start()
        self.addCleanup(patch.stop)
        self.setUpSubmitStub()

    def answer(self, *replies):
        return mock.patch.object(builtins, "input", mock.Mock(side_effect=replies))

    def setUpSubmitStub(self):
        """Consent tests exercise the prompts; submission has its own tests."""
        patch = mock.patch.object(g, "submit_and_report", return_value=True)
        patch.start()
        self.addCleanup(patch.stop)

    def test_declining_is_a_durable_answer(self):
        with self.answer("n"):
            self.assertTrue(g.ensure_consent())
        self.assertEqual(g.load()["GLOBAL_CONSENT"], "no")
        self.assertFalse(g.participating())
        # Asked once: a second start must not prompt at all.
        with mock.patch.object(builtins, "input", mock.Mock(side_effect=AssertionError)):
            self.assertTrue(g.ensure_consent())

    def test_joining_writes_configuration_and_identity(self):
        with mock.patch.object(g, "name_available", return_value=True):
            with self.answer("y", "UCLA", "UCLA Wireless Lab", "lab@ucla.edu", "y"):
                self.assertTrue(g.ensure_consent())
        kv = g.load()
        self.assertEqual(kv["GLOBAL_CONSENT"], "yes")
        self.assertEqual(kv["GLOBAL_NAME"], "ucla")
        self.assertEqual(kv["GLOBAL_DISPLAY_NAME"], "UCLA Wireless Lab")
        self.assertEqual(kv["GLOBAL_EMAIL"], "lab@ucla.edu")
        self.assertEqual(kv["GLOBAL_SHARE_LAN"], "yes")
        self.assertEqual(kv["GLOBAL_STATE"], "unregistered")
        self.assertEqual(g.hostname(), "ucla.global.remoterf.net")
        self.assertTrue(g.relay_key_path().exists())
        self.assertTrue((g.identity_dir() / "deployment-private.pem").exists())
        self.assertTrue(g.relay_public_key().startswith("ssh-ed25519 "))

    def test_taken_name_is_reprompted(self):
        with mock.patch.object(g, "name_available", side_effect=[False, True]):
            with self.answer("y", "ucla", "ucla2", "", "lab@ucla.edu", "n"):
                self.assertTrue(g.ensure_consent())
        self.assertEqual(g.load()["GLOBAL_NAME"], "ucla2")
        self.assertEqual(g.load()["GLOBAL_SHARE_LAN"], "no")

    def test_unreachable_global_accepts_the_name_provisionally(self):
        with mock.patch.object(g, "name_available", return_value=None):
            with self.answer("y", "ucla", "", "lab@ucla.edu", "y"):
                self.assertTrue(g.ensure_consent())
        self.assertEqual(g.load()["GLOBAL_NAME"], "ucla")

    def test_invalid_slug_and_email_are_rejected(self):
        with mock.patch.object(g, "name_available", return_value=True):
            with self.answer("y", "-bad-", "ok", "ucla", "", "nope", "lab@ucla.edu", "y"):
                self.assertTrue(g.ensure_consent())
        self.assertEqual(g.load()["GLOBAL_NAME"], "ucla")
        self.assertEqual(g.load()["GLOBAL_EMAIL"], "lab@ucla.edu")

    def test_leave_is_local_and_immediate(self):
        with mock.patch.object(g, "name_available", return_value=True):
            with self.answer("y", "ucla", "", "lab@ucla.edu", "y"):
                g.ensure_consent()
        self.assertEqual(g.main(["leave"]), 0)
        self.assertEqual(g.state(), "left")

    def test_status_and_usage(self):
        self.assertEqual(g.main(["status"]), 0)
        self.assertEqual(g.main(["bogus"]), 2)
        self.assertEqual(g.main([]), 2)




class RequestTests(ConsentTests):
    """Phase 1: the signed request, and what the Server records from /me."""

    def join(self, **overrides):
        with mock.patch.object(g, "name_available", return_value=True):
            with self.answer("y", "ucla", "UCLA Wireless Lab", "lab@ucla.edu", "y"):
                g.ensure_consent()
        g.update(**overrides)

    def capture(self, reply):
        """Run one signed call against a stub broker; return what it received."""
        seen = {}

        class Response:
            status_code = 200
            content = b"{}"

            @staticmethod
            def json():
                return reply

        def request(method, url, data=None, headers=None, **kwargs):
            seen.update(method=method, url=url, data=data, headers=headers)
            return Response()

        return seen, mock.patch("requests.request", side_effect=request)

    def test_request_is_signed_and_bound_to_method_path_and_body(self):
        import hashlib
        import json

        import jwt

        self.join()
        seen, patched = self.capture(
            {"status": "requested", "deployment_id": "8a2e3f10-0000-4000-8000-000000000001",
             "name": None, "relay": None}
        )
        with patched:
            g.submit_request()

        self.assertEqual(seen["method"], "POST")
        self.assertTrue(seen["url"].endswith("/v2/broker/deployments/request"))
        body = json.loads(seen["data"])
        self.assertEqual(body["name"], "ucla")
        # An admin reviews the request by its human name, not its slug.
        self.assertEqual(body["display_name"], "UCLA Wireless Lab")
        self.assertEqual(body["email"], "lab@ucla.edu")
        self.assertEqual(body["public_key"], g._public_key_b64())
        self.assertTrue(body["ssh_public_key"].startswith("ssh-ed25519 "))

        token = seen["headers"]["Authorization"].removeprefix("Bearer ")
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["typ"], "remoterf-broker-request+jwt")
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(claims["method"], "POST")
        self.assertEqual(claims["path"], "/v2/broker/deployments/request")
        self.assertEqual(
            claims["body_sha256"], hashlib.sha256(seen["data"]).hexdigest()
        )
        # Verifiable against the very key the body carries.
        import base64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        jwt.decode(
            token,
            Ed25519PublicKey.from_public_bytes(base64.b64decode(body["public_key"])),
            algorithms=["EdDSA"],
            options={"verify_aud": False},
        )
        self.assertEqual(g.state(), "requested")

    def test_no_lan_address_is_sent_when_the_operator_declined(self):
        import json

        self.join(GLOBAL_SHARE_LAN="no")
        seen, patched = self.capture({"status": "requested", "name": None, "relay": None})
        with patched:
            g.submit_request()
        self.assertIsNone(json.loads(seen["data"])["lan_address"])

    def test_the_final_name_comes_from_global_not_the_request(self):
        self.join()
        _, patched = self.capture(
            {
                "status": "active",
                "name": "ucla-two",
                "deployment_id": "8a2e3f10-0000-4000-8000-000000000001",
                "relay": {
                    "hostname": "ucla-two.global.remoterf.net",
                    "tunnel_host": "global.remoterf.net",
                    "tunnel_port": 2222,
                    "tunnel_user": "remoterf-relay",
                    "tunnel_host_key": "ssh-ed25519 AAAAhost",
                    "grpc_port": 62005,
                    "cert_port": 62006,
                },
            }
        )
        with patched:
            g.fetch_me()
        self.assertEqual(g.state(), "active")
        self.assertEqual(g.hostname(), "ucla-two.global.remoterf.net")
        self.assertEqual(g.load()["GLOBAL_RELAY_GRPC_PORT"], "62005")
        self.assertEqual(g.load()["GLOBAL_RELAY_HOST_KEY"], "ssh-ed25519 AAAAhost")

    def test_a_refusal_surfaces_its_code(self):
        self.join()

        class Response:
            status_code = 409
            content = b"x"

            @staticmethod
            def json():
                return {"error": {"code": "name_taken", "message": "taken"}}

        with mock.patch("requests.request", return_value=Response()):
            with self.assertRaises(g.GlobalError) as caught:
                g.submit_request()
        self.assertEqual(caught.exception.code, "name_taken")

    def test_the_agent_does_not_run_for_a_server_that_declined(self):
        with self.answer("n"):
            g.ensure_consent()
        self.assertIsNone(g.start_agent())

    def test_the_agent_stops_on_a_terminal_state(self):
        self.join(GLOBAL_STATE="rejected")
        self.assertIsNone(g.start_agent())
        # ...and an already-running loop returns rather than polling forever.
        with mock.patch.object(g, "_tick", side_effect=AssertionError("polled")):
            g.run_agent(stop=None)

    def test_the_agent_submits_once_then_polls(self):
        self.join()
        calls = []
        with mock.patch.object(g, "submit_request", side_effect=lambda: calls.append("submit")):
            g._tick({})
        self.assertEqual(calls, ["submit"])

        g.update(GLOBAL_STATE="requested")
        last = {}
        with mock.patch.object(g, "fetch_me", side_effect=lambda: calls.append("poll")):
            g._tick(last)
            g._tick(last)  # inside the interval: no second call
        self.assertEqual(calls, ["submit", "poll"])

class TunnelTests(RequestTests):
    """Phase 2: the reverse tunnel as a supervised child, not a boot unit."""

    ASSIGNMENT = {
        "status": "active",
        "name": "ucla",
        "deployment_id": "8a2e3f10-0000-4000-8000-000000000001",
        "relay": {
            "hostname": "ucla.global.remoterf.net",
            "tunnel_host": "global.remoterf.net",
            "tunnel_port": 2222,
            "tunnel_user": "remoterf-relay",
            "tunnel_host_key": "ssh-ed25519 AAAAhostkey",
            "grpc_port": 62005,
            "cert_port": 62006,
        },
    }

    def activate(self):
        self.join()
        g.write_env_kv(g.cfg_dir() / "server.env", {"GRPC_PORT": "61005", "CERT_PORT": "61006"})
        _, patched = self.capture(self.ASSIGNMENT)
        with patched:
            g.fetch_me()

    def test_no_tunnel_before_approval(self):
        self.join()
        self.assertIsNone(g.tunnel_command())
        Tunnel = g.Tunnel()
        with mock.patch.object(g.subprocess, "Popen", side_effect=AssertionError("started")):
            Tunnel.supervise(0.0)

    def test_tunnel_command_pins_the_host_key_and_maps_both_planes(self):
        self.activate()
        command = g.tunnel_command()
        self.assertIn("-NT", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("ExitOnForwardFailure=yes", command)
        self.assertIn("127.0.0.1:62005:127.0.0.1:61005", command)
        self.assertIn("127.0.0.1:62006:127.0.0.1:61006", command)
        self.assertIn("remoterf-relay@global.remoterf.net", command)
        self.assertIn(str(g.relay_key_path()), command)
        self.assertEqual(
            g.known_hosts_path().read_text().strip(),
            "[global.remoterf.net]:2222 ssh-ed25519 AAAAhostkey",
        )

    def test_the_tunnel_forwards_to_whatever_the_server_bound(self):
        """A Server bound to its LAN address is not reachable on loopback, so
        the reverse forward has to name the address it actually bound."""
        self.activate()
        with mock.patch.dict("os.environ", {"REMOTERF_BIND_HOST": "192.168.1.20"}):
            self.assertIn("127.0.0.1:62005:192.168.1.20:61005", g.tunnel_command())
        for wildcard in ("0.0.0.0", "::"):
            with mock.patch.dict("os.environ", {"REMOTERF_BIND_HOST": wildcard}):
                self.assertIn("127.0.0.1:62005:127.0.0.1:61005", g.tunnel_command())
        # Unset is not loopback: the Server then binds its detected LAN address.
        with mock.patch.dict("os.environ", {"REMOTERF_BIND_HOST": ""}), \
                mock.patch.object(g, "detected_lan_ip", return_value="10.0.0.7"):
            self.assertIn("127.0.0.1:62005:10.0.0.7:61005", g.tunnel_command())

    def test_server_exit_stops_the_tunnel_child(self):
        """The agent thread is a daemon; its ssh child must not outlive the
        server and squat on the relay ports."""
        self.activate()
        with mock.patch.object(g.atexit, "register") as register, \
                mock.patch.object(g, "run_agent"):
            stop = g.start_agent()
        (hook, stop_arg, tunnel), _ = register.call_args
        self.assertIs(stop_arg, stop)
        tunnel.process = mock.Mock(poll=mock.Mock(return_value=None))
        child = tunnel.process
        hook(stop, tunnel)
        self.assertTrue(stop.is_set())
        child.terminate.assert_called_once()
        self.assertIsNone(tunnel.process)

    def test_a_missing_host_key_refuses_to_start_a_tunnel(self):
        self.activate()
        g.update(GLOBAL_RELAY_HOST_KEY="")
        self.assertIsNone(g.tunnel_command())

    def test_supervisor_backs_off_then_recovers(self):
        self.activate()
        started = []

        class Child:
            def __init__(self):
                self.code = 1

            def poll(self):
                return self.code

            def terminate(self):
                self.code = 0

            def wait(self, timeout=None):
                return 0

        def spawn(command, **kwargs):
            started.append(command)
            return Child()

        tunnel = g.Tunnel()
        with mock.patch.object(g.subprocess, "Popen", side_effect=spawn):
            tunnel.supervise(0.0)
            self.assertEqual(len(started), 1)
            # A dead child is not respawned until the backoff elapses.
            tunnel.supervise(1.0)
            self.assertEqual(len(started), 1)
            tunnel.supervise(100.0)
            self.assertEqual(len(started), 2)
            self.assertGreater(tunnel.backoff, tunnel.MIN_BACKOFF)

    def test_leaving_tears_the_tunnel_down(self):
        self.activate()
        stopped = []

        class Child:
            def poll(self):
                return None

            def terminate(self):
                stopped.append(True)

            def wait(self, timeout=None):
                return 0

        tunnel = g.Tunnel()
        tunnel.process = Child()
        g.update(GLOBAL_STATE="left")
        tunnel.supervise(0.0)
        self.assertEqual(stopped, [True])
        self.assertIsNone(tunnel.process)

    def test_certificate_covers_the_global_name_from_the_moment_it_is_chosen(self):
        """Not only once approved: adding the name to the certificate later
        reissues the CA, which makes every enrolled client re-enrol."""
        from remoteRF_server.tools import gen_certs

        self.join()
        self.assertEqual(gen_certs._global_hostname(), "ucla.global.remoterf.net")
        self.activate()
        self.assertEqual(gen_certs._global_hostname(), "ucla.global.remoterf.net")

    def test_a_lab_that_declined_global_gets_no_extra_name(self):
        from remoteRF_server.tools import gen_certs

        self.join()
        g.update(GLOBAL_CONSENT="no")
        self.assertIsNone(gen_certs._global_hostname())


class StatusReportTests(TunnelTests):
    """Phase 3: exactly what the consent text promised, and nothing else."""

    def seed(self):
        import sqlite3

        db = g.cfg_dir() / "db" / "reservations.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE Accounts (username TEXT)")
            conn.executemany(
                "INSERT INTO Accounts VALUES (?)", [("a",), ("b",), ("c",)]
            )
            conn.execute(
                "CREATE TABLE Reservations "
                "(username TEXT, device_id INT, start_time TIMESTAMP, end_time TIMESTAMP)"
            )
            conn.executemany(
                "INSERT INTO Reservations VALUES (?,?,?,?)",
                [
                    ("a", 0, "2000-01-01T00:00:00+00:00", "2999-01-01T00:00:00+00:00"),
                    ("b", 1, "2000-01-01T00:00:00+00:00", "2000-01-02T00:00:00+00:00"),
                ],
            )
        (g.cfg_dir() / "devices.yml").write_text(
            "devices:\n"
            "  - device_id: 0\n    device_type: adalm_pluto\n"
            "  - device_type: usrp_2901\n    device_id: 1\n",
            encoding="utf-8",
        )
        certs = g.cfg_dir() / "certs"
        certs.mkdir(parents=True, exist_ok=True)
        (certs / "ca.crt").write_bytes(b"-----BEGIN CERTIFICATE-----\nx\n")

    def test_report_payload_matches_the_consent_text(self):
        """The consent text is the contract; the payload may not exceed it."""
        self.activate()
        self.seed()
        payload = g.status_payload()

        self.assertEqual(set(payload), g.STATUS_FIELDS)
        self.assertEqual(payload["users"], 3)
        self.assertEqual(payload["active_reservations"], 1)
        self.assertEqual(
            sorted(entry["type"] for entry in payload["devices"]),
            ["adalm_pluto", "usrp_2901"],
        )
        self.assertEqual(payload["lan_address"], g.lan_address())
        self.assertEqual(len(payload["cert_sha256"]), 64)

        # Every promised item is represented, and nothing forbidden leaks.
        serialized = repr(payload)
        for forbidden in ("username", "password", "token", "email", "salt", "hash"):
            self.assertNotIn(forbidden, serialized.lower())
        for name in ("a", "b", "c"):
            self.assertNotIn(f"'{name}'", serialized)

    def test_status_payload_survives_missing_state(self):
        self.activate()
        payload = g.status_payload()
        self.assertEqual(set(payload), g.STATUS_FIELDS)
        self.assertEqual(payload["users"], 0)
        self.assertEqual(payload["devices"], [])
        self.assertIsNone(payload["cert_sha256"])

    def test_a_withheld_lan_address_is_absent_from_the_report(self):
        self.activate()
        self.seed()
        g.update(GLOBAL_SHARE_LAN="no")
        self.assertIsNone(g.status_payload()["lan_address"])

    def test_reports_only_flow_once_active(self):
        self.join()
        sent = []
        with mock.patch.object(g, "send_liveness", side_effect=lambda: sent.append("live")), \
             mock.patch.object(g, "send_status", side_effect=lambda: sent.append("status")), \
             mock.patch.object(g, "submit_request"):
            g._tick({})
        self.assertEqual(sent, [])

        self.activate()
        last = {}
        with mock.patch.object(g, "send_liveness", side_effect=lambda: sent.append("live")), \
             mock.patch.object(g, "send_status", side_effect=lambda: sent.append("status")), \
             mock.patch.object(g, "fetch_me"):
            g._tick(last)
            g._tick(last)  # inside both intervals
        self.assertEqual(sent, ["live", "status"])

    def test_report_is_signed_to_its_own_path(self):
        import jwt

        self.activate()
        self.seed()
        seen, patched = self.capture({})
        with patched:
            g.send_status()
        claims = jwt.decode(
            seen["headers"]["Authorization"].removeprefix("Bearer "),
            options={"verify_signature": False},
        )
        self.assertEqual(claims["path"], "/v2/broker/deployments/report")
        body = __import__("json").loads(seen["data"])
        self.assertEqual(body["kind"], "status")
        self.assertEqual(set(body["status"]), g.STATUS_FIELDS)
        self.assertIn("GLOBAL_LAST_REPORT_AT", g.load())


class DisplayNameTests(ConsentTests):
    def test_display_name_defaults_to_the_slug(self):
        with mock.patch.object(g, "name_available", return_value=True):
            with self.answer("y", "ucla", "", "lab@ucla.edu", "y"):
                g.ensure_consent()
        self.assertEqual(g.load()["GLOBAL_DISPLAY_NAME"], "ucla")

    def test_control_characters_fall_back_to_the_slug(self):
        with mock.patch.object(g, "name_available", return_value=True):
            with self.answer("y", "ucla", "UCLA\x1b[2J", "lab@ucla.edu", "y"):
                g.ensure_consent()
        self.assertEqual(g.load()["GLOBAL_DISPLAY_NAME"], "ucla")


class SubmitReportTests(RequestTests):
    """What the operator is told after answering the consent questions."""

    def setUpSubmitStub(self):
        # This class is specifically about the real submit path.
        pass

    def test_a_successful_request_is_acknowledged(self):
        printed = []
        with mock.patch.object(g, "name_available", return_value=True):
            with self.answer("y", "ucla", "UCLA Wireless Lab", "lab@ucla.edu", "y"):
                _, patched = self.capture(
                    {"status": "requested", "name": None, "relay": None,
                     "deployment_id": "8a2e3f10-0000-4000-8000-000000000001"}
                )
                with patched, mock.patch("builtins.print", lambda *a, **k: printed.append(a)):
                    self.assertTrue(g.ensure_consent())
        self.assertEqual(g.state(), "requested")

    def test_an_unreachable_global_says_so_and_keeps_the_server_usable(self):
        """A lab with no route to Global still gets a working local server."""
        with mock.patch.object(g, "name_available", return_value=None):
            with self.answer("y", "ucla", "UCLA Wireless Lab", "lab@ucla.edu", "y"):
                # No mock: the suite's origin is the discard port, so this is a
                # real failed connection, not a stubbed one.
                self.assertTrue(g.ensure_consent())
        # Consent is recorded, the request simply has not landed yet.
        self.assertTrue(g.participating())
        self.assertEqual(g.state(), "unregistered")

    def test_a_name_taken_race_reprompts_instead_of_failing(self):
        calls = []

        def submit():
            calls.append(load := g.load().get("GLOBAL_NAME"))
            if len(calls) == 1:
                raise g.GlobalError("name_taken", "taken")

        with mock.patch.object(g, "name_available", return_value=True):
            with self.answer("y", "ucla", "UCLA Wireless Lab", "lab@ucla.edu", "y", "ucla2"):
                with mock.patch.object(g, "submit_request", side_effect=submit):
                    self.assertTrue(g.ensure_consent())
        self.assertEqual(calls, ["ucla", "ucla2"])
        self.assertEqual(g.load()["GLOBAL_NAME"], "ucla2")


if __name__ == "__main__":
    unittest.main()


class InviteTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.dict("os.environ", {"REMOTERF_CONFIG_DIR": self.tmp.name, "REMOTERF_GLOBAL_DOMAIN": "global.remoterf.net"})
        patch.start()
        self.addCleanup(patch.stop)

    def test_live_global_deployment_hands_out_the_full_form(self):
        g.update(GLOBAL_CONSENT="yes", GLOBAL_STATE="active", GLOBAL_FINAL_NAME="ucla-dev0")
        self.assertEqual(g.invite("RERGSOQ5"), "ucla-dev0.global.remoterf.net/RERGSOQ5")
        # LAN-only groups never get a Global invite: it would not work there.
        self.assertEqual(g.invite("RERGSOQ5", lan_only=True), "RERGSOQ5")

    def test_bare_code_until_the_deployment_is_live(self):
        g.update(GLOBAL_CONSENT="yes", GLOBAL_STATE="requested", GLOBAL_NAME="ucla-dev0")
        self.assertEqual(g.invite("RERGSOQ5"), "RERGSOQ5")
        self.assertEqual(g.tunnel_state(), "not assigned")
        g.update(GLOBAL_CONSENT="no")
        self.assertEqual(g.tunnel_state(), "off")
