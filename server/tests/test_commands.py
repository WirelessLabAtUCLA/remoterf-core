"""One command table, two doors: the shell and the console prompt."""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from remoteRF_server.server import commands, control
from remoteRF_server.server.commands import RestartRequested, dispatch, resolve


class FakeDaemon:
    """A control socket that records what a shell sends and answers like the server."""

    def __init__(self, path: Path):
        self.seen = []
        self.server = control.ControlServer(self._handle, path=path)

    def _handle(self, argv):
        self.seen.append(argv)
        print(f"daemon ran: {' '.join(argv)}")
        return 0

    def __enter__(self):
        self.server.start()
        return self

    def __exit__(self, *exc):
        self.server.stop()


class CommandTableTests(unittest.TestCase):
    def test_every_command_resolves_by_every_name(self):
        for command in commands.commands():
            for name in command.names:
                found, rest = resolve(name.split() + ["x"])
                self.assertIs(found, command, name)
                self.assertEqual(rest, ["x"])

    def test_singular_and_old_verbs_are_accepted(self):
        self.assertEqual(resolve(["device", "add"])[0].names[0], "devices add")
        self.assertEqual(resolve(["group", "delete"])[0].names[0], "groups remove")
        self.assertEqual(resolve(["certs", "show"])[0].names[0], "certs list")
        self.assertIsNone(resolve(["frobnicate"])[0])

    def test_help_is_two_levels_and_covers_every_visible_command(self):
        top = commands.help_text(in_daemon=True)
        self.assertLess(len(top), 20)
        for command in commands.commands():
            lines = commands.help_text(in_daemon=True, section=command.section)
            hits = [l for l in lines if l.startswith(f"  {command.names[0]} ")]
            self.assertEqual(len(hits), 0 if command.hidden else 1, command.names[0])
        self.assertNotIn("detach", "\n".join(commands.help_text(in_daemon=False, section="Server")))
        self.assertEqual(commands.section_for("device"), "Devices")
        self.assertEqual(commands.section_for("codes"), "Enrollment codes")
        self.assertIsNone(commands.section_for("nope"))


class ControlSocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "s.sock"

    def test_round_trip_and_absence(self):
        self.assertIsNone(control.call(["status"], path=self.path))
        self.assertFalse(control.running(self.path))
        with FakeDaemon(self.path) as daemon:
            self.assertTrue(control.running(self.path))
            self.assertEqual(control.call(["users", "list"], path=self.path), (0, "daemon ran: users list\n"))
            self.assertEqual(daemon.seen, [["users", "list"]])
            self.assertEqual(oct(self.path.stat().st_mode & 0o777), "0o600")
        self.assertFalse(self.path.exists())


class TwoDoorsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Path(self.tmp.name) / "remoterf"
        patch = mock.patch.dict(os.environ, {"REMOTERF_CONFIG_DIR": str(self.cfg), "XDG_CONFIG_HOME": self.tmp.name})
        patch.start()
        self.addCleanup(patch.stop)
        self.sock = Path(self.tmp.name) / "serverrf.sock"
        patch = mock.patch.object(control, "socket_path", return_value=self.sock)
        patch.start()
        self.addCleanup(patch.stop)

    def run_shell(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = dispatch(argv, in_daemon=False)
        return rc, out.getvalue()

    def test_daemon_command_from_a_shell_goes_over_the_socket(self):
        with FakeDaemon(self.sock) as daemon:
            rc, out = self.run_shell(["users", "list"])
        self.assertEqual((rc, out), (0, "daemon ran: users list\n"))
        self.assertEqual(daemon.seen, [["users", "list"]])

    def test_daemon_command_without_a_server_says_so(self):
        rc, out = self.run_shell(["reservations", "list"])
        self.assertEqual(rc, 1)
        self.assertIn("not running", out)

    def test_devices_add_writes_the_inventory_and_reloads_the_running_server(self):
        with FakeDaemon(self.sock) as daemon:
            rc, out = self.run_shell(["devices", "add", "pluto", "SDR-1", "--serial", "1044abc"])
            self.assertEqual(rc, 0, out)
            rc, _ = self.run_shell(["devices", "add", "hackrf", "HackRF", "--serial", "75b0"])
            self.assertEqual(rc, 0)
        devices = yaml.safe_load((self.cfg / "devices.yml").read_text())["devices"]
        self.assertEqual(
            [(d["device_id"], d["device_type"], d["name"], d["init"]["serial"]) for d in devices],
            [(0, "adalm_pluto", "SDR-1", "1044abc"), (1, "hackrf", "HackRF", "75b0")],
        )
        self.assertEqual(daemon.seen, [["reload", "devices"], ["reload", "devices"]])
        self.assertIn("reloaded on the running server", out)

    def test_devices_add_without_a_server_just_edits_the_file(self):
        rc, out = self.run_shell(["devices", "remove", "5"])
        self.assertEqual(rc, 0)
        self.assertIn("takes effect when it starts", out)

    def test_ports_change_from_a_shell_restarts_the_running_server(self):
        with FakeDaemon(self.sock) as daemon:
            rc, out = self.run_shell(["config", "ports", "61010", "61011"])
        self.assertEqual(rc, 0, out)
        self.assertIn("GRPC_PORT=61010", (self.cfg / "server.env").read_text())
        self.assertEqual(daemon.seen, [["restart"]])

    def test_ports_change_inside_the_server_asks_for_a_restart(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RestartRequested):
                dispatch(["config", "ports", "61020", "61021"], in_daemon=True)
        self.assertIn("CERT_PORT=61021", (self.cfg / "server.env").read_text())

    def test_shell_commands_run_inside_the_console_too(self):
        from prompt_toolkit.application import create_app_session
        from prompt_toolkit.output.plain_text import PlainTextOutput

        out = io.StringIO()
        with create_app_session(output=PlainTextOutput(out)), contextlib.redirect_stdout(out):
            rc = dispatch(["global", "status"], in_daemon=True)
            self.assertEqual(rc, 0)
            self.assertEqual(dispatch(["global", "clusters"], in_daemon=True), 1)
        self.assertIn("Not configured", out.getvalue())
        self.assertIn("not enabled", out.getvalue())
