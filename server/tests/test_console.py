"""`serverrf -s` console: attach-or-start, and plain foreground without tmux."""

import os
import unittest
from pathlib import Path
from unittest import mock

from remoteRF_server.server import console


class ConsoleTests(unittest.TestCase):
    def test_without_tmux_nothing_is_running_and_nothing_execs(self):
        with mock.patch.object(console.shutil, "which", return_value=None):
            self.assertFalse(console.available())
            self.assertFalse(console.running())

    def test_attached_is_the_marker_env(self):
        with mock.patch.dict(os.environ, {console.ATTACHED_ENV: "1"}):
            self.assertTrue(console.attached())
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(console.ATTACHED_ENV, None)
            self.assertFalse(console.attached())

    def test_attach_when_running_else_start_on_the_private_socket(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(console.shutil, "which", return_value="/usr/bin/tmux"), \
                mock.patch.object(console.os, "execvp") as execvp, \
                mock.patch.object(console.os, "execvpe") as execvpe:
            with mock.patch.object(console, "running", return_value=True):
                console.attach_or_start(Path(tmp), ["--serve"])
            execvp.assert_called_once()
            self.assertEqual(execvp.call_args.args[1][:5], ["tmux", "-L", console.SOCKET, "attach-session", "-t"])
            with mock.patch.object(console, "running", return_value=False):
                console.attach_or_start(Path(tmp), ["--serve"])
            argv, env = execvpe.call_args.args[1], execvpe.call_args.args[2]
            self.assertIn("new-session", argv)
            self.assertIn("-f", argv)                       # the bare config
            self.assertEqual(env[console.ATTACHED_ENV], "1")  # the server knows it is inside
            self.assertEqual(argv[-1], "--serve")
            conf = Path(tmp) / "console.tmux.conf"
            self.assertIn("set -g status off", conf.read_text())


if __name__ == "__main__":
    unittest.main()
