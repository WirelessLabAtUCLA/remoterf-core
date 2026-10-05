"""The activity log survives a truncated file and is written atomically."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from remoteRF_server.server import reservation


class ActivityLogTests(unittest.TestCase):
    def test_empty_log_file_is_rewritten_on_the_next_append(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "activity_logs.npy"
        path.write_bytes(b"")
        with mock.patch.object(reservation, "LOG_PATH", path):
            self.assertEqual(reservation._load_logs(), [])
            reservation._append_log({"call": "login", "ok": True})
            reservation._append_log({"call": "get_dev", "ok": True})
            self.assertEqual([e["call"] for e in reservation._load_logs()], ["login", "get_dev"])
        self.assertEqual(sorted(p.name for p in Path(tmp.name).iterdir()), ["activity_logs.npy"])


if __name__ == "__main__":
    unittest.main()
