# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import io
import unittest
from contextlib import redirect_stdout

from remoteRF_server.server.user_group_cli import edit_user_group_local


class _Session:
    def __init__(self, responses: list[str]):
        self.responses = iter(responses)
        self.prompts: list[str] = []

    def prompt(self, message: str) -> str:
        self.prompts.append(message)
        return next(self.responses)


class EditUserGroupCliTests(unittest.TestCase):
    def test_all_is_not_an_available_devices_whitelist_option(self) -> None:
        session = _Session([
            "1",       # group ID
            "",        # group name unchanged
            "all",     # rejected as an invalid device list
            "0,1",     # replacement device list
            "",        # max reservation time unchanged
            "",        # max reservations unchanged
            "",        # lifetime unchanged
            "n",       # do not persist the edit
        ])
        output = io.StringIO()

        with redirect_stdout(output):
            edit_user_group_local(session)

        rendered = output.getvalue()
        self.assertIn("Invalid list. Use e.g. '0,1,2' or '0 1 2'.", rendered)
        self.assertIn("devices_whitelist       : 0,1", rendered)
        self.assertNotIn("ALL([])", rendered)
        self.assertTrue(all("all" not in prompt.lower() for prompt in session.prompts))


if __name__ == "__main__":
    unittest.main()
