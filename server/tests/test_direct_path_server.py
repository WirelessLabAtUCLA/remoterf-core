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

"""The Server end of the direct path: the offer's failure reply, and the
punch holding its first check for a client that dials the fixed port first."""

from __future__ import annotations

import asyncio
import os
import unittest
from unittest import mock

from aioice import Candidate

from remoteRF_server.common.utils.process_arg import unmap_arg
from remoteRF_server.server import direct_path


class _FakeIce:
    """Enough of an aioice Connection for _Path.run() to fail after connect()."""

    def __init__(self):
        self.heard = asyncio.Event()
        self.connected_at = None
        self.remote_candidates = [
            Candidate(foundation="a", component=1, transport="udp", priority=1, host="172.20.10.2", port=53982, type="host"),
            Candidate(foundation="b", component=1, transport="udp", priority=1, host="70.243.119.29", port=9961, type="srflx"),
        ]

    async def connect(self):
        self.connected_at = asyncio.get_running_loop().time()
        raise ConnectionError("ICE negotiation failed")

    async def close(self):
        pass


class OfferTests(unittest.TestCase):
    def test_offer_failure_gives_the_client_a_fixed_line(self):
        with mock.patch.object(direct_path, "_get_loop", side_effect=RuntimeError("no loop: secret detail")):
            reply = direct_path.offer("session", "tester", '{"id": "x"}')
        self.assertEqual(unmap_arg(reply["ace"]), "direct path unavailable")


class HoldTests(unittest.TestCase):
    """With a fixed port offered too, the first check waits for the client's."""

    def _run(self, hold: float, heard_after: float | None = None) -> float:
        async def go():
            ice = _FakeIce()
            loop = asyncio.get_running_loop()
            if heard_after is not None:
                loop.call_later(heard_after, ice.heard.set)
            started = loop.time()
            await direct_path._Path("k", "tester", ice, hold=hold).run()
            return ice.connected_at - started

        return asyncio.run(go())

    def test_no_fixed_port_means_no_hold(self):
        self.assertLess(self._run(hold=0.0), 0.1)

    def test_a_silent_client_gets_our_checks_after_the_hold(self):
        self.assertGreaterEqual(self._run(hold=0.3), 0.3)

    def test_the_clients_first_check_ends_the_hold(self):
        self.assertLess(self._run(hold=0.3, heard_after=0.05), 0.2)


class _OfferIce:
    """Enough of Ice for _offer() to answer without a network."""

    local_username = "u"
    local_password = "p"
    local_candidates = []

    def __init__(self, *args, **kwargs):
        pass

    async def gather_candidates(self):
        pass

    async def add_remote_candidate(self, candidate):
        pass


class OfferHoldTests(unittest.TestCase):
    """A 2.1.0 offer (no "race" key) gets the long hold, a racing one the short one."""

    def _hold_for(self, offer: dict) -> float:
        holds = []

        class Recorder:
            def __init__(self, key, user, ice, bound=None, hold=0.0):
                holds.append(hold)

            async def run(self):
                pass

        with mock.patch.object(direct_path, "Ice", _OfferIce), \
                mock.patch.object(direct_path, "_Path", Recorder), \
                mock.patch.object(direct_path, "_make_room", mock.AsyncMock()), \
                mock.patch.object(direct_path, "_fixed_port_offer", return_value={"udp": "10.0.0.1:9961", "session": "s"}), \
                mock.patch.dict(direct_path._paths, clear=True):
            answer = asyncio.run(direct_path._offer("k", "tester", offer))
        self.assertEqual(answer["udp"], "10.0.0.1:9961")
        return holds[0]

    def test_a_2_1_0_offer_is_held(self):
        self.assertEqual(self._hold_for({"ufrag": "a", "pwd": "b", "candidates": []}), direct_path.HOLD_SECONDS)

    def test_a_racing_offer_gets_the_short_hold(self):
        self.assertEqual(self._hold_for({"ufrag": "a", "pwd": "b", "candidates": [], "race": True}), direct_path.RACE_HOLD_SECONDS)
        self.assertLess(direct_path.RACE_HOLD_SECONDS, 0.5)  # under the client's first retransmit


if __name__ == "__main__":
    unittest.main()


def test_a_broken_pyopenssl_turns_the_direct_path_off_not_the_server(tmp_path):
    # conda can swap in a cryptography the pip-installed pyOpenSSL (aioquic's) cannot use.
    import subprocess
    import sys

    (tmp_path / "OpenSSL").mkdir()
    (tmp_path / "OpenSSL" / "__init__.py").write_text("raise AttributeError(\"module 'lib' has no attribute 'GEN_EMAIL'\")\n")
    env = {**os.environ, "PYTHONPATH": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path),
           "GRPC_PORT": "50999", "CERT_PORT": "50998"}
    probe = "from remoteRF_server.server import grpc_server as g; print(g.direct_path, g._DIRECT_PATH_ERROR)"
    result = subprocess.run([sys.executable, "-c", probe], env=env, capture_output=True, text=True, timeout=120,
                            stdin=subprocess.DEVNULL)
    assert result.stdout.strip().splitlines()[-1].startswith("None AttributeError"), result.stderr[-2000:]
