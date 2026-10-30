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

from datetime import datetime, timezone
import unittest

from remoteRF_server.server.reservation import _parse_reservation_datetime


class ReservationTimestampTests(unittest.TestCase):
    def test_accepts_sqlite_timestamps_with_and_without_microseconds(self):
        self.assertEqual(
            _parse_reservation_datetime("2026-07-19 12:34:56"),
            datetime(2026, 7, 19, 12, 34, 56),
        )
        self.assertEqual(
            _parse_reservation_datetime("2026-07-19 12:34:56.123456"),
            datetime(2026, 7, 19, 12, 34, 56, 123456),
        )

    def test_normalizes_timezone_aware_values_to_naive_local_time(self):
        parsed = _parse_reservation_datetime(
            datetime(2026, 7, 19, 12, 34, 56, tzinfo=timezone.utc)
        )
        self.assertIsNone(parsed.tzinfo)

    def test_rejects_invalid_timestamp(self):
        with self.assertRaisesRegex(ValueError, "invalid reservation"):
            _parse_reservation_datetime("not-a-timestamp")


if __name__ == "__main__":
    unittest.main()
