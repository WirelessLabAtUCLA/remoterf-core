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
