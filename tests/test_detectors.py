"""Check actual detection rules, time boundaries, and ordering."""

from datetime import datetime, timedelta, timezone
import unittest

from logsentinel.detectors import (
    BruteForceDetector, ScannerDetector, SuspiciousPathDetector,
    ErrorSpikeDetector, build_detectors,
)
from logsentinel.models import InvalidArgumentError, LogEntry


def entry(seconds=0, status=200, path="/", ip="203.0.113.9"):
    stamp = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)
    return LogEntry(ip, stamp + timedelta(seconds=seconds), "GET", path, status, 10)


class DetectorTests(unittest.TestCase):
    def test_bruteforce_at_inclusive_window_boundary(self):
        detector = BruteForceDetector(3, 60)
        for seconds in (0, 30, 60):
            detector.feed(entry(seconds, 401))
        self.assertEqual(detector.finish()[0].count, 3)

    def test_bruteforce_expired_hits_do_not_count(self):
        detector = BruteForceDetector(3, 60)
        for seconds in (0, 61, 122):
            detector.feed(entry(seconds, 403))
        self.assertEqual(detector.finish(), [])

    def test_bruteforce_separates_ips_and_ignores_success(self):
        detector = BruteForceDetector(2, 60)
        detector.feed(entry(0, 401))
        detector.feed(entry(1, 200))
        detector.feed(entry(2, 401, ip="203.0.113.10"))
        self.assertEqual(detector.finish(), [])

    def test_bruteforce_rejects_out_of_order_events(self):
        detector = BruteForceDetector(2, 60)
        detector.feed(entry(600, 401))
        with self.assertRaisesRegex(InvalidArgumentError, "timestamp order"):
            detector.feed(entry(0, 401))

    def test_scanner_counts_distinct_404_paths_and_caps_set(self):
        detector = ScannerDetector(3, 60)
        for path in ("/a", "/a", "/b", "/c", "/d"):
            detector.feed(entry(status=404, path=path))
        detector.feed(entry(status=200, path="/e"))
        self.assertEqual(detector.finish()[0].count, 3)
        self.assertEqual(len(detector._paths["203.0.113.9"]), 3)

    def test_suspicious_signature_alerts_even_below_threshold(self):
        detector = SuspiciousPathDetector(100, 60)
        detector.feed(entry(path="/.env"))
        detector.feed(entry(path="/index.html"))
        self.assertEqual(detector.finish()[0].count, 1)

    def test_error_spike_groups_server_errors_per_minute(self):
        detector = ErrorSpikeDetector(2, 60)
        for seconds, status in [(0, 500), (59, 503), (60, 500), (61, 404)]:
            detector.feed(entry(seconds, status))
        alerts = detector.finish()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 2)
        self.assertEqual(alerts[0].ip, "*")

    def test_unknown_detector_rejected(self):
        with self.assertRaises(InvalidArgumentError):
            build_detectors(["unknown"], 5, 60)


if __name__ == "__main__":
    unittest.main()
