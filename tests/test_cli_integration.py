"""Run the actual CLI in temporary directories on Windows or Unix."""

import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from logsentinel.models import InvalidLogFileError, ParseStats
from logsentinel.parser import iter_entries, parse_line, validate_path


ROOT = Path(__file__).resolve().parents[1]
GOOD = '203.0.113.9 - - [13/Oct/2026:10:00:00 +0300] "GET / HTTP/1.1" 200 10'


class CliIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.sample = ROOT / "sample_logs/access.log"

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-B", str(ROOT / "cli.py"), *map(str, args)],
            cwd=self.directory, capture_output=True, text=True, encoding="utf-8",
        )

    def test_help_and_detector_listing(self):
        for args in [("--help",), ("analyze", "--help"), ("list-detectors",)]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout)

    def test_verified_sample_json_statistics_and_alerts(self):
        result = self.run_cli("analyze", "-i", self.sample, "-f", "json")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([report["stats"][key] for key in ("total", "parsed", "skipped")], [342, 339, 3])
        self.assertEqual([(a["detector"], a["count"]) for a in report["alerts"]],
                         [("bruteforce", 12), ("suspicious", 4), ("errorspike", 8), ("scanner", 5)])

    def test_csv_report_written_to_custom_path(self):
        target = self.directory / "report.csv"
        result = self.run_cli("analyze", "-i", self.sample, "-f", "csv", "-o", target)
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = list(csv.DictReader(io.StringIO(target.read_text(encoding="utf-8"))))
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["count"], "12")
        self.assertEqual(result.stdout, "")

    def test_minimum_severity_filters_output(self):
        result = self.run_cli("analyze", "-i", self.sample, "-m", "high", "-f", "json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual([a["severity"] for a in json.loads(result.stdout)["alerts"]], ["high", "high"])

    def test_clean_file_returns_zero(self):
        source = self.directory / "clean.log"
        source.write_text(GOOD + "\n", encoding="utf-8")
        result = self.run_cli("analyze", "-i", source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No suspicious activity found", result.stdout)

    def test_bad_arguments_return_two_without_traceback(self):
        for args in [("-t", "-1"), ("-t", "abc"), ("-w", "0"), ("-w", "1000001"), ("-d", "unknown")]:
            with self.subTest(args=args):
                result = self.run_cli("analyze", "-i", self.sample, *args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("error:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_missing_file_and_output_folder_return_two(self):
        for args in [("analyze", "-i", "missing.log"),
                     ("analyze", "-i", self.sample, "-o", "missing/report.txt")]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)

    def test_output_cannot_replace_input(self):
        source = self.directory / "input.log"
        original = GOOD + "\n"
        source.write_text(original, encoding="utf-8")
        result = self.run_cli("analyze", "-i", source, "-o", source)
        self.assertEqual(result.returncode, 2)
        self.assertIn("must not replace the input", result.stderr)
        self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_out_of_order_failed_auth_returns_clear_error(self):
        source = self.directory / "unsorted.log"
        source.write_text(GOOD.replace("10:00:00", "10:10:00").replace("200 10", "401 10") + "\n" +
                          GOOD.replace("200 10", "401 10") + "\n", encoding="utf-8")
        result = self.run_cli("analyze", "-i", source)
        self.assertEqual(result.returncode, 2)
        self.assertIn("timestamp order", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class ExtraParserTests(unittest.TestCase):
    def test_invalid_timestamp_and_status_are_skipped(self):
        self.assertIsNone(parse_line(GOOD.replace("13/Oct", "99/Oct")))
        for status in ("000", "099", "600", "999"):
            with self.subTest(status=status):
                self.assertIsNone(parse_line(GOOD.replace("200 10", status + " 10")))

    def test_file_size_limit_is_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "small.log"
            source.write_text(GOOD + "\n", encoding="utf-8")
            with patch("logsentinel.parser.MAX_FILE_BYTES", 1):
                with self.assertRaisesRegex(InvalidLogFileError, "200 MiB"):
                    validate_path(str(source))

    def test_bad_utf8_line_does_not_hide_next_valid_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "bad.log"
            source.write_bytes(b"\xff\xfe\n" + (GOOD + "\n").encode("utf-8"))
            stats = ParseStats()
            parsed = list(iter_entries(str(source), stats))
            self.assertEqual(len(parsed), 1)
            self.assertEqual((stats.total, stats.parsed, stats.skipped), (2, 1, 1))


if __name__ == "__main__":
    unittest.main()
