import tempfile
import unittest
from pathlib import Path

from cli import main
from logsentinel.models import InvalidLogFileError, ParseStats
from logsentinel.parser import iter_entries, parse_line, validate_path

GOOD = '1.2.3.4 - - [13/Oct/2026:10:00:00 +0300] "GET /a HTTP/1.1" 200 10'


class ParserTests(unittest.TestCase):
    def test_valid_line(self):
        self.assertEqual(parse_line(GOOD).status, 200)

    def test_garbage_and_bad_ip(self):
        self.assertIsNone(parse_line("hello"))
        self.assertIsNone(parse_line(GOOD.replace("1.2.3.4", "999.1.1.1")))

    def test_huge_line_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "x.log"
            f.write_text("A" * 50000 + "\n" + GOOD + "\n")
            stats = ParseStats()
            self.assertEqual(len(list(iter_entries(str(f), stats))), 1)
            self.assertEqual(stats.skipped, 1)

    def test_binary_file_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "b.log"
            f.write_bytes(bytes(range(256)) * 50)
            list(iter_entries(str(f), ParseStats()))

    def test_missing_and_directory(self):
        with self.assertRaises(InvalidLogFileError):
            validate_path("/no/such/file")
        with self.assertRaises(InvalidLogFileError):
            validate_path(tempfile.gettempdir())


class CliTests(unittest.TestCase):
    def test_exit_codes(self):
        sample = Path(__file__).resolve().parents[1] / "sample_logs" / "access.log"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.json"
            self.assertEqual(main(["analyze", "-i", str(sample), "-f", "json", "-o", str(target)]), 1)
        self.assertEqual(main(["analyze", "-i", "/nope"]), 2)
        self.assertEqual(main(["list-detectors"]), 0)

    def test_bad_threshold_rejected(self):
        with self.assertRaises(SystemExit):
            main(["analyze", "-i", "sample_logs/access.log", "-t", "-5"])


if __name__ == "__main__":
    unittest.main()
