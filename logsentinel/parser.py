"""Safe, streaming parser for Apache/Nginx "common log format" files."""

import ipaddress
import re
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, TextIO

from .models import InvalidLogFileError, LogEntry, ParseStats

MAX_FILE_BYTES = 200 * 1024 * 1024  # refuse files above 200 MiB
MAX_LINE_LEN = 4096  # lines longer than this are skipped (memory safety)
TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
)


def validate_path(raw: str) -> Path:
    """Resolve the path and make sure it is a reasonably sized regular file."""
    path = Path(raw).expanduser().resolve()
    if not path.exists():
        raise InvalidLogFileError(f"File not found: {raw}")
    if not path.is_file():
        raise InvalidLogFileError(f"Not a regular file: {raw}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise InvalidLogFileError("File is larger than the 200 MiB limit")
    return path


@contextmanager
def open_log(path: Path) -> Iterator[TextIO]:
    """Open a log file leniently (bad bytes are replaced, not fatal)."""
    handle = open(path, "r", encoding="utf-8", errors="replace")
    try:
        yield handle
    finally:
        handle.close()


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse one line. Returns None for anything malformed."""
    if len(line) > MAX_LINE_LEN:
        return None
    match = LINE_RE.match(line)
    if match is None:
        return None
    try:
        ipaddress.ip_address(match["ip"])
        timestamp = datetime.strptime(match["ts"], TS_FORMAT)
    except ValueError:
        return None
    size = 0 if match["size"] == "-" else int(match["size"])
    status = int(match["status"])
    if not 100 <= status <= 599:
        return None
    return LogEntry(
        ip=match["ip"],
        timestamp=timestamp,
        method=match["method"],
        path=match["path"],
        status=status,
        size=size,
    )


def iter_entries(raw_path: str, stats: ParseStats) -> Iterator[LogEntry]:
    """Generator: yields valid entries one at a time, never loads the file whole."""
    with open_log(validate_path(raw_path)) as handle:
        while True:
            line = handle.readline(MAX_LINE_LEN + 1)
            if not line:
                break
            stats.total += 1
            if len(line) > MAX_LINE_LEN and not line.endswith("\n"):
                # Oversized line: drain the rest of it without storing it.
                while line and not line.endswith("\n"):
                    line = handle.readline(MAX_LINE_LEN)
                stats.skipped += 1
                continue
            entry = parse_line(line.rstrip("\r\n"))
            if entry is None:
                stats.skipped += 1
                continue
            stats.parsed += 1
            yield entry
