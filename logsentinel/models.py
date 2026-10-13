"""Data models and custom exceptions."""

from dataclasses import dataclass
from datetime import datetime


class LogSentinelError(Exception):
    """Base class for all expected LogSentinel errors."""


class InvalidLogFileError(LogSentinelError):
    """Raised when the input path is missing, not a file, or too large."""


class InvalidArgumentError(LogSentinelError):
    """Raised when a user supplied argument is not acceptable."""


@dataclass(frozen=True)
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: int


@dataclass
class Alert:
    detector: str
    severity: str  # "low" | "medium" | "high"
    ip: str
    message: str
    count: int


@dataclass
class ParseStats:
    total: int = 0
    parsed: int = 0
    skipped: int = 0
