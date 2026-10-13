"""Pluggable attack detectors, registered with a decorator."""

import functools
import re
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import timedelta
from typing import Callable, Dict, Iterable, List, Tuple, Type

from .models import Alert, InvalidArgumentError, LogEntry, ParseStats
from .parser import iter_entries

REGISTRY: Dict[str, Type["Detector"]] = {}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def register(name: str) -> Callable[[Type["Detector"]], Type["Detector"]]:
    """Class decorator that adds a detector to the global registry."""

    def decorator(cls: Type["Detector"]) -> Type["Detector"]:
        cls.name = name
        REGISTRY[name] = cls
        return cls

    return decorator


def timed(func: Callable) -> Callable:
    """Decorator: returns (result, elapsed_seconds)."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        return result, time.perf_counter() - start

    return wrapper


class Detector(ABC):
    name = "base"

    def __init__(self, threshold: int, window: int) -> None:
        self.threshold = threshold
        self.window = timedelta(seconds=window)

    @abstractmethod
    def feed(self, entry: LogEntry) -> None:
        """Consume one parsed entry. Each detector maintains its own state."""

    @abstractmethod
    def finish(self) -> List[Alert]:
        """Return alerts after all entries were fed."""


@register("bruteforce")
class BruteForceDetector(Detector):
    """Many 401/403 responses from one IP inside a sliding time window."""

    def __init__(self, threshold: int, window: int) -> None:
        super().__init__(threshold, window)
        self._hits: Dict[str, deque] = defaultdict(deque)
        self._peak: Dict[str, int] = {}

    def feed(self, entry: LogEntry) -> None:
        if entry.status not in (401, 403):
            return
        hits = self._hits[entry.ip]
        if hits and entry.timestamp < hits[-1]:
            raise InvalidArgumentError(
                f"Failed-auth events for {entry.ip} must be in timestamp order"
            )
        hits.append(entry.timestamp)
        while hits and entry.timestamp - hits[0] > self.window:
            hits.popleft()
        self._peak[entry.ip] = max(self._peak.get(entry.ip, 0), len(hits))

    def finish(self) -> List[Alert]:
        seconds = int(self.window.total_seconds())
        return [
            Alert(self.name, "high", ip, f"{n} failed auth attempts within {seconds}s", n)
            for ip, n in self._peak.items()
            if n >= self.threshold
        ]


@register("scanner")
class ScannerDetector(Detector):
    """One IP probing many distinct non-existing paths (404)."""

    def __init__(self, threshold: int, window: int) -> None:
        super().__init__(threshold, window)
        self._paths: Dict[str, set] = defaultdict(set)

    def feed(self, entry: LogEntry) -> None:
        paths = self._paths[entry.ip]
        if entry.status == 404 and len(paths) < self.threshold:
            paths.add(entry.path)  # capped, so memory stays bounded

    def finish(self) -> List[Alert]:
        return [
            Alert(self.name, "medium", ip, f"{len(p)}+ distinct missing paths probed", len(p))
            for ip, p in self._paths.items()
            if len(p) >= self.threshold
        ]


SUSPICIOUS_RE = re.compile(
    r"(\.\./|%2e%2e|/\.env|/\.git|wp-login|phpmyadmin|union(\s|%20|\+)+select|<script)",
    re.IGNORECASE,
)


@register("suspicious")
class SuspiciousPathDetector(Detector):
    """Known attack signatures: traversal, SQLi, XSS, secret files."""

    def __init__(self, threshold: int, window: int) -> None:
        super().__init__(threshold, window)
        self._count: Dict[str, int] = defaultdict(int)

    def feed(self, entry: LogEntry) -> None:
        if SUSPICIOUS_RE.search(entry.path):
            self._count[entry.ip] += 1

    def finish(self) -> List[Alert]:
        return [
            Alert(self.name, "high", ip, f"{n} requests matching attack signatures", n)
            for ip, n in self._count.items()
        ]


@register("errorspike")
class ErrorSpikeDetector(Detector):
    """Minutes in which the server produced many 5xx errors."""

    def __init__(self, threshold: int, window: int) -> None:
        super().__init__(threshold, window)
        self._errors: Dict[str, int] = defaultdict(int)

    def feed(self, entry: LogEntry) -> None:
        if 500 <= entry.status <= 599:
            self._errors[entry.timestamp.strftime("%Y-%m-%d %H:%M")] += 1

    def finish(self) -> List[Alert]:
        return [
            Alert(self.name, "medium", "*", f"{n} server errors at {minute}", n)
            for minute, n in sorted(self._errors.items())
            if n >= self.threshold
        ]


def build_detectors(names: Iterable[str], threshold: int, window: int) -> List[Detector]:
    detectors = []
    for name in names:
        if name not in REGISTRY:
            raise InvalidArgumentError(f"Unknown detector: {name}")
        detectors.append(REGISTRY[name](threshold, window))
    return detectors


@timed
def analyze(path: str, detectors: List[Detector]) -> Tuple[List[Alert], ParseStats]:
    """Stream the file once and feed every entry to every detector."""
    stats = ParseStats()
    for entry in iter_entries(path, stats):
        for detector in detectors:
            detector.feed(entry)
    alerts = [alert for d in detectors for alert in d.finish()]
    alerts.sort(key=lambda a: (-SEVERITY_ORDER[a.severity], -a.count))
    return alerts, stats
