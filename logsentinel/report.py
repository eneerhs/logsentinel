"""Render alerts as text, JSON or CSV."""

import csv
import io
import json
from dataclasses import asdict
from typing import List

from .models import Alert, ParseStats


def _text(alerts: List[Alert], stats: ParseStats, elapsed: float) -> str:
    lines = [
        f"LogSentinel report: {stats.parsed}/{stats.total} lines parsed, "
        f"{stats.skipped} skipped, {elapsed:.3f}s",
        "-" * 60,
    ]
    if not alerts:
        lines.append("No suspicious activity found.")
    for a in alerts:
        lines.append(f"[{a.severity.upper():6}] {a.detector:<11} {a.ip:<16} {a.message}")
    return "\n".join(lines)


def _json(alerts: List[Alert], stats: ParseStats, elapsed: float) -> str:
    payload = {
        "stats": {**asdict(stats), "elapsed_seconds": round(elapsed, 4)},
        "alerts": [asdict(a) for a in alerts],
    }
    return json.dumps(payload, indent=2)


def _csv(alerts: List[Alert], stats: ParseStats, elapsed: float) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["detector", "severity", "ip", "count", "message"])
    for a in alerts:
        writer.writerow([a.detector, a.severity, a.ip, a.count, a.message])
    return buffer.getvalue()


FORMATTERS = {"text": _text, "json": _json, "csv": _csv}


def render(fmt: str, alerts: List[Alert], stats: ParseStats, elapsed: float) -> str:
    return FORMATTERS[fmt](alerts, stats, elapsed)
