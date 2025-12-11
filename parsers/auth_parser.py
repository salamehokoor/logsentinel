"""
Parser for Linux authentication logs (/var/log/auth.log style).

Extracts timestamp, username, source IP, event type, and status. Malformed
lines are skipped gracefully to keep the pipeline resilient.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

# Regex to capture the syslog-style prefix and the remainder of the message.
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+(?P<process>[\w\-/]+)(?:\[\d+\])?:\s+(?P<message>.+)$"
)
IP_PATTERN = re.compile(r"from\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
USER_PATTERN = re.compile(r"(?:user|invalid user)\s(?P<user>[A-Za-z0-9._-]+)")


def parse_auth_log(path: Path) -> pd.DataFrame:
    """
    Parse an auth log file into a pandas DataFrame.

    Args:
        path: Path to the auth log file.

    Returns:
        DataFrame with columns: timestamp, ip, username, event_type, status, raw_line.
    """
    records: List[Dict] = []
    for idx, line in enumerate(path.read_text(errors="ignore").splitlines(),
                               start=1):
        parsed = _parse_line(line, idx)
        if parsed:
            records.append(parsed)

    if not records:
        return pd.DataFrame(columns=[
            "timestamp", "ip", "username", "event_type", "status", "raw_line"
        ])

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def _parse_line(line: str, lineno: int) -> Optional[Dict]:
    """Parse a single log line; return None when the line cannot be parsed."""
    match = LOG_PATTERN.match(line)
    if not match:
        return None

    timestamp_str = match.group("timestamp")
    timestamp = _parse_timestamp(timestamp_str)
    message = match.group("message")

    ip = _extract_value(IP_PATTERN, message)
    username = _extract_value(USER_PATTERN, message)

    event_type, status = _classify_event(message)

    return {
        "timestamp": timestamp,
        "ip": ip,
        "username": username,
        "event_type": event_type,
        "status": status,
        "raw_line": line,
    }


def _parse_timestamp(raw: str) -> datetime:
    """
    Parse syslog-style timestamps (no year) and attach the current year.
    If parsing fails, fall back to the current time to avoid losing the line.
    """
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {raw}", "%Y %b %d %H:%M:%S")
        return dt
    except ValueError:
        return datetime.now()


def _classify_event(message: str) -> tuple[str, str]:
    """Infer event type and status from the message text."""
    if "Failed password" in message:
        return "PASSWORD_AUTH", "failure"
    if "Accepted password" in message or "Accepted publickey" in message:
        return "PASSWORD_AUTH", "success"
    if "Invalid user" in message:
        return "INVALID_USER", "failure"
    if "Disconnected from" in message or "Connection closed" in message:
        return "SESSION", "info"
    return "OTHER", "unknown"


def _extract_value(pattern: re.Pattern, text: str) -> Optional[str]:
    """Return the first regex capture or None."""
    match = pattern.search(text)
    return match.group(1) if match else None
