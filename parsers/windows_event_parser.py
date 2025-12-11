"""
Windows Event Log parser for Security logon events.

Produces a pandas DataFrame with the same schema as the Linux auth parser:
timestamp, ip, username, event_type, status, raw_line.

Requirements:
- pywin32 installed on Windows (win32evtlog).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd

try:
    import win32evtlog  # type: ignore
    import pywintypes  # type: ignore
except ImportError as exc:  # pragma: no cover - platform import guard
    raise ImportError(
        "pywin32 is required for Windows Event Log parsing. Install with `pip install pywin32`."
    ) from exc

# Event IDs of interest for logon activity.
LOGON_FAILED = 4625
LOGON_SUCCESS = 4624
LOGOFF = 4634

# Extract username and IP from event string payloads.
USER_PATTERN = re.compile(r"(?im)^Account\s+Name:\s*(?P<user>[^\s].*?)\s*$")
IP_PATTERN = re.compile(
    r"(?im)^Source\s+Network\s+Address:\s*(?P<ip>[^\s].*?)\s*$")


def parse_windows_security_log(log_name: str = "Security",
                               server: str = "localhost") -> pd.DataFrame:
    """
    Read Windows Event Log (Security) and normalize to the shared schema.

    Args:
        log_name: Event log name (default: Security).
        server: Host to query (default: localhost).

    Returns:
        pandas DataFrame with columns: timestamp, ip, username, event_type, status, raw_line.
    """
    try:
        handle = win32evtlog.OpenEventLog(server, log_name)
    except pywintypes.error as err:
        code = getattr(err, "winerror",
                       None) or (err.args[0] if err.args else None)
        if code == 1314:
            raise RuntimeError(
                "Access denied to Windows Event Log. Run PowerShell as Administrator or choose a readable log (e.g., Application) via --windows-log."
            ) from err
        raise
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    records: List[Dict] = []
    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0) or []
        if not events:
            break
        for evt in events:
            normalized = _to_record(evt)
            if normalized:
                records.append(normalized)

    if not records:
        return pd.DataFrame(columns=[
            "timestamp", "ip", "username", "event_type", "status", "raw_line"
        ])

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def _to_record(evt) -> Optional[Dict]:
    """
    Convert a pywin32 event to a normalized dict.

    We only map a handful of logon-related Event IDs; everything else is skipped.
    """
    event_id = evt.EventID & 0xFFFF  # low word is the actual ID

    if event_id not in {LOGON_FAILED, LOGON_SUCCESS, LOGOFF}:
        return None

    payload = "\n".join(evt.StringInserts or [])
    username = _extract(USER_PATTERN, payload)
    ip = _extract(IP_PATTERN, payload)

    if event_id == LOGON_FAILED:
        event_type, status = "PASSWORD_AUTH", "failure"
    elif event_id == LOGON_SUCCESS:
        event_type, status = "PASSWORD_AUTH", "success"
    else:
        event_type, status = "SESSION", "info"

    return {
        "timestamp":
        _safe_timestamp(evt.TimeGenerated),
        "ip":
        ip if ip and ip != "-" else None,
        "username":
        username if username and username != "-" else None,
        "event_type":
        event_type,
        "status":
        status,
        "raw_line":
        f"EventID={event_id} Source={evt.SourceName} Record={evt.RecordNumber}",
    }


def _extract(pattern: re.Pattern, text: str) -> Optional[str]:
    match = pattern.search(text)
    return match.group(1) if match else None


def _safe_timestamp(dt) -> datetime:
    try:
        return datetime.fromtimestamp(dt.timestamp())
    except Exception:
        return datetime.now()
