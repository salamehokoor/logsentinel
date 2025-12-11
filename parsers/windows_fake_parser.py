"""
Synthetic Windows Security log events for demo/testing without pywin32.

Reads from a SQLite table (windows_fake_events) and seeds it automatically if
empty so the dashboard can always load fake data without any extra files.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
from zoneinfo import ZoneInfo

import pandas as pd

FAKE_EVENTS: List[Dict] = [
    {
        "timestamp":
        "2025-12-11T18:30:00",
        "ip":
        "203.0.113.10",
        "username":
        "alice",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10001",
    },
    {
        "timestamp":
        "2025-12-11T18:30:15",
        "ip":
        "203.0.113.10",
        "username":
        "alice",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10002",
    },
    {
        "timestamp":
        "2025-12-11T18:31:05",
        "ip":
        "198.51.100.77",
        "username":
        "svc-backup",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10003",
    },
    {
        "timestamp":
        "2025-12-11T18:31:20",
        "ip":
        "198.51.100.77",
        "username":
        "svc-backup",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10004",
    },
    {
        "timestamp":
        "2025-12-11T18:31:35",
        "ip":
        "198.51.100.77",
        "username":
        "svc-backup",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10005",
    },
    {
        "timestamp":
        "2025-12-11T18:32:00",
        "ip":
        "203.0.113.10",
        "username":
        "alice",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "success",
        "raw_line":
        "EventID=4624 Source=Microsoft-Windows-Security-Auditing Record=10006",
    },
    {
        "timestamp":
        "2025-12-11T18:33:10",
        "ip":
        "45.83.23.12",
        "username":
        "deploy",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10007",
    },
    {
        "timestamp":
        "2025-12-11T18:33:45",
        "ip":
        "45.83.23.12",
        "username":
        "deploy",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10008",
    },
    {
        "timestamp":
        "2025-12-11T18:34:10",
        "ip":
        "10.10.10.10",
        "username":
        "ghost",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10009",
    },
    {
        "timestamp":
        "2025-12-11T18:34:15",
        "ip":
        "10.10.10.10",
        "username":
        "ghost",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10010",
    },
    {
        "timestamp":
        "2025-12-11T18:34:20",
        "ip":
        "10.10.10.10",
        "username":
        "ghost",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10011",
    },
    {
        "timestamp":
        "2025-12-11T18:34:25",
        "ip":
        "10.10.10.10",
        "username":
        "ghost",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "failure",
        "raw_line":
        "EventID=4625 Source=Microsoft-Windows-Security-Auditing Record=10012",
    },
    {
        "timestamp":
        "2025-12-11T18:35:00",
        "ip":
        "10.10.10.10",
        "username":
        "ghost",
        "event_type":
        "PASSWORD_AUTH",
        "status":
        "success",
        "raw_line":
        "EventID=4624 Source=Microsoft-Windows-Security-Auditing Record=10013",
    },
]
APP_TZ = ZoneInfo("Asia/Amman")


def load_fake_windows_events(db_path: Path) -> Tuple[pd.DataFrame, str]:
    """
    Load synthetic Windows Security events from SQLite, seeding if empty.

    Returns:
        (DataFrame, source_label)
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS windows_fake_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                username TEXT,
                event_type TEXT,
                status TEXT,
                raw_line TEXT
            )
            """)
        cur = conn.execute("SELECT COUNT(1) FROM windows_fake_events")
        count = cur.fetchone()[0]
        if count == 0:
            conn.executemany(
                """
                INSERT INTO windows_fake_events (timestamp, ip, username, event_type, status, raw_line)
                VALUES (:timestamp, :ip, :username, :event_type, :status, :raw_line)
                """,
                FAKE_EVENTS,
            )
        rows = conn.execute("""
            SELECT timestamp, ip, username, event_type, status, raw_line
            FROM windows_fake_events
            ORDER BY timestamp ASC
            """).fetchall()

    if not rows:
        return pd.DataFrame(columns=[
            "timestamp", "ip", "username", "event_type", "status", "raw_line"
        ]), f"{db_path} (windows_fake_events)"

    df = pd.DataFrame(rows,
                      columns=[
                          "timestamp", "ip", "username", "event_type",
                          "status", "raw_line"
                      ])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["timestamp"] = df["timestamp"].dt.tz_localize(APP_TZ,
                                                     nonexistent="NaT",
                                                     ambiguous="NaT")
    return df, f"{db_path} (windows_fake_events)"
