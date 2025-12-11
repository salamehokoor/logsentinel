"""
SQLite persistence for alerts and dashboard summaries.

The database is intentionally simple: a single alerts table and a single-row
dashboard_summary table that holds the latest aggregates for the dashboard.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List


def init_db(db_path: Path) -> None:
    """Create the database and tables if they do not exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        # Use default DELETE journal mode to avoid -wal/-shm sidecars.
        conn.execute("PRAGMA journal_mode=DELETE;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                severity TEXT,
                source_ip TEXT,
                count INTEGER,
                time_start TEXT,
                time_end TEXT,
                details TEXT,
                username TEXT,
                created_at TEXT NOT NULL
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_summary (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                total_events INTEGER,
                failed_logins INTEGER,
                unique_attackers INTEGER,
                alerts_by_type TEXT,
                alerts_by_severity TEXT,
                attack_patterns TEXT,
                generated_at TEXT NOT NULL
            )
            """)


def save_results(db_path: Path, alerts: List[Dict],
                 dashboard_data: Dict) -> None:
    """Replace stored alerts and dashboard summary with the latest run."""
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM alerts")
        if alerts:
            conn.executemany(
                """
                INSERT INTO alerts (
                    type, severity, source_ip, count, time_start, time_end,
                    details, username, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [(
                    alert.get("type"),
                    alert.get("severity"),
                    alert.get("source_ip"),
                    alert.get("count"),
                    alert.get("time_start"),
                    alert.get("time_end"),
                    alert.get("details"),
                    alert.get("username"),
                    now,
                ) for alert in alerts],
            )

        conn.execute("DELETE FROM dashboard_summary")
        conn.execute(
            """
            INSERT OR REPLACE INTO dashboard_summary (
                id, total_events, failed_logins, unique_attackers,
                alerts_by_type, alerts_by_severity, attack_patterns, generated_at
            )
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dashboard_data.get("total_events", 0),
                dashboard_data.get("failed_logins", 0),
                dashboard_data.get("unique_attackers", 0),
                json.dumps(dashboard_data.get("alerts_by_type", {})),
                json.dumps(dashboard_data.get("alerts_by_severity", {})),
                json.dumps(dashboard_data.get("attack_patterns", {})),
                now,
            ),
        )


def read_alerts(db_path: Path) -> List[Dict]:
    """Return all stored alerts, newest first."""
    if not db_path.exists():
        return []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT type, severity, source_ip, count, time_start, time_end,
                   details, username, created_at
            FROM alerts
            ORDER BY time_start DESC
            """).fetchall()
    return [dict(row) for row in rows]


def read_dashboard(db_path: Path) -> Dict:
    """Return the latest dashboard summary or an empty baseline."""
    baseline = {
        "total_events": 0,
        "failed_logins": 0,
        "unique_attackers": 0,
        "alerts_by_type": {},
        "alerts_by_severity": {},
        "attack_patterns": {
            "failed_logins_by_hour": [],
            "top_source_ips": [],
            "top_usernames": [],
        },
    }
    if not db_path.exists():
        return baseline

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT total_events, failed_logins, unique_attackers,
                   alerts_by_type, alerts_by_severity, attack_patterns, generated_at
            FROM dashboard_summary
            WHERE id = 1
            """).fetchone()

    if not row:
        return baseline

    result = {
        "total_events": row["total_events"] or 0,
        "failed_logins": row["failed_logins"] or 0,
        "unique_attackers": row["unique_attackers"] or 0,
        "alerts_by_type": json.loads(row["alerts_by_type"] or "{}"),
        "alerts_by_severity": json.loads(row["alerts_by_severity"] or "{}"),
        "attack_patterns": json.loads(row["attack_patterns"] or "{}"),
        "generated_at": row["generated_at"],
    }
    # Ensure nested keys exist for the dashboard.
    result["attack_patterns"].setdefault("failed_logins_by_hour", [])
    result["attack_patterns"].setdefault("top_source_ips", [])
    result["attack_patterns"].setdefault("top_usernames", [])
    return result
