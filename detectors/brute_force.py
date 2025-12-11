"""
Brute force detector: flags repeated failed logins from the same IP within a rolling window.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

import pandas as pd


@dataclass
class BruteForceDetector:
    """Detect repeated failed logins from a single IP within a short window."""

    threshold: int = 5
    window_minutes: int = 5
    name: str = "BruteForceDetector"

    def detect(self, df: pd.DataFrame) -> List[Dict]:
        """
        Run detection on the provided DataFrame.

        Args:
            df: Parsed log events.

        Returns:
            List of alert dictionaries.
        """
        failures = df[(df["status"] == "failure") & df["ip"].notna()].copy()
        if failures.empty:
            return []

        failures = failures.sort_values(["ip", "timestamp"])
        alerts: List[Dict] = []

        for ip, ip_df in failures.groupby("ip"):
            ip_df = ip_df.set_index("timestamp")
            window_counts = ip_df["event_type"].rolling(
                f"{self.window_minutes}min").count()
            max_count = int(
                window_counts.max()) if not window_counts.empty else 0

            if max_count >= self.threshold:
                top_user = None
                user_counts = ip_df["username"].dropna().value_counts()
                if not user_counts.empty:
                    top_user = user_counts.index[0]

                trigger_times = window_counts[window_counts >=
                                              self.threshold].index
                time_start = trigger_times.min()
                time_end = trigger_times.max()
                alerts.append({
                    "type":
                    "BRUTE_FORCE",
                    "severity":
                    "high",
                    "source_ip":
                    ip,
                    "count":
                    max_count,
                    "time_start":
                    time_start.isoformat(timespec="seconds"),
                    "time_end":
                    time_end.isoformat(timespec="seconds"),
                    "details":
                    f"Repeated failed logins within {self.window_minutes} minutes",
                    "username":
                    top_user,
                })

        return alerts
