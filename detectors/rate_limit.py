"""
Rate limit detector: flags IPs exceeding requests per minute thresholds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

import pandas as pd


@dataclass
class RateLimitDetector:
    """Detect IPs that exceed a per-minute request volume."""

    threshold_per_minute: int = 20
    name: str = "RateLimitDetector"

    def detect(self, df: pd.DataFrame) -> List[Dict]:
        """
        Run detection on the provided DataFrame.

        Args:
            df: Parsed log events.

        Returns:
            List of alert dictionaries.
        """
        records = df[df["ip"].notna()].copy()
        if records.empty:
            return []

        records = records.sort_values("timestamp")
        alerts: List[Dict] = []

        for ip, ip_df in records.groupby("ip"):
            ip_df = ip_df.set_index("timestamp")
            per_minute = ip_df.resample("1min").size()
            top_user = None
            user_counts = ip_df["username"].dropna().value_counts()
            if not user_counts.empty:
                top_user = user_counts.index[0]

            for ts, count in per_minute.items():
                if count > self.threshold_per_minute:
                    alerts.append({
                        "type":
                        "RATE_LIMIT",
                        "severity":
                        "medium",
                        "source_ip":
                        ip,
                        "count":
                        int(count),
                        "time_start":
                        ts.isoformat(timespec="seconds"),
                        "time_end": (ts + pd.Timedelta(minutes=1)).isoformat(
                            timespec="seconds"),
                        "details":
                        f"Exceeded {self.threshold_per_minute} events per minute",
                        "username":
                        top_user,
                    })

        return alerts
