"""
Suspicious IP detector: flags events originating from known malicious CIDR ranges.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

import pandas as pd

DEFAULT_SUSPICIOUS_CIDRS = [
    "203.0.113.0/24",
    "198.51.100.0/24",
    "45.83.0.0/16",
    "185.220.100.0/24",
]


@dataclass
class SuspiciousIPDetector:
    """Detect events sourced from known malicious CIDR ranges."""

    cidrs: Sequence[str] = field(
        default_factory=lambda: DEFAULT_SUSPICIOUS_CIDRS)
    name: str = "SuspiciousIPDetector"

    def __post_init__(self) -> None:
        self.networks = [ipaddress.ip_network(cidr) for cidr in self.cidrs]

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

        alerts: List[Dict] = []
        for ip, ip_df in records.groupby("ip"):
            if not self._is_suspicious(ip):
                continue

            top_user = None
            user_counts = ip_df["username"].dropna().value_counts()
            if not user_counts.empty:
                top_user = user_counts.index[0]

            time_start = ip_df["timestamp"].min()
            time_end = ip_df["timestamp"].max()

            alerts.append({
                "type":
                "SUSPICIOUS_IP",
                "severity":
                "medium",
                "source_ip":
                ip,
                "count":
                int(len(ip_df)),
                "time_start":
                time_start.isoformat(timespec="seconds"),
                "time_end":
                time_end.isoformat(timespec="seconds"),
                "details":
                f"Source IP falls within suspicious ranges: {', '.join(self.cidrs)}",
                "username":
                top_user,
            })

        return alerts

    def _is_suspicious(self, ip: str) -> bool:
        """Check if an IP belongs to any known bad network."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        return any(addr in network for network in self.networks)
