"""
Entry point for the LogSentinel mini-SIEM.

Pipeline:
1) Parse auth logs into a pandas DataFrame.
2) Run detectors to generate alerts.
3) Export alerts JSON and dashboard summary JSON.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List

import pandas as pd

from detectors.brute_force import BruteForceDetector
from detectors.rate_limit import RateLimitDetector
from detectors.suspicious_ip import SuspiciousIPDetector
from exporters.json_exporter import export_alerts, write_json
from parsers.auth_parser import parse_auth_log


def run_pipeline(
    log_file: Path,
    alerts_output: Path,
    dashboard_output: Path,
    input_format: str = "linux",
    windows_log: str = "Security",
    brute_threshold: int = 5,
    brute_window_minutes: int = 5,
    rate_threshold_per_minute: int = 20,
) -> None:
    """
    Execute the parse → detect → export pipeline.

    Args:
        log_file: Path to the auth log to process (linux mode).
        alerts_output: Path to write the alerts JSON file.
        dashboard_output: Path to write the dashboard summary JSON file.
        input_format: "linux" for file-based auth logs, "windows" for Event Log.
        windows_log: Windows Event Log name to read (default: Security).
        brute_threshold: Failed login count to trigger brute-force alert.
        brute_window_minutes: Time window for brute-force detection (minutes).
        rate_threshold_per_minute: Event volume to trigger rate-limit alert.
    """
    if input_format == "windows":
        try:
            from parsers.windows_event_parser import parse_windows_security_log
        except ImportError as exc:
            raise SystemExit(
                "pywin32 is required for Windows Event Log parsing. Install with `pip install pywin32`."
            ) from exc
        try:
            df = parse_windows_security_log(log_name=windows_log)
        except Exception as exc:
            raise SystemExit(
                f"[ERROR] Windows Event Log read failed: {exc}") from exc
    else:
        df = parse_auth_log(log_file)
    if df.empty:
        print(f"[WARN] No events parsed from {log_file}. Nothing to do.")
        return

    detectors = [
        BruteForceDetector(threshold=brute_threshold,
                           window_minutes=brute_window_minutes),
        SuspiciousIPDetector(),
        RateLimitDetector(threshold_per_minute=rate_threshold_per_minute),
    ]

    alerts: List[Dict] = []
    for detector in detectors:
        detected = detector.detect(df)
        alerts.extend(detected)
        print(f"[INFO] {detector.name} produced {len(detected)} alert(s).")

    export_alerts(alerts, alerts_output)
    print(f"[INFO] Wrote {len(alerts)} total alerts to {alerts_output}.")

    dashboard_data = build_dashboard_data(df, alerts)
    write_json(dashboard_data, dashboard_output)
    print(f"[INFO] Wrote dashboard summary to {dashboard_output}.")


def build_dashboard_data(df: pd.DataFrame, alerts: List[Dict]) -> Dict:
    """
    Create a compact dashboard summary for downstream UI consumption.

    Args:
        df: Parsed log events.
        alerts: Alerts produced by detectors.

    Returns:
        Dictionary formatted for JSON serialization with headline stats and
        simple attack-pattern rollups.
    """
    failed_df = df[df["status"] == "failure"]
    summary = {
        "total_events": int(len(df)),
        "failed_logins": int(len(failed_df)),
        "unique_attackers": int(failed_df["ip"].nunique(dropna=True)),
        "alerts_by_type": {},
        "alerts_by_severity": {},
        "attack_patterns": {
            "failed_logins_by_hour": [],
            "top_source_ips": [],
            "top_usernames": [],
        },
    }

    for alert in alerts:
        summary["alerts_by_type"].setdefault(alert["type"], 0)
        summary["alerts_by_type"][alert["type"]] += 1
        severity = alert.get("severity", "unknown")
        summary["alerts_by_severity"].setdefault(severity, 0)
        summary["alerts_by_severity"][severity] += 1

    if not failed_df.empty:
        # Basic temporal and categorical patterns to support charts/heatmaps.
        failures_by_hour = (
            failed_df.set_index("timestamp").resample("1h").size())
        summary["attack_patterns"]["failed_logins_by_hour"] = [{
            "hour":
            ts.isoformat(timespec="seconds"),
            "count":
            int(count),
        } for ts, count in failures_by_hour.items() if count > 0]

        top_ips = failed_df["ip"].dropna().value_counts().head(5)
        summary["attack_patterns"]["top_source_ips"] = [{
            "ip": ip,
            "failures": int(count)
        } for ip, count in top_ips.items()]

        top_users = failed_df["username"].dropna().value_counts().head(5)
        summary["attack_patterns"]["top_usernames"] = [{
            "username": user,
            "failures": int(count)
        } for user, count in top_users.items()]

    return summary


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="LogSentinel - Security Log Analyzer")
    parser.add_argument(
        "--input-format",
        choices=["linux", "windows"],
        default="linux",
        help="Parse Linux auth log file or Windows Event Log (default: linux)",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("data") / "sample_auth.log",
        help=
        "Path to auth log file (linux only, default: data/sample_auth.log)",
    )
    parser.add_argument(
        "--windows-log",
        default="Security",
        help=
        "Windows Event Log name when --input-format=windows (default: Security)",
    )
    parser.add_argument(
        "--brute-threshold",
        type=int,
        default=5,
        help="Failed login count to trigger brute-force alert (default: 5)",
    )
    parser.add_argument(
        "--brute-window-minutes",
        type=int,
        default=5,
        help="Time window in minutes for brute-force detection (default: 5)",
    )
    parser.add_argument(
        "--rate-threshold-per-minute",
        type=int,
        default=20,
        help=
        "Event volume per minute to trigger rate-limit alert (default: 20)",
    )
    parser.add_argument(
        "--alerts-output",
        type=Path,
        default=Path("data") / "alerts.json",
        help="Where to write alerts JSON (default: data/alerts.json)",
    )
    parser.add_argument(
        "--dashboard-output",
        type=Path,
        default=Path("data") / "dashboard_data.json",
        help=
        "Where to write dashboard summary JSON (default: data/dashboard_data.json)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_pipeline(
        log_file=args.log_file,
        alerts_output=args.alerts_output,
        dashboard_output=args.dashboard_output,
        input_format=args.input_format,
        windows_log=args.windows_log,
        brute_threshold=args.brute_threshold,
        brute_window_minutes=args.brute_window_minutes,
        rate_threshold_per_minute=args.rate_threshold_per_minute,
    )
