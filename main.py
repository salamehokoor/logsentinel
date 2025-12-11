"""
Entry point for the LogSentinel mini-SIEM.

Pipeline:
1) Parse auth logs into a pandas DataFrame.
2) Run detectors to generate alerts.
3) Persist alerts and dashboard summary to SQLite for the dashboard/API.
"""

from __future__ import annotations

import argparse
import platform
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

from detectors.brute_force import BruteForceDetector
from detectors.rate_limit import RateLimitDetector
from detectors.suspicious_ip import SuspiciousIPDetector
from parsers.auth_parser import parse_auth_log
from services.dashboard_server import start_dashboard_server
from storage.db import init_db, save_results


def run_pipeline(
    log_file: Optional[Path],
    input_format: str = "linux",
    windows_log: str = "Security",
    brute_threshold: int = 5,
    brute_window_minutes: int = 5,
    rate_threshold_per_minute: int = 20,
    db_path: Path = Path("data") / "logsentinel.sqlite",
) -> None:
    """
    Execute the parse → detect → persist pipeline (SQLite-backed).

    Args:
        log_file: Path to the auth log to process (linux mode).
        input_format: "linux" for file-based auth logs, "windows" for Event Log.
        windows_log: Windows Event Log name to read (default: Security).
        brute_threshold: Failed login count to trigger brute-force alert.
        brute_window_minutes: Time window for brute-force detection (minutes).
        rate_threshold_per_minute: Event volume to trigger rate-limit alert.
        db_path: SQLite database location for storing results.
    """
    if input_format == "windows":
        try:
            from parsers.windows_event_parser import parse_windows_security_log
        except ImportError as exc:
            raise SystemExit(
                "pywin32 is required for Windows Event Log parsing. Install with `pip install pywin32`."
            ) from exc
        source_label = f"Windows Event Log '{windows_log}'"
        try:
            df = parse_windows_security_log(log_name=windows_log)
            source_label = f"Windows Event Log '{windows_log}'"
        except Exception as exc:
            err_msg = str(exc)
            if "Access denied" in err_msg and windows_log != "Application":
                print(
                    "[WARN] Access denied to Windows Event Log "
                    f"'{windows_log}'. Falling back to 'Application'.")
                df = parse_windows_security_log(log_name="Application")
                source_label = "Windows Event Log 'Application'"
            else:
                raise SystemExit(
                    f"[ERROR] Windows Event Log read failed: {exc}") from exc
    elif input_format == "windows-fake":
        from parsers.windows_fake_parser import load_fake_windows_events

        df, source_label = load_fake_windows_events(db_path)
    else:
        if not log_file:
            raise SystemExit(
                "[ERROR] No log file provided for linux input format.")
        if not log_file.exists():
            raise SystemExit(f"[ERROR] Log file not found: {log_file}")
        source_label = str(log_file)
        df = parse_auth_log(log_file)
    if df.empty:
        print(f"[WARN] No events parsed from {source_label}. Nothing to do.")
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

    dashboard_data = build_dashboard_data(df, alerts)

    save_results(db_path, alerts, dashboard_data)
    print(
        f"[INFO] Persisted {len(alerts)} alerts and dashboard summary to {db_path}."
    )


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
        choices=["auto", "linux", "windows", "windows-fake"],
        default="auto",
        help="Auto-detect OS (default), or force linux file / windows Event Log",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Path to auth log file (linux only). If omitted, common system paths are tried.",
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
        "--interval-seconds",
        type=int,
        default=30,
        help="How often to re-run the pipeline in live mode (default: 30)",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=Path("data") / "logsentinel.sqlite",
        help="Path to the SQLite database for alerts and dashboard data.",
    )
    parser.add_argument(
        "--serve-port",
        type=int,
        default=8000,
        help="Port for the built-in dashboard/API server (default: 8000).",
    )
    parser.add_argument(
        "--no-serve",
        action="store_true",
        help="Run pipeline only (disable dashboard/API server).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single pipeline pass and exit (disables live mode)",
    )
    return parser.parse_args()


LINUX_LOG_CANDIDATES = [
    Path("/var/log/auth.log"),
    Path("/var/log/secure"),
    Path("/var/log/syslog"),
]

LEGACY_JSON_OUTPUTS = [
    Path("data") / "alerts.json",
    Path("data") / "dashboard_data.json",
]
LEGACY_DB_SIDECARS = [
    Path("data") / "logsentinel.db-wal",
    Path("data") / "logsentinel.db-shm",
]
LEGACY_DB = Path("data") / "logsentinel.db"


def cleanup_legacy_json_outputs() -> None:
    """Remove legacy JSON outputs to keep the pipeline DB-only."""
    for path in LEGACY_JSON_OUTPUTS:
        if path.exists():
            try:
                path.unlink()
                print(f"[INFO] Removed legacy JSON output {path}")
            except Exception as exc:  # pragma: no cover - best effort cleanup
                print(f"[WARN] Could not remove {path}: {exc}")

    for path in LEGACY_DB_SIDECARS:
        if path.exists():
            try:
                path.unlink()
                print(f"[INFO] Removed legacy DB sidecar {path}")
            except Exception as exc:  # pragma: no cover - best effort cleanup
                print(f"[WARN] Could not remove {path}: {exc}")


def migrate_legacy_db(db_path: Path) -> None:
    """
    If the old logsentinel.db exists and the new target does not, copy it over.
    Prevents data loss when switching default DB names.
    """
    if db_path.exists():
        return
    if LEGACY_DB.exists() and LEGACY_DB != db_path:
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(LEGACY_DB, db_path)
            print(f"[INFO] Migrated legacy DB from {LEGACY_DB} to {db_path}")
        except Exception as exc:  # pragma: no cover - best effort migration
            print(f"[WARN] Could not migrate legacy DB: {exc}")

    for path in LEGACY_DB_SIDECARS:
        if path.exists():
            try:
                path.unlink()
                print(f"[INFO] Removed legacy DB sidecar {path}")
            except Exception as exc:  # pragma: no cover - best effort cleanup
                print(f"[WARN] Could not remove {path}: {exc}")


def resolve_input_source(
    args: argparse.Namespace) -> Tuple[str, Optional[Path]]:
    """
    Choose input format and source based on OS and CLI overrides.

    Returns:
        A tuple of (input_format, log_file_path_or_None).
    """
    if args.input_format == "auto":
        system = platform.system().lower()
        if system == "windows":
            return "windows", None
        return "linux", _pick_linux_log(args.log_file)

    if args.input_format == "windows-fake":
        return "windows-fake", None

    if args.input_format == "linux":
        return "linux", _pick_linux_log(args.log_file)

    return "windows", None


def _pick_linux_log(explicit: Optional[Path]) -> Path:
    """Return the explicit path or the first existing system auth log."""
    if explicit:
        if not explicit.exists():
            raise SystemExit(f"[ERROR] Provided log file not found: {explicit}")
        return explicit

    for candidate in LINUX_LOG_CANDIDATES:
        if candidate.exists():
            return candidate

    checked = ", ".join(str(p) for p in LINUX_LOG_CANDIDATES)
    raise SystemExit(
        f"[ERROR] No Linux auth log found. Checked: {checked}. "
        "Provide --log-file to point at your auth log.")


def run_live_mode(pipeline_kwargs: Dict, interval: int) -> None:
    """
    Continuously re-run the pipeline until interrupted.

    Press Ctrl+C to exit. Interval is clamped to at least one second to avoid
    tight loops if an invalid value is provided.
    """
    interval = interval
    if interval < 1:
        print(
            f"[WARN] interval-seconds={interval} is too small; using 1 second.")
        interval = 1

    source_descr = (f"log_file={pipeline_kwargs['log_file']}"
                    if pipeline_kwargs["input_format"] == "linux" else
                    f"windows_log={pipeline_kwargs['windows_log']}")

    print(
        f"[INFO] Live mode started ({pipeline_kwargs['input_format']}, {source_descr}). "
        f"Running every {interval} seconds. Press Ctrl+C to stop."
    )

    while True:
        run_started = datetime.now().isoformat(timespec="seconds")
        print(f"[INFO] [{run_started}] Pipeline run starting...")
        try:
            run_pipeline(**pipeline_kwargs)
        except KeyboardInterrupt:
            # Allow outer handler to surface clean exit message.
            raise
        except Exception as exc:  # noqa: BLE001 - best-effort live mode resilience
            print(f"[ERROR] Pipeline run failed at {run_started}: {exc}")

        print(f"[INFO] Sleeping for {interval} seconds. Press Ctrl+C to stop.")
        time.sleep(interval)


def main() -> None:
    cleanup_legacy_json_outputs()

    args = parse_args()
    input_format, log_file = resolve_input_source(args)

    migrate_legacy_db(args.db_path)
    init_db(args.db_path)

    server = None
    if not args.no_serve:
        server = start_dashboard_server(
            db_path=args.db_path,
            port=args.serve_port,
            frontend_dir=Path("frontend"),
        )

    pipeline_kwargs = {
        "log_file": log_file,
        "input_format": input_format,
        "windows_log": args.windows_log,
        "brute_threshold": args.brute_threshold,
        "brute_window_minutes": args.brute_window_minutes,
        "rate_threshold_per_minute": args.rate_threshold_per_minute,
        "db_path": args.db_path,
    }
    try:
        if args.once:
            run_pipeline(**pipeline_kwargs)
        else:
            run_live_mode(pipeline_kwargs, args.interval_seconds)
    except KeyboardInterrupt:
        print("\n[INFO] Live mode stopped by user request.")
    finally:
        if server:
            server.shutdown()


if __name__ == "__main__":
    main()
