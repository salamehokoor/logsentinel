from __future__ import annotations

import sys
from pathlib import Path

# Ensure repository root is on sys.path for direct imports.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from detectors.brute_force import BruteForceDetector  # noqa: E402
from detectors.rate_limit import RateLimitDetector  # noqa: E402
from detectors.suspicious_ip import SuspiciousIPDetector  # noqa: E402
from parsers.auth_parser import parse_auth_log  # noqa: E402


def _load_sample_df():
    return parse_auth_log(PROJECT_ROOT / "data" / "sample_auth.log")


def test_brute_force_detector() -> None:
    df = _load_sample_df()
    alerts = BruteForceDetector(threshold=5, window_minutes=5).detect(df)

    assert len(alerts) == 2
    for alert in alerts:
        assert alert["type"] == "BRUTE_FORCE"
        assert alert["severity"] == "high"
        assert alert["count"] >= 5
        assert alert["source_ip"]
        assert alert["time_start"]
        assert alert["time_end"]


def test_rate_limit_detector() -> None:
    df = _load_sample_df()
    alerts = RateLimitDetector(threshold_per_minute=20).detect(df)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "RATE_LIMIT"
    assert alert["severity"] == "medium"
    assert alert["count"] > 20
    assert alert["source_ip"]


def test_suspicious_ip_detector() -> None:
    df = _load_sample_df()
    alerts = SuspiciousIPDetector().detect(df)

    assert len(alerts) == 3
    for alert in alerts:
        assert alert["type"] == "SUSPICIOUS_IP"
        assert alert["severity"] == "medium"
        assert alert["source_ip"]
        assert alert["count"] >= 1
