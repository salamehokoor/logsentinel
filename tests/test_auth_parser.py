from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

# Ensure repository root is on sys.path for direct imports.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from parsers.auth_parser import parse_auth_log  # noqa: E402


def test_parse_auth_log_sample_counts() -> None:
    sample_path = PROJECT_ROOT / "data" / "sample_auth.log"
    df = parse_auth_log(sample_path)

    assert not df.empty
    assert set(["timestamp", "ip", "username", "event_type", "status", "raw_line"]).issubset(
        df.columns
    )
    assert len(df) == 41
    assert df[df["status"] == "failure"].shape[0] == 37
    assert df["ip"].dropna().nunique() == 9


def test_parse_auth_log_timestamp_type() -> None:
    sample_path = PROJECT_ROOT / "data" / "sample_auth.log"
    df = parse_auth_log(sample_path)
    assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])
