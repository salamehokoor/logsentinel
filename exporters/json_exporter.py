"""
JSON exporter utilities for alerts and dashboard data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def export_alerts(alerts: List[Dict], path: Path) -> None:
    """
    Write alerts to a JSON file.

    Args:
        alerts: List of alert dictionaries.
        path: Destination path.
    """
    write_json(alerts, path)


def write_json(data: Any, path: Path) -> None:
    """Serialize data to JSON with indentation."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
