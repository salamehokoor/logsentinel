# LogSentinel

LogSentinel is a Python mini-SIEM that ingests Linux authentication logs or Windows Event Logs, detects suspicious activity, and persists alerts plus dashboard-ready summaries into SQLite (served via a built-in API). It is intentionally modular so you can plug in new detectors or swap parsers without rewriting the pipeline.

## Features
- Auth log parsing (Linux) with regex, pandas DataFrame output, and graceful handling of malformed lines.
- Windows Event Log parsing (pywin32) to reuse the same pipeline.
- Detectors for brute force, suspicious IP ranges, and per-minute rate limiting (now CLI-tunable thresholds).
- SQLite persistence plus a built-in HTTP server exposing `/api/dashboard` and `/api/alerts` for the dashboard.
- Dashboard-ready summary (alerts by type/severity, failed logins, top attackers, temporal rollups).
- Easy to extend with additional detectors.
- Timestamps are normalized to the Asia/Amman timezone in outputs and dashboard.

## Installation
1) Ensure Python 3.9+ is available.  
2) Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Quick start (auto OS detection):
```bash
python main.py
```
Then open `http://localhost:8000` (or `/frontend/`) for the dashboard. The server exposes `/api/dashboard` and `/api/alerts` from SQLite (`data/logsentinel.sqlite`).

Linux/macOS (file-based):
- Default: tries `/var/log/auth.log`, then `/var/log/secure`, then `/var/log/syslog`.
- Override: `python main.py --log-file /path/to/auth.log`

Windows Event Log:
- Admin for Security log: `python main.py --input-format windows --windows-log Security`
- No admin: `python main.py --input-format windows --windows-log Application`

Synthetic Windows feed (no pywin32 needed):
- `python main.py --input-format windows-fake` (seeds/reads synthetic events from SQLite)

Useful flags:
- `--input-format`: `auto` | `linux` | `windows` | `windows-fake`
- `--db-path`: SQLite location (default: `data/logsentinel.sqlite`)
- `--serve-port`: dashboard/API port (default: 8000)
- `--interval-seconds`: live loop cadence (default: 30)
- `--once`: single pass and exit
- `--brute-threshold`, `--brute-window-minutes`, `--rate-threshold-per-minute`: detector tuning

## Tests
Install dev/test deps (pytest is already listed in `requirements.txt`):
```bash
pip install -r requirements.txt
pytest
```

Included:
- `tests/test_auth_parser.py`: validates the sample auth log parses correctly.
- `tests/test_detectors.py`: smoke tests for brute-force, rate-limit, and suspicious-IP detectors on the sample log.

## Example Output
Example alert returned from `GET /api/alerts`:
```json
{
  "type": "BRUTE_FORCE",
  "severity": "high",
  "source_ip": "198.51.100.77",
  "count": 6,
  "time_start": "2025-11-10T06:35:01",
  "time_end": "2025-11-10T06:36:30",
  "details": "Repeated failed logins within 5 minutes"
}
```

Example dashboard summary from `GET /api/dashboard`:
```json
{
  "total_events": 40,
  "failed_logins": 24,
  "unique_attackers": 3,
  "alerts_by_type": {
    "BRUTE_FORCE": 1,
    "SUSPICIOUS_IP": 1,
    "RATE_LIMIT": 1
  }
}
```

## Future Improvements
- Add geo-IP enrichment and ASN tagging to alerts.
- Persist recent alerts and offenders in a lightweight cache (SQLite or Redis) for cross-run context.
- Pluggable notification targets (Slack/email/webhook) in the exporter layer.
- Extend parsers for other log sources (systemd journal, cloud auth events, VPN gateways).
- CLI flags for detector tuning (thresholds, window sizes, CIDR lists) and YAML-based configs.
