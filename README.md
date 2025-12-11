# LogSentinel

LogSentinel is a Python mini-SIEM that ingests Linux authentication logs or Windows Event Logs, detects suspicious activity, and exports JSON alerts plus dashboard-friendly summaries. It is intentionally modular so you can plug in new detectors or swap parsers without rewriting the pipeline.

## Features
- Auth log parsing (Linux) with regex, pandas DataFrame output, and graceful handling of malformed lines.
- Windows Event Log parsing (pywin32) to reuse the same pipeline.
- Detectors for brute force, suspicious IP ranges, and per-minute rate limiting (now CLI-tunable thresholds).
- JSON alert exporting with consistent schema (type, severity, source IP, counts, timeframe, username when available).
- Dashboard prep via `dashboard_data.json` summarizing failed logins, unique attackers, alerts by type/severity, and attack patterns.
- File-based, dependency-light, and easy to extend with additional detectors.

## Installation
1) Ensure Python 3.9+ is available.  
2) Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
### Linux auth logs (default)
```bash
python main.py
python main.py --log-file /var/log/auth.log --alerts-output out/alerts.json --dashboard-output out/dashboard_data.json
```

### Windows Event Log (Security) via pywin32
Install dependencies (adds pywin32 on Windows):
```powershell
pip install -r requirements.txt
```

Read the Security log directly (requires Administrator):
```powershell
python main.py --input-format windows --windows-log Security --alerts-output data\\alerts.json --dashboard-output data\\dashboard_data.json
```
If you don't have elevation, switch to a readable log like `Application`:
```powershell
python main.py --input-format windows --windows-log Application
```

Key options:
- `--input-format`: `linux` (auth log file) or `windows` (Event Log).
- `--log-file`: path to the auth log file (linux only, default: `data/sample_auth.log`).
- `--windows-log`: Windows Event Log name (default: `Security`).
- `--alerts-output`: where to write alerts JSON (default: `data/alerts.json`).
- `--dashboard-output`: where to write dashboard summary JSON (default: `data/dashboard_data.json`).
- `--brute-threshold`: failed login count to trigger brute-force alert (default: 5).
- `--brute-window-minutes`: rolling window in minutes for brute-force detection (default: 5).
- `--rate-threshold-per-minute`: per-minute volume to trigger rate-limit alert (default: 20).

Threshold tuning examples:
```bash
# Linux file, more sensitive brute-force, stricter rate limit
python main.py --log-file /var/log/auth.log --brute-threshold 3 --brute-window-minutes 10 --rate-threshold-per-minute 15

# Windows Event Log, same outputs, custom thresholds
python main.py --input-format windows --windows-log Security --brute-threshold 4 --rate-threshold-per-minute 25
```

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
Example alert emitted to `data/alerts.json`:
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

Example dashboard summary from `data/dashboard_data.json`:
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
