"""
Lightweight HTTP server that serves the frontend and exposes API endpoints
backed by the SQLite datastore.

Endpoints:
- GET /api/alerts
- GET /api/dashboard
"""

from __future__ import annotations

import json
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from storage.db import read_alerts, read_dashboard


class DashboardRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, db_path: Path, frontend_dir: Path, **kwargs):
        self.db_path = db_path
        super().__init__(*args, directory=str(frontend_dir), **kwargs)

    def do_GET(self) -> None:
        # Support both root (/) and /frontend/* URLs for convenience.
        if self.path.startswith("/frontend"):
            self.path = self.path.removeprefix("/frontend") or "/"

        if self.path.startswith("/api/alerts"):
            return self._send_json(read_alerts(self.db_path))
        if self.path.startswith("/api/dashboard"):
            return self._send_json(read_dashboard(self.db_path))

        if self.path in {"/", ""}:
            self.path = "/index.html"
        return super().do_GET()

    def log_message(self, format, *args):  # type: ignore[override]
        # Quieter logs; comment out to enable per-request logging.
        return

    def _send_json(self, payload) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_dashboard_server(db_path: Path, port: int,
                           frontend_dir: Path) -> ThreadingHTTPServer:
    """
    Start the dashboard/API server in a background thread.

    Returns:
        The ThreadingHTTPServer instance (daemon thread already started).
    """
    handler = partial(DashboardRequestHandler,
                      db_path=db_path,
                      frontend_dir=frontend_dir)
    httpd = ThreadingHTTPServer(("", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    print(
        f"[INFO] Dashboard/API server running at http://localhost:{port} (serving {frontend_dir})"
    )
    return httpd
