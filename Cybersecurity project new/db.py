"""Database integration placeholders.

The project keeps persistence modular so a database can be attached later without
rewriting the scanning workflow.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).with_name("scan_history.db")


def _connect():
    """Create a SQLite connection and ensure rows behave like dictionaries."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _initialize_schema(connection):
    """Create the scan history table the first time the application runs."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            scan_timestamp TEXT NOT NULL,
            overall_risk TEXT NOT NULL,
            total_findings INTEGER NOT NULL,
            critical INTEGER NOT NULL,
            high INTEGER NOT NULL,
            medium INTEGER NOT NULL,
            low INTEGER NOT NULL,
            open_ports INTEGER NOT NULL,
            status_code INTEGER NOT NULL,
            server_banner TEXT NOT NULL,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def save_scan_history(scan_data):
    """Persist a completed scan so it can be reviewed later in the history view.

    The full report is stored as JSON for future expansion, while a few summary
    fields are kept as columns for fast dashboard display.
    """
    connection = _connect()
    try:
        _initialize_schema(connection)
        summary_stats = scan_data.get("summary_stats", {})
        connection.execute(
            """
            INSERT INTO scan_history (
                target_url,
                scan_timestamp,
                overall_risk,
                total_findings,
                critical,
                high,
                medium,
                low,
                open_ports,
                status_code,
                server_banner,
                report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_data.get("target_url", ""),
                scan_data.get("scan_timestamp", ""),
                scan_data.get("overall_risk", "Low"),
                int(summary_stats.get("total_findings", 0)),
                int(summary_stats.get("critical", 0)),
                int(summary_stats.get("high", 0)),
                int(summary_stats.get("medium", 0)),
                int(summary_stats.get("low", 0)),
                int(summary_stats.get("open_ports", 0)),
                int(scan_data.get("status_code", 0)),
                scan_data.get("server_banner", "Not disclosed"),
                json.dumps(scan_data),
            ),
        )
        connection.commit()
        return {"stored": True, "reason": "Scan history saved successfully."}
    finally:
        connection.close()


def get_scan_history(limit=25):
    """Return the most recent scans for the scan history dashboard."""
    connection = _connect()
    try:
        _initialize_schema(connection)
        rows = connection.execute(
            """
            SELECT id, target_url, scan_timestamp, overall_risk, total_findings, critical,
                   high, medium, low, open_ports, status_code, server_banner, created_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()


def save_user_authentication(user_data):
    """TODO: connect authentication storage when user accounts are added."""
    return {"stored": False, "reason": "Authentication storage pending."}


def save_report(report_data):
    """TODO: persist generated reports in a future database table."""
    return {"stored": False, "reason": "Report storage pending."}
