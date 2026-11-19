"""SQLite database schema and persistence layer for Linux Security Log Analyzer."""

from typing import Tuple


SCHEMA_TABLES_SQL: Tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS scan_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        source_path TEXT NOT NULL,
        total_lines INTEGER NOT NULL DEFAULT 0,
        valid_events INTEGER NOT NULL DEFAULT 0,
        malformed_lines INTEGER NOT NULL DEFAULT 0,
        new_events_stored INTEGER NOT NULL DEFAULT 0,
        alerts_generated INTEGER NOT NULL DEFAULT 0
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS auth_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_run_id INTEGER,
        line_number INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        hostname TEXT NOT NULL,
        service TEXT NOT NULL,
        pid INTEGER,
        event_type TEXT NOT NULL,
        username TEXT,
        source_ip TEXT,
        port INTEGER,
        auth_method TEXT,
        target_user TEXT,
        command TEXT,
        is_invalid_user INTEGER NOT NULL DEFAULT 0,
        message TEXT NOT NULL,
        raw_line TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE SET NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_run_id INTEGER,
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        source_ip TEXT,
        username TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        evidence_json TEXT NOT NULL,
        alert_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE SET NULL
    );
    """,
)