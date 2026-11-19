from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from security_analyzer.logger import get_logger
from security_analyzer.models import AuthEvent, SecurityAlert, ParseResult


logger = get_logger(__name__)

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


def _utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


class DatabaseManager:
    """Manages SQLite connections, schema initialization, and persistence."""

    def __init__(self, db_path: Union[str, Path]) -> None:
        self.db_path = Path(db_path).expanduser().resolve()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a configured SQLite connection with automatic commit/rollback."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create all required tables idempotently."""
        with self._connect() as conn:
            for statement in SCHEMA_TABLES_SQL:
                conn.execute(statement)
        logger.debug("Initialized SQLite database at %s", self.db_path)

    def list_tables(self) -> List[str]:
        """Return a sorted list of user-defined tables in the database."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name;"
            ).fetchall()
            return [str(row["name"]) for row in rows]

    def create_scan_run(
        self,
        source_path: str,
        total_lines: int = 0,
        valid_events: int = 0,
        malformed_lines: int = 0,
        new_events_stored: int = 0,
        alerts_generated: int = 0,
    ) -> int:
        """Insert a scan_runs audit row and return its generated integer ID."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_runs (
                    started_at, source_path, total_lines, valid_events,
                    malformed_lines, new_events_stored, alerts_generated
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    _utc_now_iso(),
                    source_path,
                    total_lines,
                    valid_events,
                    malformed_lines,
                    new_events_stored,
                    alerts_generated,
                ),
            )
            assert cursor.lastrowid is not None
            return int(cursor.lastrowid)

    def store_events(
        self,
        events: Sequence[AuthEvent],
        scan_run_id: Optional[int] = None,
    ) -> int:
        """Persist AuthEvent records in a single transaction.

        Returns the exact number of newly inserted rows.
        """
        if not events:
            return 0

        now_iso = _utc_now_iso()
        rows = [
            (
                scan_run_id,
                ev.line_number,
                ev.timestamp,
                ev.hostname,
                ev.service,
                ev.pid,
                ev.event_type,
                ev.username,
                ev.source_ip,
                ev.port,
                ev.auth_method,
                ev.target_user,
                ev.command,
                1 if ev.is_invalid_user else 0,
                ev.message,
                ev.raw_line,
                ev.event_hash,
                now_iso,
            )
            for ev in events
        ]

        with self._connect() as conn:
            before = conn.total_changes
            conn.executemany(
                """
                INSERT OR IGNORE INTO auth_events (
                    scan_run_id, line_number, timestamp, hostname, service,
                    pid, event_type, username, source_ip, port, auth_method,
                    target_user, command, is_invalid_user, message, raw_line,
                    event_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                rows,
            )
            inserted = conn.total_changes - before

        logger.debug("Stored %d new authentication events", inserted)
        return inserted

    def count_events(self) -> int:
        """Return total number of authentication events stored in auth_events."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM auth_events;").fetchone()
            return int(row["cnt"])

    def store_alerts(
        self,
        alerts: Sequence[SecurityAlert],
        scan_run_id: Optional[int] = None,
    ) -> int:
        """Persist SecurityAlert records in a single transaction.

        Returns the exact number of newly inserted alert rows.
        """
        if not alerts:
            return 0

        now_iso = _utc_now_iso()
        rows = [
            (
                scan_run_id,
                alert.rule_id,
                alert.rule_name,
                alert.severity,
                alert.title,
                alert.description,
                alert.source_ip,
                alert.username,
                alert.first_seen,
                alert.last_seen,
                alert.event_count,
                json.dumps(list(alert.evidence), separators=(",", ":")),
                alert.alert_hash,
                now_iso,
            )
            for alert in alerts
        ]

        with self._connect() as conn:
            before = conn.total_changes
            conn.executemany(
                """
                INSERT OR IGNORE INTO security_alerts (
                    scan_run_id, rule_id, rule_name, severity, title,
                    description, source_ip, username, first_seen, last_seen,
                    event_count, evidence_json, alert_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                rows,
            )
            inserted = conn.total_changes - before

        logger.debug("Stored %d new security alerts", inserted)
        return inserted

    def count_alerts(self) -> int:
        """Return total number of security alerts stored in security_alerts."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM security_alerts;"
            ).fetchone()
            return int(row["cnt"])
    def persist_scan_results(
        self,
        parse_result: ParseResult,
        alerts: Sequence[SecurityAlert],
    ) -> Dict[str, int]:
        """Atomically record a scan run, deduplicated events, and deduplicated alerts."""
        now_iso = _utc_now_iso()

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_runs (
                    started_at, source_path, total_lines, valid_events,
                    malformed_lines, new_events_stored, alerts_generated
                ) VALUES (?, ?, ?, ?, ?, 0, 0);
                """,
                (
                    now_iso,
                    parse_result.source_path,
                    parse_result.total_lines,
                    parse_result.valid_events,
                    parse_result.malformed_lines,
                ),
            )
            assert cursor.lastrowid is not None
            scan_run_id = int(cursor.lastrowid)

            event_rows = [
                (
                    scan_run_id,
                    ev.line_number,
                    ev.timestamp,
                    ev.hostname,
                    ev.service,
                    ev.pid,
                    ev.event_type,
                    ev.username,
                    ev.source_ip,
                    ev.port,
                    ev.auth_method,
                    ev.target_user,
                    ev.command,
                    1 if ev.is_invalid_user else 0,
                    ev.message,
                    ev.raw_line,
                    ev.event_hash,
                    now_iso,
                )
                for ev in parse_result.events
            ]
            before_events = conn.total_changes
            if event_rows:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO auth_events (
                        scan_run_id, line_number, timestamp, hostname, service,
                        pid, event_type, username, source_ip, port, auth_method,
                        target_user, command, is_invalid_user, message, raw_line,
                        event_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    event_rows,
                )
            new_events = conn.total_changes - before_events
            duplicate_events = len(event_rows) - new_events

            alert_rows = [
                (
                    scan_run_id,
                    alert.rule_id,
                    alert.rule_name,
                    alert.severity,
                    alert.title,
                    alert.description,
                    alert.source_ip,
                    alert.username,
                    alert.first_seen,
                    alert.last_seen,
                    alert.event_count,
                    json.dumps(list(alert.evidence), separators=(",", ":")),
                    alert.alert_hash,
                    now_iso,
                )
                for alert in alerts
            ]
            before_alerts = conn.total_changes
            if alert_rows:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO security_alerts (
                        scan_run_id, rule_id, rule_name, severity, title,
                        description, source_ip, username, first_seen, last_seen,
                        event_count, evidence_json, alert_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    alert_rows,
                )
            new_alerts = conn.total_changes - before_alerts
            duplicate_alerts = len(alert_rows) - new_alerts

            conn.execute(
                """
                UPDATE scan_runs
                SET new_events_stored = ?, alerts_generated = ?
                WHERE id = ?;
                """,
                (new_events, new_alerts, scan_run_id),
            )

        return {
            "scan_run_id": scan_run_id,
            "new_events": new_events,
            "duplicate_events": duplicate_events,
            "new_alerts": new_alerts,
            "duplicate_alerts": duplicate_alerts,
        }
    def query_events(
        self,
        event_type: Optional[str] = None,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        service: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query stored authentication events with optional filters."""
        if limit < 1:
            raise ValueError("limit must be at least 1")

        conditions: List[str] = []
        params: List[Any] = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if username:
            conditions.append("username = ?")
            params.append(username)
        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip)
        if service:
            conditions.append("service = ?")
            params.append(service)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM auth_events {where_clause} "
            "ORDER BY timestamp DESC, id DESC LIMIT ?;"
        )
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            results: List[Dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["is_invalid_user"] = bool(item["is_invalid_user"])
                results.append(item)
            return results

    def query_alerts(
        self,
        severity: Optional[str] = None,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query stored security alerts ordered by severity priority and recency."""
        if limit < 1:
            raise ValueError("limit must be at least 1")

        conditions: List[str] = []
        params: List[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.lower())
        if rule_id:
            conditions.append("rule_id = ?")
            params.append(rule_id)
        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip)
        if username:
            conditions.append("username = ?")
            params.append(username)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM security_alerts {where_clause} "
            "ORDER BY CASE severity "
            "WHEN 'critical' THEN 4 "
            "WHEN 'high' THEN 3 "
            "WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 1 "
            "ELSE 0 END DESC, last_seen DESC, id DESC LIMIT ?;"
        )
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            results: List[Dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["evidence"] = json.loads(item.pop("evidence_json"))
                results.append(item)
            return results

    def get_statistics(self, top_n: int = 10) -> Dict[str, Any]:
        """Compute aggregated authentication and alert statistics from SQLite."""
        if top_n < 1:
            raise ValueError("top_n must be at least 1")

        with self._connect() as conn:
            total_events = int(
                conn.execute("SELECT COUNT(*) AS c FROM auth_events;").fetchone()["c"]
            )
            total_successful_logins = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM auth_events "
                    "WHERE event_type = 'ssh_successful_login';"
                ).fetchone()["c"]
            )
            total_failed_logins = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM auth_events "
                    "WHERE event_type = 'ssh_failed_login';"
                ).fetchone()["c"]
            )
            total_invalid_users = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM auth_events "
                    "WHERE is_invalid_user = 1;"
                ).fetchone()["c"]
            )
            total_sudo_events = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM auth_events "
                    "WHERE service = 'sudo' "
                    "AND event_type IN ('sudo_command', 'sudo_auth_failure');"
                ).fetchone()["c"]
            )
            total_alerts = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM security_alerts;"
                ).fetchone()["c"]
            )

            severity_rows = conn.execute(
                "SELECT severity, COUNT(*) AS cnt FROM security_alerts "
                "GROUP BY severity;"
            ).fetchall()
            alerts_by_severity: Dict[str, int] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
            for row in severity_rows:
                alerts_by_severity[str(row["severity"])] = int(row["cnt"])

            top_ips_rows = conn.execute(
                """
                SELECT source_ip, COUNT(*) AS event_count
                FROM auth_events
                WHERE source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY event_count DESC, source_ip ASC
                LIMIT ?;
                """,
                (top_n,),
            ).fetchall()
            top_source_ips = [
                {"source_ip": str(r["source_ip"]), "count": int(r["event_count"])}
                for r in top_ips_rows
            ]

            top_users_rows = conn.execute(
                """
                SELECT username, COUNT(*) AS event_count
                FROM auth_events
                WHERE username IS NOT NULL
                  AND event_type IN ('ssh_failed_login', 'ssh_invalid_user', 'sudo_auth_failure')
                GROUP BY username
                ORDER BY event_count DESC, username ASC
                LIMIT ?;
                """,
                (top_n,),
            ).fetchall()
            top_targeted_usernames = [
                {"username": str(r["username"]), "count": int(r["event_count"])}
                for r in top_users_rows
            ]

            recent_runs_rows = conn.execute(
                """
                SELECT id, started_at, source_path, total_lines, valid_events,
                       malformed_lines, new_events_stored, alerts_generated
                FROM scan_runs
                ORDER BY id DESC
                LIMIT 5;
                """
            ).fetchall()
            recent_scan_runs = [dict(row) for row in recent_runs_rows]

        return {
            "total_events": total_events,
            "total_successful_logins": total_successful_logins,
            "total_failed_logins": total_failed_logins,
            "total_invalid_users": total_invalid_users,
            "total_sudo_events": total_sudo_events,
            "total_alerts": total_alerts,
            "alerts_by_severity": alerts_by_severity,
            "top_source_ips": top_source_ips,
            "top_targeted_usernames": top_targeted_usernames,
            "recent_scan_runs": recent_scan_runs,
        }