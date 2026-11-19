from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Iterator, List, Tuple, Union

from security_analyzer.logger import get_logger


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