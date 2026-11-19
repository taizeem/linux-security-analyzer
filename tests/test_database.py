from pathlib import Path
import json
import sqlite3
import tempfile
import unittest

from security_analyzer.database import DatabaseManager
from security_analyzer.detector import DetectionEngine
from security_analyzer.parser import parse_log_file


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"


class TestDatabaseInitialization(unittest.TestCase):
    """Verify Checkpoint 5.2: database creation, pragmas, and idempotency."""

    def setUp(self) -> None:
        """Create an isolated temporary directory for each database test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "nested" / "test_security.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        """Clean up temporary database directory."""
        self.temp_dir.cleanup()

    def test_initialize_creates_parent_directory_and_all_tables(self) -> None:
        """Verify initialize() creates nested directories and all 3 schema tables."""
        self.assertFalse(self.db_path.exists())
        self.db.initialize()
        self.assertTrue(self.db_path.is_file())

        tables = self.db.list_tables()
        self.assertEqual(tables, ["auth_events", "scan_runs", "security_alerts"])

    def test_initialize_is_idempotent_and_enables_wal_mode(self) -> None:
        """Verify calling initialize() twice succeeds and WAL journal mode is active."""
        self.db.initialize()
        self.db.initialize()

        conn = sqlite3.connect(str(self.db_path))
        try:
            journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(journal_mode.lower(), "wal")

    def test_create_scan_run_returns_incrementing_ids(self) -> None:
        """Verify scan_runs audit records are inserted cleanly."""
        self.db.initialize()
        run_1 = self.db.create_scan_run(
            source_path="/var/log/auth.log",
            total_lines=100,
            valid_events=98,
            malformed_lines=2,
        )
        run_2 = self.db.create_scan_run(
            source_path="sample_logs/auth_sample.log",
            total_lines=26,
            valid_events=25,
            malformed_lines=1,
        )
        self.assertEqual(run_1, 1)
        self.assertEqual(run_2, 2)


class TestEventPersistence(unittest.TestCase):
    """Verify Checkpoint 5.3: storing parsed AuthEvents in SQLite."""

    def setUp(self) -> None:
        """Create a fresh initialized test database for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "events.db"
        self.db = DatabaseManager(self.db_path)
        self.db.initialize()

    def tearDown(self) -> None:
        """Clean up temporary database directory."""
        self.temp_dir.cleanup()

    def test_store_events_persists_all_sample_events_with_scan_run_id(self) -> None:
        """Verify all 25 valid events from auth_sample.log are stored accurately."""
        parsed = parse_log_file(SAMPLE_LOG, reference_year=2026)
        run_id = self.db.create_scan_run(
            source_path=parsed.source_path,
            total_lines=parsed.total_lines,
            valid_events=parsed.valid_events,
            malformed_lines=parsed.malformed_lines,
        )

        inserted = self.db.store_events(parsed.events, scan_run_id=run_id)
        self.assertEqual(inserted, 25)
        self.assertEqual(self.db.count_events(), 25)

    def test_store_empty_event_list_returns_zero(self) -> None:
        """Verify storing an empty sequence returns 0 without database errors."""
        self.assertEqual(self.db.store_events([]), 0)
        self.assertEqual(self.db.count_events(), 0)

class TestAlertPersistence(unittest.TestCase):
    """Verify Checkpoint 5.4: storing SecurityAlerts and JSON evidence in SQLite."""

    def setUp(self) -> None:
        """Create a fresh initialized test database for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "alerts.db"
        self.db = DatabaseManager(self.db_path)
        self.db.initialize()

    def tearDown(self) -> None:
        """Clean up temporary database directory."""
        self.temp_dir.cleanup()

    def test_store_alerts_persists_all_generated_alerts_with_evidence(self) -> None:
        """Verify all 5 alerts from auth_sample.log persist with valid evidence JSON."""
        parsed = parse_log_file(SAMPLE_LOG, reference_year=2026)
        alerts = DetectionEngine().evaluate(parsed.events)
        run_id = self.db.create_scan_run(
            source_path=parsed.source_path,
            total_lines=parsed.total_lines,
            valid_events=parsed.valid_events,
            malformed_lines=parsed.malformed_lines,
        )

        inserted = self.db.store_alerts(alerts, scan_run_id=run_id)
        self.assertEqual(inserted, 5)
        self.assertEqual(self.db.count_alerts(), 5)

        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT rule_id, severity, evidence_json FROM security_alerts "
                "WHERE rule_id = 'SSH_SUCCESS_AFTER_FAILURES';"
            ).fetchone()
        finally:
            conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["severity"], "critical")
        evidence = json.loads(row["evidence_json"])
        self.assertEqual(len(evidence), 6)

    def test_store_empty_alert_list_returns_zero(self) -> None:
        """Verify storing an empty alert list returns 0 cleanly."""
        self.assertEqual(self.db.store_alerts([]), 0)
        self.assertEqual(self.db.count_alerts(), 0)


if __name__ == "__main__":
    unittest.main()