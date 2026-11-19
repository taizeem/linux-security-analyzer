from pathlib import Path
import sqlite3
import tempfile
import unittest

from security_analyzer.database import DatabaseManager


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


if __name__ == "__main__":
    unittest.main()