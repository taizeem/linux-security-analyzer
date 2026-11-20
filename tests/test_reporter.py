from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from security_analyzer.cli import main
from security_analyzer.database import DatabaseManager
from security_analyzer.detector import DetectionEngine
from security_analyzer.parser import parse_log_file
from security_analyzer.reporter import (
    build_report_data,
    render_terminal_report,
    write_report_file,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"


class TestTerminalReporting(unittest.TestCase):
    """Verify terminal security report assembly, rendering, and file output."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db = DatabaseManager(self.base_path / "report_test.db")
        self.db.initialize()

        parsed = parse_log_file(SAMPLE_LOG, reference_year=2026)
        alerts = DetectionEngine().evaluate(parsed.events)
        self.db.persist_scan_results(parsed, alerts)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_terminal_report_contains_all_required_sections_and_evidence(self) -> None:
        """Verify terminal report includes totals, IPs, usernames, alerts, evidence, and scans."""
        report_data = build_report_data(self.db, top_n=5)
        rendered = render_terminal_report(report_data)

        self.assertIn("LINUX SECURITY LOG ANALYZER", rendered)
        self.assertIn("Total Successful Logins:   3", rendered)
        self.assertIn("Total Failed Logins:       11", rendered)
        self.assertIn("CRITICAL=1  HIGH=1  MEDIUM=3  LOW=0", rendered)
        self.assertIn("203.0.113.50", rendered)
        self.assertIn("SSH_SUCCESS_AFTER_FAILURES", rendered)
        self.assertIn("Evidence:", rendered)
        self.assertIn("SCAN EXECUTION HISTORY", rendered)

    def test_cli_report_terminal_writes_to_output_file(self) -> None:
        """Verify report --format terminal --output writes report text to disk."""
        out_file = self.base_path / "reports" / "security_report.txt"
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "report",
                    "--db",
                    str(self.db.db_path),
                    "--format",
                    "terminal",
                    "--output",
                    str(out_file),
                ]
            )
        self.assertEqual(code, 0)
        self.assertTrue(out_file.is_file())
        saved = out_file.read_text(encoding="utf-8")
        self.assertIn("AUTHENTICATION SUMMARY", saved)
        self.assertIn("198.51.100.77", saved)

    def test_write_report_file_creates_parent_directories(self) -> None:
        """Verify write_report_file creates missing parent folders safely."""
        nested = self.base_path / "deep" / "nested" / "out.txt"
        written = write_report_file("sample report", nested)
        self.assertEqual(written, nested.resolve())
        self.assertEqual(written.read_text(encoding="utf-8"), "sample report\n")


if __name__ == "__main__":
    unittest.main()