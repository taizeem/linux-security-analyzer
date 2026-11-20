import json
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
    REPORT_SCHEMA_VERSION,
    build_report_data,
    render_json_report,
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
class TestJsonReporting(unittest.TestCase):
    """Verify JSON security report serialization, schema metadata, and file output."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db = DatabaseManager(self.base_path / "json_report_test.db")
        self.db.initialize()

        parsed = parse_log_file(SAMPLE_LOG, reference_year=2026)
        alerts = DetectionEngine().evaluate(parsed.events)
        self.db.persist_scan_results(parsed, alerts)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_render_json_report_contains_valid_schema_and_evidence(self) -> None:
        """Verify render_json_report outputs parseable JSON with full report sections."""
        data = build_report_data(self.db, top_n=3)
        raw_json = render_json_report(data)
        parsed = json.loads(raw_json)

        self.assertEqual(parsed["metadata"]["schema_version"], REPORT_SCHEMA_VERSION)
        self.assertEqual(parsed["summary"]["total_successful_logins"], 3)
        self.assertEqual(parsed["summary"]["total_failed_logins"], 11)
        self.assertEqual(parsed["summary"]["total_alerts"], 5)
        self.assertEqual(len(parsed["top_source_ips"]), 3)
        self.assertEqual(len(parsed["alerts"]), 5)
        self.assertIsInstance(parsed["alerts"][0]["evidence"], list)
        self.assertEqual(len(parsed["scan_runs"]), 1)

    def test_cli_report_json_writes_valid_json_file(self) -> None:
        """Verify report --format json --output creates a valid JSON report file."""
        out_file = self.base_path / "reports" / "security_report.json"
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "report",
                    "--db",
                    str(self.db.db_path),
                    "--format",
                    "json",
                    "--output",
                    str(out_file),
                ]
            )
        self.assertEqual(code, 0)
        self.assertTrue(out_file.is_file())
        saved = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(saved["summary"]["alerts_by_severity"]["critical"], 1)

class TestAuthenticationStatistics(unittest.TestCase):
    """Verify enriched authentication statistics in reports and empty databases."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db = DatabaseManager(self.base_path / "stats_report.db")
        self.db.initialize()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_report_statistics_include_failure_rate_and_auth_methods(self) -> None:
        """Verify failure rate, auth methods, and unique counts are accurate."""
        parsed = parse_log_file(SAMPLE_LOG, reference_year=2026)
        alerts = DetectionEngine().evaluate(parsed.events)
        self.db.persist_scan_results(parsed, alerts)

        data = build_report_data(self.db)
        summary = data["summary"]
        # 11 failed / (11 + 3) = 78.57%
        self.assertEqual(summary["ssh_failure_rate_percent"], 78.57)
        self.assertEqual(summary["unique_source_ips"], 4)
        self.assertEqual(
            summary["successful_logins_by_method"],
            {"publickey": 2, "password": 1},
        )
        self.assertIn("ssh_failed_login", summary["events_by_type"])

        terminal = render_terminal_report(data)
        self.assertIn("SSH Failure Rate:          78.57%", terminal)
        self.assertIn("publickey=2, password=1", terminal)

    def test_empty_database_report_avoids_zero_division(self) -> None:
        """Verify an empty database reports 0.0% failure rate cleanly."""
        data = build_report_data(self.db)
        self.assertEqual(data["summary"]["ssh_failure_rate_percent"], 0.0)
        self.assertEqual(data["summary"]["successful_logins_by_method"], {})
        terminal = render_terminal_report(data)
        self.assertIn("SSH Failure Rate:          0.00%", terminal)

if __name__ == "__main__":
    unittest.main()