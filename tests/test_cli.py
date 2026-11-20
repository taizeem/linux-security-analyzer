from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from security_analyzer.cli import build_parser, main


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"


class TestCliParserStructure(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = build_parser()

    def test_all_five_subcommands_are_registered(self) -> None:
        """Verify analyze, events, alerts, stats, and report parse cleanly."""
        analyze_args = self.parser.parse_args(
            ["analyze", "--file", "sample_logs/auth_sample.log", "--year", "2026"]
        )
        self.assertEqual(analyze_args.command, "analyze")
        self.assertEqual(analyze_args.file, "sample_logs/auth_sample.log")
        self.assertEqual(analyze_args.year, 2026)

        events_args = self.parser.parse_args(
            ["events", "--ip", "203.0.113.50", "--user", "root", "--limit", "20"]
        )
        self.assertEqual(events_args.command, "events")
        self.assertEqual(events_args.source_ip, "203.0.113.50")
        self.assertEqual(events_args.username, "root")
        self.assertEqual(events_args.limit, 20)

        alerts_args = self.parser.parse_args(
            ["alerts", "--severity", "critical", "--show-evidence"]
        )
        self.assertEqual(alerts_args.command, "alerts")
        self.assertEqual(alerts_args.severity, "critical")
        self.assertTrue(alerts_args.show_evidence)

        stats_args = self.parser.parse_args(["stats", "--top", "5", "--json"])
        self.assertEqual(stats_args.command, "stats")
        self.assertEqual(stats_args.top, 5)
        self.assertTrue(stats_args.as_json)

        report_args = self.parser.parse_args(
            ["report", "--format", "json", "--output", "reports/out.json"]
        )
        self.assertEqual(report_args.command, "report")
        self.assertEqual(report_args.format, "json")
        self.assertEqual(report_args.output, "reports/out.json")

    def test_global_options_accepted_after_subcommand(self) -> None:
        """Verify --db and --config work cleanly after the subcommand name."""
        args = self.parser.parse_args(
            ["events", "--db", "data/custom.db", "--config", "config.example.json"]
        )
        self.assertEqual(args.db, "data/custom.db")
        self.assertEqual(args.config, "config.example.json")

    def test_no_subcommand_returns_zero(self) -> None:
        """Verify running with no subcommand prints help and exits 0."""
        self.assertEqual(main([]), 0)

class TestAnalyzeCommand(unittest.TestCase):
   
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "cli_test.db"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_analyze_command_json_and_idempotent_rerun(self) -> None:
        """Verify analyze ingests events/alerts on run 1 and deduplicates on run 2."""
        stdout_1 = io.StringIO()
        with redirect_stdout(stdout_1):
            code_1 = main(
                [
                    "analyze",
                    "--file",
                    str(SAMPLE_LOG),
                    "--db",
                    str(self.db_path),
                    "--year",
                    "2026",
                    "--json",
                ]
            )
        self.assertEqual(code_1, 0)
        payload_1 = json.loads(stdout_1.getvalue())
        self.assertEqual(payload_1["new_events_stored"], 25)
        self.assertEqual(payload_1["new_alerts_stored"], 5)
        self.assertEqual(payload_1["malformed_lines"], 1)

        stdout_2 = io.StringIO()
        with redirect_stdout(stdout_2):
            code_2 = main(
                [
                    "analyze",
                    "--file",
                    str(SAMPLE_LOG),
                    "--db",
                    str(self.db_path),
                    "--year",
                    "2026",
                    "--json",
                ]
            )
        self.assertEqual(code_2, 0)
        payload_2 = json.loads(stdout_2.getvalue())
        self.assertEqual(payload_2["new_events_stored"], 0)
        self.assertEqual(payload_2["duplicate_events_skipped"], 25)
        self.assertEqual(payload_2["new_alerts_stored"], 0)
        self.assertEqual(payload_2["duplicate_alerts_skipped"], 5)

    def test_analyze_missing_file_returns_exit_code_one(self) -> None:
        """Verify missing log file prints an error to stderr and exits 1."""
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            code = main(
                [
                    "analyze",
                    "--file",
                    str(Path(self.temp_dir.name) / "does_not_exist.log"),
                    "--db",
                    str(self.db_path),
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("not found", stderr_buf.getvalue().lower())

class TestEventsCommand(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "events_cli.db"
        with redirect_stdout(io.StringIO()):
            main(
                [
                    "analyze",
                    "--file",
                    str(SAMPLE_LOG),
                    "--db",
                    str(self.db_path),
                    "--year",
                    "2026",
                ]
            )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_events_filter_by_ip_json_output(self) -> None:
        """Verify events --ip --json returns only matching IP records."""
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(
                [
                    "events",
                    "--db",
                    str(self.db_path),
                    "--ip",
                    "198.51.100.77",
                    "--json",
                ]
            )
        self.assertEqual(code, 0)
        rows = json.loads(stdout_buf.getvalue())
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(r["source_ip"] == "198.51.100.77" for r in rows))

    def test_events_terminal_table_and_empty_result_message(self) -> None:
        """Verify terminal table formatting and clean empty-result messaging."""
        table_buf = io.StringIO()
        with redirect_stdout(table_buf):
            code_1 = main(
                [
                    "events",
                    "--db",
                    str(self.db_path),
                    "--service",
                    "sudo",
                    "--user",
                    "intern",
                ]
            )
        self.assertEqual(code_1, 0)
        output = table_buf.getvalue()
        self.assertIn("sudo_auth_failure", output)
        self.assertIn("Showing 4 event(s).", output)

        empty_buf = io.StringIO()
        with redirect_stdout(empty_buf):
            code_2 = main(
                [
                    "events",
                    "--db",
                    str(self.db_path),
                    "--user",
                    "nonexistent_user_xyz",
                ]
            )
        self.assertEqual(code_2, 0)
        self.assertIn("No matching authentication events found.", empty_buf.getvalue())

class TestAlertsCommand(unittest.TestCase):
    """Verify alerts CLI command filtering, evidence display, and JSON output."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "alerts_cli.db"
        with redirect_stdout(io.StringIO()):
            main(
                [
                    "analyze",
                    "--file",
                    str(SAMPLE_LOG),
                    "--db",
                    str(self.db_path),
                    "--year",
                    "2026",
                ]
            )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_alerts_filter_by_severity_and_show_evidence(self) -> None:
        """Verify alerts --severity critical --show-evidence renders evidence lines."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "alerts",
                    "--db",
                    str(self.db_path),
                    "--severity",
                    "critical",
                    "--show-evidence",
                ]
            )
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("[CRITICAL]", output)
        self.assertIn("SSH_SUCCESS_AFTER_FAILURES", output)
        self.assertIn("Evidence:", output)
        self.assertIn("Accepted password for deploy", output)
        self.assertIn("Showing 1 alert(s).", output)

    def test_alerts_json_output_and_empty_filter(self) -> None:
        """Verify alerts --json returns valid JSON and empty filters print message."""
        json_buf = io.StringIO()
        with redirect_stdout(json_buf):
            code_1 = main(
                [
                    "alerts",
                    "--db",
                    str(self.db_path),
                    "--ip",
                    "203.0.113.50",
                    "--json",
                ]
            )
        self.assertEqual(code_1, 0)
        rows = json.loads(json_buf.getvalue())
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["source_ip"] == "203.0.113.50" for r in rows))

        empty_buf = io.StringIO()
        with redirect_stdout(empty_buf):
            code_2 = main(
                [
                    "alerts",
                    "--db",
                    str(self.db_path),
                    "--severity",
                    "low",
                ]
            )
        self.assertEqual(code_2, 0)
        self.assertIn("No matching security alerts found.", empty_buf.getvalue())


if __name__ == "__main__":
    unittest.main()