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

class TestStatsCommand(unittest.TestCase):
    """Verify stats CLI command terminal dashboard and JSON output."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "stats_cli.db"
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

    def test_stats_terminal_output_displays_counts_and_top_entities(self) -> None:
        """Verify stats renders totals, severity counts, top IPs, and scan runs."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["stats", "--db", str(self.db_path), "--top", "3"])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("Total stored events:       25", output)
        self.assertIn("Successful SSH logins:     3", output)
        self.assertIn("Failed SSH logins:         11", output)
        self.assertIn("CRITICAL: 1 | HIGH: 1 | MEDIUM: 3 | LOW: 0", output)
        self.assertIn("203.0.113.50", output)

    def test_stats_json_output_matches_database_aggregates(self) -> None:
        """Verify stats --json outputs machine-readable aggregate counts."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["stats", "--db", str(self.db_path), "--top", "2", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["total_events"], 25)
        self.assertEqual(data["total_alerts"], 5)
        self.assertEqual(len(data["top_source_ips"]), 2)

class TestCliInputValidation(unittest.TestCase):
    """Verify strict CLI input validation and non-zero error exit codes."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "validation_cli.db"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_invalid_ip_and_event_type_rejected(self) -> None:
        """Verify malformed --ip and unknown --event-type exit with code 1."""
        err_ip = io.StringIO()
        with redirect_stderr(err_ip):
            code_ip = main(
                ["events", "--db", str(self.db_path), "--ip", "999.999.999.999"]
            )
        self.assertEqual(code_ip, 1)
        self.assertIn("invalid ip address", err_ip.getvalue().lower())

        err_type = io.StringIO()
        with redirect_stderr(err_type):
            code_type = main(
                ["events", "--db", str(self.db_path), "--event-type", "ssh_typo"]
            )
        self.assertEqual(code_type, 1)
        self.assertIn("invalid event type", err_type.getvalue().lower())

    def test_invalid_severity_and_inverted_time_bounds_rejected(self) -> None:
        """Verify invalid --severity, bad ISO dates, and inverted --since/--until fail."""
        err_sev = io.StringIO()
        with redirect_stderr(err_sev):
            code_sev = main(
                ["alerts", "--db", str(self.db_path), "--severity", "urgent"]
            )
        self.assertEqual(code_sev, 1)
        self.assertIn("invalid severity", err_sev.getvalue().lower())

        err_range = io.StringIO()
        with redirect_stderr(err_range):
            code_range = main(
                [
                    "events",
                    "--db",
                    str(self.db_path),
                    "--since",
                    "2026-11-20T10:00:00+05:30",
                    "--until",
                    "2026-11-18T10:00:00+05:30",
                ]
            )
        self.assertEqual(code_range, 1)
        self.assertIn("--since must be earlier", err_range.getvalue().lower())

    def test_invalid_limit_top_and_year_rejected(self) -> None:
        """Verify out-of-range --limit, --top, and --year return exit code 1."""
        for argv in (
            ["events", "--db", str(self.db_path), "--limit", "0"],
            ["stats", "--db", str(self.db_path), "--top", "-3"],
            [
                "analyze",
                "--file",
                str(SAMPLE_LOG),
                "--db",
                str(self.db_path),
                "--year",
                "1800",
            ],
        ):
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                code = main(argv)
            self.assertEqual(code, 1, msg=f"Expected exit code 1 for {argv}")

if __name__ == "__main__":
    unittest.main()