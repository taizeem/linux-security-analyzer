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


if __name__ == "__main__":
    unittest.main()