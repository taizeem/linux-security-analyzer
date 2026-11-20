import unittest

from security_analyzer.cli import build_parser, main


class TestCliParserStructure(unittest.TestCase):
    """Verify Checkpoint 6.1: subcommand registration and argument parsing."""

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


if __name__ == "__main__":
    unittest.main()