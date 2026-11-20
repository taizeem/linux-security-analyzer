import json
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUN_SCRIPT = PROJECT_ROOT / "scripts" / "run.sh"
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"
BENIGN_LOG = PROJECT_ROOT / "sample_logs" / "benign_activity.log"


class TestEndToEndIntegration(unittest.TestCase):
    """Verify full multi-command workflows via scripts/run.sh subprocesses."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "integration.db"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(RUN_SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_full_cli_workflow_analyze_query_stats_and_reports(self) -> None:
        """Verify analyze -> events -> alerts -> stats -> report end-to-end."""
        cfg_path = self.base_path / "integration_config.json"
        cfg_path.write_text(
            json.dumps(
                {
                    "database": {"db_path": str(self.db_path)},
                    "detection_rules": {
                        "brute_force_threshold": 5,
                        "brute_force_window_seconds": 300,
                        "multi_user_threshold": 3,
                        "multi_user_window_seconds": 600,
                        "success_after_failure_threshold": 3,
                        "success_after_failure_window_seconds": 300,
                        "sudo_failure_threshold": 3,
                        "sudo_failure_window_seconds": 300,
                    },
                }
            ),
            encoding="utf-8",
        )

        # 1. Analyze
        res_analyze = self._run_cli(
            "--config",
            str(cfg_path),
            "analyze",
            "--file",
            str(SAMPLE_LOG),
            "--year",
            "2026",
            "--json",
        )
        self.assertEqual(res_analyze.returncode, 0, msg=res_analyze.stderr)
        analyze_data = json.loads(res_analyze.stdout)
        self.assertEqual(analyze_data["new_events_stored"], 25)
        self.assertEqual(analyze_data["new_alerts_stored"], 5)

        # 2. Query events filtered by IP
        res_events = self._run_cli(
            "--config",
            str(cfg_path),
            "events",
            "--ip",
            "203.0.113.50",
            "--json",
        )
        self.assertEqual(res_events.returncode, 0, msg=res_events.stderr)
        self.assertEqual(len(json.loads(res_events.stdout)), 9)

        # 3. Query critical alerts with evidence
        res_alerts = self._run_cli(
            "--config",
            str(cfg_path),
            "alerts",
            "--severity",
            "critical",
            "--show-evidence",
        )
        self.assertEqual(res_alerts.returncode, 0, msg=res_alerts.stderr)
        self.assertIn("SSH_SUCCESS_AFTER_FAILURES", res_alerts.stdout)
        self.assertIn("Evidence:", res_alerts.stdout)

        # 4. Fetch aggregated stats
        res_stats = self._run_cli("--config", str(cfg_path), "stats", "--json")
        self.assertEqual(res_stats.returncode, 0, msg=res_stats.stderr)
        stats_data = json.loads(res_stats.stdout)
        self.assertEqual(stats_data["total_events"], 25)
        self.assertEqual(stats_data["total_alerts"], 5)

        # 5. Export JSON and terminal reports to disk
        json_out = self.base_path / "out_report.json"
        txt_out = self.base_path / "out_report.txt"
        res_rep_json = self._run_cli(
            "--config",
            str(cfg_path),
            "report",
            "--format",
            "json",
            "--output",
            str(json_out),
        )
        res_rep_txt = self._run_cli(
            "--config",
            str(cfg_path),
            "report",
            "--format",
            "terminal",
            "--output",
            str(txt_out),
        )
        self.assertEqual(res_rep_json.returncode, 0, msg=res_rep_json.stderr)
        self.assertEqual(res_rep_txt.returncode, 0, msg=res_rep_txt.stderr)
        self.assertEqual(
            json.loads(json_out.read_text(encoding="utf-8"))["summary"]["total_alerts"],
            5,
        )
        self.assertIn("ACTION REQUIRED", txt_out.read_text(encoding="utf-8"))

    def test_rolling_log_posture_transitions_from_clear_to_action_required(
        self,
    ) -> None:
        """Verify benign scan starts CLEAR, then appended attack triggers ACTION REQUIRED."""
        rolling_log = self.base_path / "rolling.log"
        initial = BENIGN_LOG.read_text(encoding="utf-8")
        if not initial.endswith("\n"):
            initial += "\n"
        rolling_log.write_text(initial, encoding="utf-8")

        # Scan 1: Benign activity only -> 0 alerts, CLEAR
        r1 = self._run_cli(
            "analyze",
            "--file",
            str(rolling_log),
            "--db",
            str(self.db_path),
            "--year",
            "2026",
            "--json",
        )
        self.assertEqual(r1.returncode, 0, msg=r1.stderr)
        d1 = json.loads(r1.stdout)
        self.assertEqual(d1["new_events_stored"], 19)
        self.assertEqual(d1["new_alerts_stored"], 0)

        rep1 = self._run_cli("report", "--db", str(self.db_path))
        self.assertIn("Status:       CLEAR", rep1.stdout)

        # Append a simulated root credential compromise sequence
        with open(rolling_log, mode="a", encoding="utf-8") as handle:
            handle.write(
                "2026-11-18T15:00:01+05:30 prod-app-01 sshd[30001]: "
                "Failed password for root from 203.0.113.200 port 49001 ssh2\n"
            )
            handle.write(
                "2026-11-18T15:00:03+05:30 prod-app-01 sshd[30002]: "
                "Failed password for root from 203.0.113.200 port 49002 ssh2\n"
            )
            handle.write(
                "2026-11-18T15:00:05+05:30 prod-app-01 sshd[30003]: "
                "Failed password for root from 203.0.113.200 port 49003 ssh2\n"
            )
            handle.write(
                "2026-11-18T15:00:09+05:30 prod-app-01 sshd[30004]: "
                "Accepted password for root from 203.0.113.200 port 49004 ssh2\n"
            )

        # Scan 2: 19 duplicates skipped, 4 new events stored, 1 critical alert generated
        r2 = self._run_cli(
            "analyze",
            "--file",
            str(rolling_log),
            "--db",
            str(self.db_path),
            "--year",
            "2026",
            "--json",
        )
        self.assertEqual(r2.returncode, 0, msg=r2.stderr)
        d2 = json.loads(r2.stdout)
        self.assertEqual(d2["duplicate_events_skipped"], 19)
        self.assertEqual(d2["new_events_stored"], 4)
        self.assertEqual(d2["new_alerts_stored"], 1)

        rep2 = self._run_cli("report", "--db", str(self.db_path))
        self.assertIn("Status:       ACTION REQUIRED", rep2.stdout)

class TestAdversarialAndMalformedInputs(unittest.TestCase):
    """Verify resilience against empty files, binary garbage, long lines, and SQLi."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "resilience.db"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(RUN_SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_empty_log_file_completes_cleanly(self) -> None:
        """Verify an empty 0-byte log file exits 0 with zero events and alerts."""
        empty_log = self.base_path / "empty.log"
        empty_log.write_text("", encoding="utf-8")

        res = self._run_cli(
            "analyze", "--file", str(empty_log), "--db", str(self.db_path), "--json"
        )
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["total_lines"], 0)
        self.assertEqual(data["valid_events"], 0)
        self.assertEqual(data["alerts_detected"], 0)

    def test_binary_garbage_and_oversized_lines_do_not_crash_analyzer(self) -> None:
        """Verify invalid UTF-8 bytes, null bytes, and 20k-char lines are handled safely."""
        hostile_log = self.base_path / "hostile.log"
        long_garbage = ("A" * 20000).encode("ascii")
        hostile_log.write_bytes(
            b"\xff\xfe\x00\x01NOT_A_VALID_SYSLOG_LINE\n"
            + long_garbage
            + b"\n"
            + b"2026-11-18T08:00:00+05:30 host sshd[1]: Failed password for root from 999.999.999.999 port 22 ssh2\n"
        )

        res = self._run_cli(
            "analyze", "--file", str(hostile_log), "--db", str(self.db_path), "--json"
        )
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["total_lines"], 3)
        self.assertEqual(data["valid_events"], 0)
        self.assertEqual(data["malformed_lines"], 3)

    def test_sql_injection_payload_in_username_is_stored_safely_as_literal_text(
        self,
    ) -> None:
        """Verify parameterized SQLite queries neutralize SQL injection in usernames."""
        sqli_log = self.base_path / "sqli.log"
        payload_user = "';DROP_TABLE_auth_events;--"
        sqli_log.write_text(
            f"2026-11-18T08:00:01+05:30 host sshd[500]: "
            f"Failed password for invalid user {payload_user} from 203.0.113.55 port 40001 ssh2\n",
            encoding="utf-8",
        )

        res_analyze = self._run_cli(
            "analyze", "--file", str(sqli_log), "--db", str(self.db_path), "--json"
        )
        self.assertEqual(res_analyze.returncode, 0, msg=res_analyze.stderr)
        self.assertEqual(json.loads(res_analyze.stdout)["new_events_stored"], 1)

        res_events = self._run_cli(
            "events", "--db", str(self.db_path), "--user", payload_user, "--json"
        )
        self.assertEqual(res_events.returncode, 0, msg=res_events.stderr)
        rows = json.loads(res_events.stdout)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], payload_user)


if __name__ == "__main__":
    unittest.main()