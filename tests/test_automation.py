import json
import os
import fcntl
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SETUP_SCRIPT = PROJECT_ROOT / "scripts" / "setup.sh"
SCHEDULED_SCAN_SCRIPT = PROJECT_ROOT / "scripts" / "scheduled_scan.sh"
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"


class TestSetupScript(unittest.TestCase):
    """Verify scripts/setup.sh syntax, permissions, and idempotent initialization."""

    def test_setup_script_exists_is_executable_and_valid_bash(self) -> None:
        """Verify scripts/setup.sh is executable and passes bash -n syntax check."""
        self.assertTrue(SETUP_SCRIPT.is_file())
        self.assertTrue(os.access(SETUP_SCRIPT, os.X_OK))

        syntax = subprocess.run(
            ["bash", "-n", str(SETUP_SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, msg=syntax.stderr)

    def test_setup_script_is_idempotent_and_preserves_existing_config(self) -> None:
        """Verify setup.sh initializes config/DB on run 1 and preserves config on run 2."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            cfg_path = tmp_path / "custom_config.json"
            db_path = tmp_path / "custom_security.db"

            env = os.environ.copy()
            env["LSA_CONFIG_PATH"] = str(cfg_path)
            env["LSA_DB_PATH"] = str(db_path)

            run_1 = subprocess.run(
                [str(SETUP_SCRIPT)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(run_1.returncode, 0, msg=run_1.stderr)
            self.assertTrue(cfg_path.is_file())
            self.assertTrue(db_path.is_file())
            self.assertIn("Created configuration file", run_1.stdout)

            # Modify config.json slightly and re-run setup.sh to ensure preservation
            original_text = cfg_path.read_text(encoding="utf-8")
            updated_text = original_text.replace('"brute_force_threshold": 5', '"brute_force_threshold": 9')
            cfg_path.write_text(updated_text, encoding="utf-8")

            run_2 = subprocess.run(
                [str(SETUP_SCRIPT)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(run_2.returncode, 0, msg=run_2.stderr)
            self.assertIn("already exists (preserved)", run_2.stdout)
            self.assertIn('"brute_force_threshold": 9', cfg_path.read_text(encoding="utf-8"))

class TestScheduledScanScript(unittest.TestCase):
    """Verify scripts/scheduled_scan.sh syntax, permissions, and automated scan run."""

    def test_scheduled_scan_script_is_executable_and_valid_bash(self) -> None:
        """Verify scripts/scheduled_scan.sh is executable and passes bash -n."""
        self.assertTrue(SCHEDULED_SCAN_SCRIPT.is_file())
        self.assertTrue(os.access(SCHEDULED_SCAN_SCRIPT, os.X_OK))

        syntax = subprocess.run(
            ["bash", "-n", str(SCHEDULED_SCAN_SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, msg=syntax.stderr)

    def test_scheduled_scan_runs_end_to_end_and_writes_reports(self) -> None:
        """Verify scheduled_scan.sh ingests sample log and writes JSON + TXT reports."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = tmp_path / "cron_test.db"
            report_dir = tmp_path / "reports"
            run_log = tmp_path / "scheduled_scan.log"

            env = os.environ.copy()
            env["LSA_LOG_FILE"] = str(SAMPLE_LOG)
            env["LSA_DB_PATH"] = str(db_path)
            env["LSA_REPORT_DIR"] = str(report_dir)
            env["LSA_RUN_LOG"] = str(run_log)

            result = subprocess.run(
                [str(SCHEDULED_SCAN_SCRIPT)],
                cwd="/tmp",
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(db_path.is_file())
            self.assertTrue(run_log.is_file())

            json_reports = list(report_dir.glob("security_report_*.json"))
            txt_reports = list(report_dir.glob("security_report_*.txt"))
            self.assertEqual(len(json_reports), 1)
            self.assertEqual(len(txt_reports), 1)

            payload = json.loads(json_reports[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["total_events"], 25)
            self.assertEqual(payload["summary"]["total_alerts"], 5)
            self.assertIn("ACTION REQUIRED", txt_reports[0].read_text(encoding="utf-8"))
    def test_scheduled_scan_returns_exit_10_on_missing_log_file(self) -> None:
        """Verify missing log file exits with code 10 and logs ERROR without writing reports."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            report_dir = tmp_path / "reports"
            run_log = tmp_path / "scheduled_scan.log"

            env = os.environ.copy()
            env["LSA_LOG_FILE"] = str(tmp_path / "missing_auth.log")
            env["LSA_DB_PATH"] = str(tmp_path / "test.db")
            env["LSA_REPORT_DIR"] = str(report_dir)
            env["LSA_RUN_LOG"] = str(run_log)

            result = subprocess.run(
                [str(SCHEDULED_SCAN_SCRIPT)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 10)
            self.assertIn("cannot read log file", result.stderr.lower())
            self.assertIn("ERROR", run_log.read_text(encoding="utf-8"))
            self.assertEqual(list(report_dir.glob("*")), [])

    def test_scheduled_scan_returns_exit_11_on_invalid_config(self) -> None:
        """Verify analyze failure (broken config JSON) exits with code 11."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            bad_cfg = tmp_path / "broken.json"
            bad_cfg.write_text("{ bad json", encoding="utf-8")
            run_log = tmp_path / "scheduled_scan.log"

            env = os.environ.copy()
            env["LSA_LOG_FILE"] = str(SAMPLE_LOG)
            env["LSA_DB_PATH"] = str(tmp_path / "test.db")
            env["LSA_REPORT_DIR"] = str(tmp_path / "reports")
            env["LSA_RUN_LOG"] = str(run_log)
            env["LSA_CONFIG_PATH"] = str(bad_cfg)

            result = subprocess.run(
                [str(SCHEDULED_SCAN_SCRIPT)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 11)
            self.assertIn("analyze stage failed", result.stderr.lower())

    def test_scheduled_scan_skips_with_exit_20_when_lock_is_held(self) -> None:
        """Verify flock prevents overlapping scans and exits with code 20."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            lock_path = tmp_path / "scan.lock"
            run_log = tmp_path / "scheduled_scan.log"
            report_dir = tmp_path / "reports"

            env = os.environ.copy()
            env["LSA_LOG_FILE"] = str(SAMPLE_LOG)
            env["LSA_DB_PATH"] = str(tmp_path / "locked.db")
            env["LSA_REPORT_DIR"] = str(report_dir)
            env["LSA_RUN_LOG"] = str(run_log)
            env["LSA_LOCK_FILE"] = str(lock_path)

            with open(lock_path, mode="w", encoding="utf-8") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    result = subprocess.run(
                        [str(SCHEDULED_SCAN_SCRIPT)],
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                finally:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

            self.assertEqual(result.returncode, 20)
            self.assertIn("already running", result.stderr.lower())
            self.assertIn("WARNING", run_log.read_text(encoding="utf-8"))
            self.assertEqual(list(report_dir.glob("*")), [])

if __name__ == "__main__":
    unittest.main()