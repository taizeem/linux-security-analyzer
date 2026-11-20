import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SETUP_SCRIPT = PROJECT_ROOT / "scripts" / "setup.sh"


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


if __name__ == "__main__":
    unittest.main()