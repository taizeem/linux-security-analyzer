import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from security_analyzer import __app_name__, __version__


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUN_SCRIPT = PROJECT_ROOT / "scripts" / "run.sh"


class TestBashLauncher(unittest.TestCase):
    """Verify scripts/run.sh permissions, environment setup, and CLI forwarding."""

    def test_run_script_exists_and_is_executable(self) -> None:
        """Verify scripts/run.sh exists and has the executable permission bit set."""
        self.assertTrue(RUN_SCRIPT.is_file(), f"Missing script: {RUN_SCRIPT}")
        self.assertTrue(
            os.access(RUN_SCRIPT, os.X_OK),
            f"Script is not executable: {RUN_SCRIPT}",
        )

    def test_launcher_version_flag(self) -> None:
        """Verify --version prints the package name and version and exits with 0."""
        result = subprocess.run(
            [str(RUN_SCRIPT), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn(f"{__app_name__} {__version__}", result.stdout.strip())

    def test_launcher_help_flag(self) -> None:
        """Verify --help outputs usage information and exits with 0."""
        result = subprocess.run(
            [str(RUN_SCRIPT), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("usage:", result.stdout.lower())
        self.assertIn("--version", result.stdout)

    def test_launcher_works_from_outside_project_directory(self) -> None:
        """Verify scripts/run.sh resolves paths when run from an external directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = subprocess.run(
                [str(RUN_SCRIPT), "--version"],
                cwd=tmp_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn(__version__, result.stdout)

    def test_launcher_rejects_unknown_arguments(self) -> None:
        """Verify invalid CLI flags return a non-zero exit code and write to stderr."""
        result = subprocess.run(
            [str(RUN_SCRIPT), "--invalid-nonexistent-flag"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()