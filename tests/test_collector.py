import os
from pathlib import Path
import tempfile
import unittest

from security_analyzer.collector import read_log_lines, validate_log_file


class TestLogCollector(unittest.TestCase):
    """Test filesystem validation and line streaming in collector.py."""

    def setUp(self) -> None:
        """Create an isolated temporary directory for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        """Restore permissions if needed and clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_read_valid_log_lines_and_skip_blank_lines(self) -> None:
        """Verify non-empty lines are yielded with exact 1-based line numbers."""
        log_file = self.base_path / "auth.log"
        log_file.write_text(
            "2026-11-18T07:42:32+05:30 host sshd[100]: Accepted publickey for taizeem\n"
            "\n"
            "   \n"
            "2026-11-18T07:43:00+05:30 host sudo: session opened for user root\n",
            encoding="utf-8",
        )

        entries = list(read_log_lines(log_file))
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0][0], 1)
        self.assertIn("Accepted publickey", entries[0][1])
        self.assertEqual(entries[1][0], 4)
        self.assertIn("session opened", entries[1][1])

    def test_read_empty_log_file_returns_empty_iterator(self) -> None:
        """Verify an empty file yields zero entries without error."""
        log_file = self.base_path / "empty.log"
        log_file.write_text("", encoding="utf-8")

        entries = list(read_log_lines(log_file))
        self.assertEqual(entries, [])

    def test_missing_file_raises_file_not_found_error(self) -> None:
        """Verify missing log path raises FileNotFoundError."""
        missing_path = self.base_path / "nonexistent.log"
        with self.assertRaises(FileNotFoundError):
            validate_log_file(missing_path)

    def test_directory_path_raises_is_a_directory_error(self) -> None:
        """Verify passing a directory instead of a file raises IsADirectoryError."""
        with self.assertRaises(IsADirectoryError):
            validate_log_file(self.base_path)

    @unittest.skipIf(os.geteuid() == 0, "Root bypasses 0000 file permission checks")
    def test_unreadable_file_raises_permission_error(self) -> None:
        """Verify an unreadable file (mode 0000) raises PermissionError."""
        locked_file = self.base_path / "locked.log"
        locked_file.write_text("secret log line\n", encoding="utf-8")
        locked_file.chmod(0o000)
        try:
            with self.assertRaises(PermissionError):
                list(read_log_lines(locked_file))
        finally:
            locked_file.chmod(0o600)

    def test_malformed_utf8_bytes_are_replaced_safely(self) -> None:
        """Verify invalid UTF-8 byte sequences do not crash the log collector."""
        binary_log = self.base_path / "corrupted.log"
        binary_log.write_bytes(
            b"2026-11-18T07:45:00+05:30 host sshd[200]: Invalid user \xff\xfe from 192.0.2.10\n"
        )

        entries = list(read_log_lines(binary_log))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], 1)
        self.assertIn("Invalid user", entries[0][1])


if __name__ == "__main__":
    unittest.main()