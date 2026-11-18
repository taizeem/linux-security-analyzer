from dataclasses import FrozenInstanceError
from pathlib import Path
import unittest

from security_analyzer.models import AuthEvent, compute_event_hash
from security_analyzer.parser import parse_log_file, parse_log_line


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"


class TestEventModels(unittest.TestCase):
    """Verify structured event models, immutability, hashing, and file parsing."""

    def test_auth_event_is_immutable(self) -> None:
        """Verify modifying a frozen AuthEvent attribute raises FrozenInstanceError."""
        line = (
            "2026-11-18T08:00:01.100000+05:30 bastion-01 sshd[10101]: "
            "Accepted publickey for developer from 192.0.2.10 port 50112 ssh2"
        )
        event = parse_log_line(line, line_number=1)
        self.assertIsNotNone(event)
        assert event is not None

        with self.assertRaises(FrozenInstanceError):
            event.username = "tampered"  # type: ignore[misc]

    def test_event_hash_is_deterministic_and_ignores_line_number(self) -> None:
        """Verify identical events at different line numbers produce the same hash."""
        line = (
            "2026-11-18T08:01:15.700000+05:30 bastion-01 sshd[10204]: "
            "Failed password for root from 203.0.113.50 port 41004 ssh2"
        )
        event_a = parse_log_line(line, line_number=11)
        event_b = parse_log_line(line, line_number=99)

        self.assertIsNotNone(event_a)
        self.assertIsNotNone(event_b)
        assert event_a is not None and event_b is not None
        self.assertEqual(event_a.event_hash, event_b.event_hash)
        self.assertEqual(len(event_a.event_hash), 64)
        self.assertEqual(
            event_a.event_hash,
            compute_event_hash(
                event_a.timestamp,
                event_a.hostname,
                event_a.service,
                event_a.pid,
                event_a.message,
            ),
        )

    def test_auth_event_epoch_seconds_and_to_dict(self) -> None:
        """Verify epoch_seconds calculation and dictionary serialization."""
        line = (
            "2026-11-18T08:00:01.100000+05:30 bastion-01 sshd[10101]: "
            "Accepted publickey for developer from 192.0.2.10 port 50112 ssh2"
        )
        event = parse_log_line(line, line_number=1)
        assert event is not None

        self.assertIsInstance(event.epoch_seconds, float)
        self.assertGreater(event.epoch_seconds, 0.0)

        serialized = event.to_dict()
        self.assertEqual(serialized["username"], "developer")
        self.assertEqual(serialized["source_ip"], "192.0.2.10")
        self.assertEqual(serialized["event_hash"], event.event_hash)

    def test_parse_log_file_on_sample_dataset(self) -> None:
        """Verify end-to-end parsing of sample_logs/auth_sample.log."""
        with self.assertLogs("security_analyzer.parser", level="WARNING"):
            result = parse_log_file(SAMPLE_LOG, reference_year=2026)

        self.assertEqual(result.total_lines, 26)
        self.assertEqual(result.valid_events, 25)
        self.assertEqual(result.malformed_lines, 1)
        self.assertEqual(len(result.events), 25)
        self.assertIsInstance(result.events[0], AuthEvent)


if __name__ == "__main__":
    unittest.main()