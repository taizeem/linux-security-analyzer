"""Accuracy and false-positive tests for DetectionEngine (Checkpoint 4.5)."""

from pathlib import Path
import unittest

from security_analyzer.detector import DetectionEngine
from security_analyzer.models import Severity
from security_analyzer.parser import parse_log_file, parse_log_line


PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENIGN_LOG = PROJECT_ROOT / "sample_logs" / "benign_activity.log"


class TestDetectionAccuracyAndFalsePositives(unittest.TestCase):
    """Verify false-positive resistance and high-severity escalation accuracy."""

    def test_benign_activity_produces_zero_false_positives(self) -> None:
        """Verify normal logins, 2-typo logins, and slow/distributed failures emit 0 alerts."""
        parsed = parse_log_file(BENIGN_LOG, reference_year=2026)
        self.assertEqual(parsed.malformed_lines, 0)
        self.assertEqual(parsed.valid_events, 19)

        engine = DetectionEngine()
        alerts = engine.evaluate(parsed.events)
        self.assertEqual(
            alerts,
            [],
            msg=f"Expected 0 false positives on benign log, got: {alerts}",
        )

    def test_high_volume_brute_force_escalates_to_high_severity(self) -> None:
        """Verify 12 rapid SSH failures from one IP escalate from medium to high."""
        lines = [
            f"2026-11-18T08:00:{sec:02d}+05:30 host sshd[{sec}]: "
            f"Failed password for root from 203.0.113.77 port {41000 + sec} ssh2"
            for sec in range(1, 13)
        ]
        events = [
            ev
            for idx, line in enumerate(lines, start=1)
            if (ev := parse_log_line(line, line_number=idx)) is not None
        ]

        alerts = DetectionEngine().evaluate(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "SSH_REPEATED_FAILURES")
        self.assertEqual(alerts[0].severity, Severity.HIGH.value)
        self.assertEqual(alerts[0].event_count, 12)

    def test_root_login_after_three_failures_escalates_to_critical(self) -> None:
        """Verify root login after 3 failures is always critical regardless of auth method."""
        lines = [
            "2026-11-18T08:10:01+05:30 host sshd[1]: Failed password for root from 198.51.100.88 port 50001 ssh2",
            "2026-11-18T08:10:05+05:30 host sshd[2]: Failed password for root from 198.51.100.88 port 50002 ssh2",
            "2026-11-18T08:10:09+05:30 host sshd[3]: Failed password for root from 198.51.100.88 port 50003 ssh2",
            "2026-11-18T08:10:15+05:30 host sshd[4]: Accepted publickey for root from 198.51.100.88 port 50004 ssh2",
        ]
        events = [
            ev
            for idx, line in enumerate(lines, start=1)
            if (ev := parse_log_line(line, line_number=idx)) is not None
        ]

        alerts = DetectionEngine().evaluate(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "SSH_SUCCESS_AFTER_FAILURES")
        self.assertEqual(alerts[0].severity, Severity.CRITICAL.value)
        self.assertEqual(alerts[0].username, "root")

    def test_ipv6_brute_force_detected_identically_to_ipv4(self) -> None:
        """Verify IPv6 addresses trigger SSH_REPEATED_FAILURES cleanly."""
        lines = [
            f"2026-11-18T08:20:0{sec}+05:30 host sshd[{sec}]: "
            f"Failed password for admin from 2001:db8:abcd::1 port {42000 + sec} ssh2"
            for sec in range(1, 7)
        ]
        events = [
            ev
            for idx, line in enumerate(lines, start=1)
            if (ev := parse_log_line(line, line_number=idx)) is not None
        ]

        alerts = DetectionEngine().evaluate(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "2001:db8:abcd::1")
        self.assertEqual(alerts[0].rule_id, "SSH_REPEATED_FAILURES")
        self.assertEqual(alerts[0].event_count, 6)


if __name__ == "__main__":
    unittest.main()