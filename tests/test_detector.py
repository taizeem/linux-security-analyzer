from pathlib import Path
import unittest

from security_analyzer.detector import (
    detect_failed_ssh_logins,
    detect_invalid_user_events,
    detect_multi_username_probes,
    detect_successful_ssh_logins,
    group_failed_ssh_by_ip,
    group_successful_ssh_by_user,
)
from security_analyzer.parser import parse_log_file, parse_log_line


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"


class TestFailedSshDetection(unittest.TestCase):
    """Verify Checkpoint 3.1: failed SSH login detection and IP grouping."""

    @classmethod
    def setUpClass(cls) -> None:
        """Parse sample_logs/auth_sample.log once for read-only detector tests."""
        cls.sample_result = parse_log_file(SAMPLE_LOG, reference_year=2026)

    def test_detect_failed_ssh_logins_from_sample_log(self) -> None:
        """Verify all 11 failed SSH password attempts are detected in order."""
        failed_events = detect_failed_ssh_logins(self.sample_result.events)
        self.assertEqual(len(failed_events), 11)
        self.assertTrue(
            all(ev.event_type == "ssh_failed_login" for ev in failed_events)
        )
        epochs = [ev.epoch_seconds for ev in failed_events]
        self.assertEqual(epochs, sorted(epochs))

    def test_group_failed_ssh_by_ip(self) -> None:
        """Verify failed SSH logins are accurately grouped by source IP."""
        grouped = group_failed_ssh_by_ip(self.sample_result.events)
        self.assertEqual(set(grouped.keys()), {"203.0.113.50", "198.51.100.77"})
        self.assertEqual(len(grouped["203.0.113.50"]), 6)
        self.assertEqual(len(grouped["198.51.100.77"]), 5)

    def test_detect_failed_ssh_sorts_out_of_order_events(self) -> None:
        """Verify out-of-order input events are returned in chronological order."""
        later = parse_log_line(
            "2026-11-18T08:05:00+05:30 host sshd[2]: "
            "Failed password for root from 192.0.2.5 port 40002 ssh2",
            line_number=2,
        )
        earlier = parse_log_line(
            "2026-11-18T08:01:00+05:30 host sshd[1]: "
            "Failed password for root from 192.0.2.5 port 40001 ssh2",
            line_number=1,
        )
        assert later is not None and earlier is not None

        detected = detect_failed_ssh_logins([later, earlier])
        self.assertEqual([ev.port for ev in detected], [40001, 40002])


class TestSuccessfulSshDetection(unittest.TestCase):
    """Verify Checkpoint 3.2: successful SSH login detection and user grouping."""

    @classmethod
    def setUpClass(cls) -> None:
        """Parse sample_logs/auth_sample.log once for read-only detector tests."""
        cls.sample_result = parse_log_file(SAMPLE_LOG, reference_year=2026)

    def test_detect_successful_ssh_logins_from_sample_log(self) -> None:
        """Verify all 3 successful SSH logins (IPv4 and IPv6) are detected."""
        accepted = detect_successful_ssh_logins(self.sample_result.events)
        self.assertEqual(len(accepted), 3)

        usernames = [ev.username for ev in accepted]
        methods = [ev.auth_method for ev in accepted]
        ips = [ev.source_ip for ev in accepted]

        self.assertEqual(usernames, ["developer", "deploy", "ipv6admin"])
        self.assertEqual(methods, ["publickey", "password", "publickey"])
        self.assertEqual(
            ips,
            [
                "192.0.2.10",
                "198.51.100.77",
                "2001:db8:85a3::8a2e:370:7334",
            ],
        )

    def test_group_successful_ssh_by_user(self) -> None:
        """Verify successful SSH logins are accurately grouped by username."""
        grouped = group_successful_ssh_by_user(self.sample_result.events)
        self.assertEqual(
            set(grouped.keys()),
            {"developer", "deploy", "ipv6admin"},
        )
        self.assertEqual(grouped["deploy"][0].auth_method, "password")
        self.assertEqual(grouped["deploy"][0].source_ip, "198.51.100.77")


class TestInvalidUserDetection(unittest.TestCase):
    """Verify Checkpoint 3.3: invalid username and multi-user enumeration detection."""

    @classmethod
    def setUpClass(cls) -> None:
        """Parse sample_logs/auth_sample.log once for read-only detector tests."""
        cls.sample_result = parse_log_file(SAMPLE_LOG, reference_year=2026)

    def test_detect_invalid_user_events_from_sample_log(self) -> None:
        """Verify all 6 invalid-user SSH events are detected from sample log."""
        invalid_events = detect_invalid_user_events(self.sample_result.events)
        self.assertEqual(len(invalid_events), 6)
        self.assertTrue(all(ev.is_invalid_user for ev in invalid_events))
        targeted_invalid = {ev.username for ev in invalid_events}
        self.assertEqual(targeted_invalid, {"admin", "test", "oracle"})

    def test_detect_multi_username_probes_identifies_scanner_ip(self) -> None:
        """Verify IP 203.0.113.50 is flagged for targeting 4 distinct usernames."""
        findings = detect_multi_username_probes(
            self.sample_result.events,
            min_usernames=3,
            window_seconds=600,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["source_ip"], "203.0.113.50")
        self.assertEqual(
            finding["usernames"],
            ["admin", "oracle", "root", "test"],
        )
        self.assertEqual(
            finding["invalid_usernames"],
            ["admin", "oracle", "test"],
        )
        self.assertEqual(finding["unique_username_count"], 4)

    def test_multi_username_probes_respects_time_window(self) -> None:
        """Verify attempts spaced further apart than window_seconds do not trigger."""
        lines = [
            "2026-11-18T08:00:00+05:30 host sshd[1]: Invalid user u1 from 192.0.2.99 port 40001",
            "2026-11-18T08:15:00+05:30 host sshd[2]: Invalid user u2 from 192.0.2.99 port 40002",
            "2026-11-18T08:30:00+05:30 host sshd[3]: Invalid user u3 from 192.0.2.99 port 40003",
        ]
        events = [
            ev
            for idx, line in enumerate(lines, start=1)
            if (ev := parse_log_line(line, line_number=idx)) is not None
        ]
        findings = detect_multi_username_probes(
            events,
            min_usernames=3,
            window_seconds=300,
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()