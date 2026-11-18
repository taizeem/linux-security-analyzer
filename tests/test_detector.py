from pathlib import Path
import unittest

from security_analyzer.detector import (
    detect_failed_ssh_logins,
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


if __name__ == "__main__":
    unittest.main()