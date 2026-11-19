from pathlib import Path
import unittest

from security_analyzer.detector import (
    detect_failed_ssh_logins,
    detect_invalid_user_events,
    detect_multi_username_probes,
    detect_repeated_ssh_failures,
    detect_repeated_sudo_failures,
    detect_success_after_failures,
    detect_successful_ssh_logins,
    detect_sudo_events,
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


class TestRepeatedSshFailuresDetection(unittest.TestCase):
    """Verify Checkpoint 3.4: sliding-window repeated SSH failure detection."""

    @classmethod
    def setUpClass(cls) -> None:
        """Parse sample_logs/auth_sample.log once for read-only detector tests."""
        cls.sample_result = parse_log_file(SAMPLE_LOG, reference_year=2026)

    def test_detect_repeated_ssh_failures_at_default_threshold(self) -> None:
        """Verify both brute-force IPs are flagged when min_failures=5."""
        findings = detect_repeated_ssh_failures(
            self.sample_result.events,
            min_failures=5,
            window_seconds=300,
        )
        by_ip = {item["source_ip"]: item for item in findings}
        self.assertEqual(set(by_ip.keys()), {"203.0.113.50", "198.51.100.77"})
        self.assertEqual(by_ip["203.0.113.50"]["failure_count"], 6)
        self.assertEqual(by_ip["198.51.100.77"]["failure_count"], 5)

    def test_detect_repeated_ssh_failures_more_than_five(self) -> None:
        """Verify min_failures=6 ('more than five') flags only 203.0.113.50."""
        findings = detect_repeated_ssh_failures(
            self.sample_result.events,
            min_failures=6,
            window_seconds=300,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source_ip"], "203.0.113.50")
        self.assertEqual(findings[0]["failure_count"], 6)
        self.assertEqual(len(findings[0]["evidence_events"]), 6)

    def test_repeated_failures_outside_time_window_are_not_flagged(self) -> None:
        """Verify slow failures spread across hours do not trigger a burst alert."""
        lines = [
            f"2026-11-18T0{hour}:00:00+05:30 host sshd[{hour}]: "
            f"Failed password for root from 192.0.2.88 port 4100{hour} ssh2"
            for hour in range(1, 7)
        ]
        events = [
            ev
            for idx, line in enumerate(lines, start=1)
            if (ev := parse_log_line(line, line_number=idx)) is not None
        ]
        findings = detect_repeated_ssh_failures(
            events,
            min_failures=5,
            window_seconds=300,
        )
        self.assertEqual(findings, [])


class TestSuccessAfterFailuresDetection(unittest.TestCase):
    """Verify Checkpoint 3.5: successful login after repeated failures detection."""

    @classmethod
    def setUpClass(cls) -> None:
        """Parse sample_logs/auth_sample.log once for read-only detector tests."""
        cls.sample_result = parse_log_file(SAMPLE_LOG, reference_year=2026)

    def test_detect_success_after_failures_on_sample_log(self) -> None:
        """Verify 198.51.100.77 (deploy) is flagged after 5 failures + 1 success."""
        findings = detect_success_after_failures(
            self.sample_result.events,
            min_failures=3,
            window_seconds=300,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["source_ip"], "198.51.100.77")
        self.assertEqual(finding["username"], "deploy")
        self.assertEqual(finding["auth_method"], "password")
        self.assertEqual(finding["preceding_failure_count"], 5)
        self.assertEqual(len(finding["evidence_events"]), 6)
        self.assertEqual(
            finding["evidence_events"][-1].event_type,
            "ssh_successful_login",
        )

    def test_failures_occurring_after_success_do_not_trigger(self) -> None:
        """Verify failures logged AFTER a successful login are not counted."""
        lines = [
            "2026-11-18T08:00:00+05:30 host sshd[1]: Accepted publickey for ops from 192.0.2.50 port 50001 ssh2",
            "2026-11-18T08:00:10+05:30 host sshd[2]: Failed password for ops from 192.0.2.50 port 50002 ssh2",
            "2026-11-18T08:00:20+05:30 host sshd[3]: Failed password for ops from 192.0.2.50 port 50003 ssh2",
            "2026-11-18T08:00:30+05:30 host sshd[4]: Failed password for ops from 192.0.2.50 port 50004 ssh2",
        ]
        events = [
            ev
            for idx, line in enumerate(lines, start=1)
            if (ev := parse_log_line(line, line_number=idx)) is not None
        ]
        findings = detect_success_after_failures(
            events,
            min_failures=3,
            window_seconds=300,
        )
        self.assertEqual(findings, [])

    def test_old_failures_outside_window_do_not_trigger(self) -> None:
        """Verify failures older than window_seconds before success do not trigger."""
        lines = [
            "2026-11-18T08:00:00+05:30 host sshd[1]: Failed password for ops from 192.0.2.51 port 50001 ssh2",
            "2026-11-18T08:00:05+05:30 host sshd[2]: Failed password for ops from 192.0.2.51 port 50002 ssh2",
            "2026-11-18T08:00:10+05:30 host sshd[3]: Failed password for ops from 192.0.2.51 port 50003 ssh2",
            "2026-11-18T09:00:00+05:30 host sshd[4]: Accepted password for ops from 192.0.2.51 port 50004 ssh2",
        ]
        events = [
            ev
            for idx, line in enumerate(lines, start=1)
            if (ev := parse_log_line(line, line_number=idx)) is not None
        ]
        findings = detect_success_after_failures(
            events,
            min_failures=3,
            window_seconds=300,
        )
        self.assertEqual(findings, [])


class TestSudoDetection(unittest.TestCase):
    """Verify Checkpoint 3.6: sudo command and repeated sudo failure detection."""

    @classmethod
    def setUpClass(cls) -> None:
        """Parse sample_logs/auth_sample.log once for read-only detector tests."""
        cls.sample_result = parse_log_file(SAMPLE_LOG, reference_year=2026)

    def test_detect_sudo_events_from_sample_log(self) -> None:
        """Verify 1 sudo command and 4 sudo auth failure records are detected."""
        sudo_events = detect_sudo_events(self.sample_result.events)
        self.assertEqual(len(sudo_events), 5)
        commands = [ev for ev in sudo_events if ev.event_type == "sudo_command"]
        failures = [
            ev for ev in sudo_events if ev.event_type == "sudo_auth_failure"
        ]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].username, "developer")
        self.assertEqual(commands[0].command, "/usr/bin/systemctl status nginx")
        self.assertEqual(len(failures), 4)

    def test_detect_repeated_sudo_failures_identifies_intern(self) -> None:
        """Verify user intern is flagged with attempted command /usr/sbin/visudo."""
        findings = detect_repeated_sudo_failures(
            self.sample_result.events,
            min_failures=3,
            window_seconds=300,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["username"], "intern")
        self.assertEqual(finding["failure_count"], 4)
        self.assertEqual(finding["target_users"], ["root"])
        self.assertEqual(finding["attempted_commands"], ["/usr/sbin/visudo"])

    def test_sudo_failures_outside_window_do_not_trigger(self) -> None:
        """Verify sudo failures spaced beyond window_seconds do not trigger."""
        lines = [
            "2026-11-18T08:00:00+05:30 host sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob",
            "2026-11-18T08:20:00+05:30 host sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob",
            "2026-11-18T08:40:00+05:30 host sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob",
        ]
        events = [
            ev
            for idx, line in enumerate(lines, start=1)
            if (ev := parse_log_line(line, line_number=idx)) is not None
        ]
        findings = detect_repeated_sudo_failures(
            events,
            min_failures=3,
            window_seconds=300,
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()