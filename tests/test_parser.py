import unittest

from security_analyzer.parser import parse_syslog_header


class TestSyslogHeaderParser(unittest.TestCase):
    """Verify Stage 1 syslog envelope parsing across timestamp and daemon formats."""

    def test_parse_iso8601_sshd_header_with_pid(self) -> None:
        """Verify ISO-8601 timestamp and sshd[PID] header extraction."""
        line = (
            "2026-11-18T08:00:01.100000+05:30 bastion-01 sshd[10101]: "
            "Accepted publickey for developer from 192.0.2.10 port 50112 ssh2"
        )
        parsed = parse_syslog_header(line, line_number=1)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["line_number"], 1)
        self.assertEqual(parsed["timestamp_raw"], "2026-11-18T08:00:01.100000+05:30")
        self.assertEqual(parsed["hostname"], "bastion-01")
        self.assertEqual(parsed["service"], "sshd")
        self.assertEqual(parsed["pid"], 10101)
        self.assertEqual(
            parsed["message"],
            "Accepted publickey for developer from 192.0.2.10 port 50112 ssh2",
        )

    def test_parse_iso8601_sudo_header_without_pid(self) -> None:
        """Verify sudo log lines without [PID] set pid to None."""
        line = (
            "2026-11-18T08:00:15.210000+05:30 taizeem-ThinkPad-T490s sudo: "
            "taizeem : TTY=pts/0 ; PWD=/home/taizeem ; USER=root ; COMMAND=/usr/bin/id"
        )
        parsed = parse_syslog_header(line, line_number=2)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["hostname"], "taizeem-ThinkPad-T490s")
        self.assertEqual(parsed["service"], "sudo")
        self.assertIsNone(parsed["pid"])
        self.assertIn("COMMAND=/usr/bin/id", parsed["message"])

    def test_parse_bsd_syslog_header_double_and_single_digit_day(self) -> None:
        """Verify BSD syslog timestamps work for both double- and single-digit days."""
        line_double = (
            "Nov 18 08:04:00 bastion-01 sshd[10401]: "
            "Accepted publickey for ipv6admin from 2001:db8::1 port 55100 ssh2"
        )
        line_single = (
            "Nov  5 03:12:09 bastion-01 sshd[999]: "
            "Invalid user guest from 192.0.2.99 port 40000"
        )

        parsed_double = parse_syslog_header(line_double, line_number=24)
        parsed_single = parse_syslog_header(line_single, line_number=25)

        self.assertIsNotNone(parsed_double)
        self.assertIsNotNone(parsed_single)
        assert parsed_double is not None and parsed_single is not None
        self.assertEqual(parsed_double["timestamp_raw"], "Nov 18 08:04:00")
        self.assertEqual(parsed_single["timestamp_raw"], "Nov  5 03:12:09")
        self.assertEqual(parsed_single["pid"], 999)

    def test_malformed_line_returns_none(self) -> None:
        """Verify lines without a valid syslog header return None."""
        self.assertIsNone(parse_syslog_header(""))
        self.assertIsNone(parse_syslog_header("   "))
        self.assertIsNone(
            parse_syslog_header("CORRUPTED_LINE_WITHOUT_SYSLOG_HEADER_OR_TIMESTAMP")
        )


if __name__ == "__main__":
    unittest.main()