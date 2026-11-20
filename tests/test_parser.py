import unittest

from security_analyzer.parser import (
    extract_auth_fields,
    normalize_timestamp,
    parse_log_entry,
    parse_syslog_header,
    sanitize_log_line,
    validate_ip_address,
    validate_port,
)


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


class TestFieldExtraction(unittest.TestCase):
    """Verify Stage 2 extraction of timestamps, usernames, and IPv4/IPv6 addresses."""

    def test_normalize_iso8601_and_bsd_timestamps(self) -> None:
        """Verify both ISO-8601 and BSD timestamps normalize to ISO format."""
        iso = normalize_timestamp("2026-11-18T08:00:01.100000+05:30")
        bsd = normalize_timestamp("Nov  5 03:12:09", reference_year=2026)

        self.assertEqual(iso, "2026-11-18T08:00:01.100000+05:30")
        self.assertEqual(bsd, "2026-11-05T03:12:09")
        self.assertIsNone(normalize_timestamp("2026-02-30T08:00:00+00:00"))

    def test_validate_ipv4_and_ipv6_addresses(self) -> None:
        """Verify valid IPv4/IPv6 addresses pass and invalid octets return None."""
        self.assertEqual(validate_ip_address("203.0.113.50"), "203.0.113.50")
        self.assertEqual(
            validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "2001:db8:85a3::8a2e:370:7334",
        )
        self.assertIsNone(validate_ip_address("999.999.999.999"))
        self.assertIsNone(validate_ip_address("not-an-ip"))

    def test_extract_ssh_failed_valid_and_invalid_user(self) -> None:
        """Verify username, IPv4, port, and invalid_user flag on SSH failures."""
        valid_user_msg = "Failed password for root from 203.0.113.50 port 41004 ssh2"
        invalid_user_msg = (
            "Failed password for invalid user admin from 203.0.113.50 port 41001 ssh2"
        )

        f1 = extract_auth_fields("sshd", valid_user_msg)
        self.assertEqual(f1["event_type"], "ssh_failed_login")
        self.assertEqual(f1["username"], "root")
        self.assertEqual(f1["source_ip"], "203.0.113.50")
        self.assertEqual(f1["port"], 41004)
        self.assertFalse(f1["is_invalid_user"])

        f2 = extract_auth_fields("sshd", invalid_user_msg)
        self.assertEqual(f2["event_type"], "ssh_failed_login")
        self.assertEqual(f2["username"], "admin")
        self.assertEqual(f2["source_ip"], "203.0.113.50")
        self.assertTrue(f2["is_invalid_user"])

    def test_extract_ssh_accepted_ipv6_login(self) -> None:
        """Verify IPv6 address and publickey auth method extraction on SSH login."""
        msg = (
            "Accepted publickey for ipv6admin from "
            "2001:db8:85a3::8a2e:370:7334 port 55100 ssh2"
        )
        fields = extract_auth_fields("sshd", msg)
        self.assertEqual(fields["event_type"], "ssh_successful_login")
        self.assertEqual(fields["username"], "ipv6admin")
        self.assertEqual(fields["source_ip"], "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(fields["port"], 55100)
        self.assertEqual(fields["auth_method"], "publickey")

    def test_extract_sudo_command_and_failure_fields(self) -> None:
        """Verify sudo command execution and PAM failure field extraction."""
        cmd_msg = (
            "developer : TTY=pts/0 ; PWD=/home/developer ; USER=root ; "
            "COMMAND=/usr/bin/systemctl status nginx"
        )
        fail_msg = (
            "pam_unix(sudo:auth): authentication failure; logname=intern "
            "uid=1002 euid=0 tty=/dev/pts/2 ruser=intern rhost=  user=intern"
        )

        f_cmd = extract_auth_fields("sudo", cmd_msg)
        self.assertEqual(f_cmd["event_type"], "sudo_command")
        self.assertEqual(f_cmd["username"], "developer")
        self.assertEqual(f_cmd["target_user"], "root")
        self.assertEqual(f_cmd["command"], "/usr/bin/systemctl status nginx")

        f_fail = extract_auth_fields("sudo", fail_msg)
        self.assertEqual(f_fail["event_type"], "sudo_auth_failure")
        self.assertEqual(f_fail["username"], "intern")


class TestMalformedLogHandling(unittest.TestCase):
    """Verify defensive handling of corrupted, injected, or invalid log lines."""

    def test_sanitize_log_line_strips_null_bytes_and_escape_codes(self) -> None:
        """Verify null bytes and terminal escape sequences are stripped safely."""
        dirty = "2026-11-18T08:00:01Z host sshd[1]: Invalid user \x00bad\x1b[31muser\r\n"
        cleaned = sanitize_log_line(dirty)
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertTrue(cleaned.endswith("[31muser"))

    def test_validate_port_bounds(self) -> None:
        """Verify TCP/UDP port numbers must be within 1..65535."""
        self.assertEqual(validate_port("22"), 22)
        self.assertEqual(validate_port("65535"), 65535)
        self.assertIsNone(validate_port("0"))
        self.assertIsNone(validate_port("65536"))
        self.assertIsNone(validate_port("abc"))

    def test_parse_log_entry_rejects_invalid_ip_and_port_with_warning(self) -> None:
        """Verify invalid IP or port returns None and logs a warning."""
        bad_ip_line = (
            "2026-11-18T08:01:02+05:30 bastion-01 sshd[10201]: "
            "Failed password for root from 999.999.999.999 port 22 ssh2"
        )
        bad_port_line = (
            "2026-11-18T08:01:02+05:30 bastion-01 sshd[10201]: "
            "Failed password for root from 203.0.113.50 port 99999 ssh2"
        )
        bad_date_line = (
            "2026-02-30T08:01:02+05:30 bastion-01 sshd[10201]: "
            "Failed password for root from 203.0.113.50 port 22 ssh2"
        )

        with self.assertLogs("security_analyzer.parser", level="WARNING") as cm:
            self.assertIsNone(parse_log_entry(bad_ip_line, line_number=10))
            self.assertIsNone(parse_log_entry(bad_port_line, line_number=11))
            self.assertIsNone(parse_log_entry(bad_date_line, line_number=12))

        self.assertEqual(len(cm.output), 3)
        self.assertIn("line 10", cm.output[0])
        self.assertIn("line 11", cm.output[1])
        self.assertIn("line 12", cm.output[2])

class TestParserEdgeCases(unittest.TestCase):
    """Verify QA edge cases: missing usernames, IPv6 forms, leap years, and auth methods."""

    def test_ssh_disconnect_without_username_parses_as_other(self) -> None:
        """Verify valid syslog lines without a username parse cleanly with username=None."""
        line = (
            "2026-11-18T08:05:12+05:30 bastion-01 sshd[12345]: "
            "Received disconnect from 192.0.2.10 port 51234:11: disconnected by user"
        )
        entry = parse_log_entry(line, line_number=50)
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["event_type"], "other")
        self.assertIsNone(entry["username"])

    def test_keyboard_interactive_ssh_login_extraction(self) -> None:
        """Verify keyboard-interactive/pam SSH authentication method is extracted."""
        line = (
            "2026-11-18T08:06:00Z bastion-01 sshd[12346]: "
            "Accepted keyboard-interactive/pam for ops from 2001:DB8::1 port 44321 ssh2"
        )
        entry = parse_log_entry(line, line_number=51)
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["event_type"], "ssh_successful_login")
        self.assertEqual(entry["auth_method"], "keyboard-interactive/pam")
        self.assertEqual(entry["username"], "ops")
        # Uppercase IPv6 is canonicalized to lowercase RFC 5952 form
        self.assertEqual(entry["source_ip"], "2001:db8::1")

    def test_leap_year_and_utc_z_timestamp_validation(self) -> None:
        """Verify leap-day 2024-02-29Z is accepted and non-leap 2026-02-29Z is rejected."""
        self.assertEqual(
            normalize_timestamp("2024-02-29T23:59:59Z"),
            "2024-02-29T23:59:59+00:00",
        )
        self.assertIsNone(normalize_timestamp("2026-02-29T23:59:59Z"))

    def test_invalid_ipv6_rejected_and_truncated_sudo_handled(self) -> None:
        """Verify malformed IPv6 returns None and truncated sudo lines do not crash."""
        self.assertIsNone(validate_ip_address("2001:db8:::1"))
        self.assertEqual(validate_ip_address("::1"), "::1")

        truncated_sudo = (
            "2026-11-18T08:07:00+05:30 host sudo: "
            "bob : TTY=pts/0 ; PWD=/home/bob"
        )
        entry = parse_log_entry(truncated_sudo, line_number=52)
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["event_type"], "other")


if __name__ == "__main__":
    unittest.main()