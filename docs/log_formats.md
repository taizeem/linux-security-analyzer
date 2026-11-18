# Supported Linux Authentication Log Formats

## 1. Syslog Header Formats

The parser supports both standard syslog timestamp formats found across Ubuntu, Debian, and RHEL-family distributions:

1. **ISO-8601 / RFC 3339 (`RSYSLOG_FileFormat`)**:
   ```text
   2026-11-18T08:00:01.100000+05:30 bastion-01 sshd[10101]: <message>