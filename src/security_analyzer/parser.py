import re
from typing import Any, Dict, Optional


# Matches either:
# 1. ISO-8601 / RFC 3339: 2026-11-18T08:00:01.100000+05:30 or 2026-11-18T08:00:01Z
# 2. BSD Syslog / RFC 3164: Nov 18 08:04:00 or Nov  5 08:04:00
SYSLOG_HEADER_RE = re.compile(
    r"^(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
    r"|"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r")\s+"
    r"(?P<hostname>[\w.\-]+)\s+"
    r"(?P<service>[\w.\-/]+?)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)


def parse_syslog_header(
    raw_line: str,
    line_number: int = 1,
) -> Optional[Dict[str, Any]]:
    """Extract the syslog envelope fields from a raw log line.

    Returns a dictionary with keys:
        line_number, timestamp_raw, hostname, service, pid, message, raw_line
    or None if the line does not match a valid syslog header.
    """
    if not raw_line or not raw_line.strip():
        return None

    cleaned = raw_line.strip("\r\n")
    match = SYSLOG_HEADER_RE.match(cleaned)
    if match is None:
        return None

    pid_str = match.group("pid")
    return {
        "line_number": line_number,
        "timestamp_raw": match.group("timestamp"),
        "hostname": match.group("hostname"),
        "service": match.group("service"),
        "pid": int(pid_str) if pid_str is not None else None,
        "message": match.group("message"),
        "raw_line": cleaned,
    }