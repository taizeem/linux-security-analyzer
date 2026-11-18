from datetime import datetime
import ipaddress
import re
from typing import Any, Dict, Optional


# Stage 1: Syslog envelope regex (ISO-8601 or BSD RFC 3164)
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

# Stage 2: Service message payload regexes
SSH_FAILED_RE = re.compile(
    r"^Failed\s+(?P<auth_method>\S+)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?"
    r"(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

SSH_ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<auth_method>\S+)\s+for\s+"
    r"(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

SSH_INVALID_USER_RE = re.compile(
    r"^Invalid user\s+(?P<username>\S+)\s+from\s+(?P<ip>\S+)"
    r"(?:\s+port\s+(?P<port>\d+))?"
)

SUDO_COMMAND_RE = re.compile(
    r"^(?P<username>[\w.\-]+)\s*:\s*"
    r"(?:(?P<attempts>\d+)\s+incorrect password attempts\s*;\s*)?"
    r"TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>[^;]+?)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)

SUDO_PAM_AUTH_FAIL_RE = re.compile(
    r"^pam_unix\(sudo:auth\):\s+authentication failure;.*?"
    r"\buser=(?P<username>\S+)"
)

PAM_SESSION_RE = re.compile(
    r"^pam_unix\((?P<pam_service>[^:]+):session\):\s+"
    r"session\s+(?P<state>opened|closed)\s+for\s+user\s+"
    r"(?P<target_user>[\w.\-]+)(?:\(uid=\d+\))?"
    r"(?:\s+by\s+(?P<username>[\w.\-]*)(?:\(uid=\d+\))?)?"
)


def parse_syslog_header(
    raw_line: str,
    line_number: int = 1,
) -> Optional[Dict[str, Any]]:
    """Extract the syslog envelope fields from a raw log line."""
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


def normalize_timestamp(
    timestamp_raw: str,
    reference_year: Optional[int] = None,
) -> Optional[str]:
    """Normalize an ISO-8601 or BSD syslog timestamp into ISO-8601 format."""
    if not timestamp_raw:
        return None

    raw = timestamp_raw.strip()

    # Case 1: ISO-8601 timestamp (e.g. 2026-11-18T08:00:01.100000+05:30 or ...Z)
    if raw[:4].isdigit() and "T" in raw:
        iso_candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            dt = datetime.fromisoformat(iso_candidate)
            return dt.isoformat()
        except ValueError:
            return None

    # Case 2: BSD syslog timestamp (e.g. "Nov 18 08:04:00" or "Nov  5 03:12:09")
    year = reference_year if reference_year is not None else datetime.now().year
    normalized_spaces = " ".join(raw.split())
    try:
        dt = datetime.strptime(f"{year} {normalized_spaces}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return None


def validate_ip_address(ip_candidate: Optional[str]) -> Optional[str]:
    """Validate and canonicalize an IPv4 or IPv6 address string."""
    if not ip_candidate:
        return None
    try:
        return str(ipaddress.ip_address(ip_candidate.strip()))
    except ValueError:
        return None


def extract_auth_fields(service: str, message: str) -> Dict[str, Any]:
    """Extract authentication event type, username, IP, and metadata from message."""
    fields: Dict[str, Any] = {
        "event_type": "other",
        "username": None,
        "source_ip": None,
        "port": None,
        "auth_method": None,
        "target_user": None,
        "command": None,
        "is_invalid_user": False,
    }

    # 1. SSH Failed Login
    match = SSH_FAILED_RE.match(message)
    if match:
        ip_addr = validate_ip_address(match.group("ip"))
        if ip_addr is None:
            fields["event_type"] = "malformed"
            return fields
        fields.update(
            {
                "event_type": "ssh_failed_login",
                "username": match.group("username"),
                "source_ip": ip_addr,
                "port": int(match.group("port")),
                "auth_method": match.group("auth_method"),
                "is_invalid_user": match.group("invalid") is not None,
            }
        )
        return fields

    # 2. SSH Successful Login
    match = SSH_ACCEPTED_RE.match(message)
    if match:
        ip_addr = validate_ip_address(match.group("ip"))
        if ip_addr is None:
            fields["event_type"] = "malformed"
            return fields
        fields.update(
            {
                "event_type": "ssh_successful_login",
                "username": match.group("username"),
                "source_ip": ip_addr,
                "port": int(match.group("port")),
                "auth_method": match.group("auth_method"),
            }
        )
        return fields

    # 3. SSH Invalid User probe
    match = SSH_INVALID_USER_RE.match(message)
    if match:
        ip_addr = validate_ip_address(match.group("ip"))
        if ip_addr is None:
            fields["event_type"] = "malformed"
            return fields
        port_str = match.group("port")
        fields.update(
            {
                "event_type": "ssh_invalid_user",
                "username": match.group("username"),
                "source_ip": ip_addr,
                "port": int(port_str) if port_str else None,
                "is_invalid_user": True,
            }
        )
        return fields

    # 4. Sudo PAM authentication failure
    match = SUDO_PAM_AUTH_FAIL_RE.match(message)
    if match:
        fields.update(
            {
                "event_type": "sudo_auth_failure",
                "username": match.group("username"),
                "target_user": "root",
            }
        )
        return fields

    # 5. Sudo command execution or repeated incorrect password summary
    if service == "sudo":
        match = SUDO_COMMAND_RE.match(message)
        if match:
            attempts = match.group("attempts")
            fields.update(
                {
                    "event_type": (
                        "sudo_auth_failure" if attempts else "sudo_command"
                    ),
                    "username": match.group("username"),
                    "target_user": match.group("target_user"),
                    "command": match.group("command").strip(),
                }
            )
            return fields

    # 6. PAM session opened/closed
    match = PAM_SESSION_RE.match(message)
    if match:
        state = match.group("state")
        actor = match.group("username") or match.group("target_user")
        fields.update(
            {
                "event_type": f"session_{state}",
                "username": actor,
                "target_user": match.group("target_user"),
            }
        )
        return fields

    return fields